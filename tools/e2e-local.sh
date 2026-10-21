#!/usr/bin/env bash
# Run the registry lifecycle test against a local sequencer at the pinned LEZ
# tag: boot `dev.sh` with a payer funded at genesis, run
# `lez-rln/tests/local_sequencer.rs`, shut the sequencer down.
#
#   bash tools/e2e-local.sh [-- <extra cargo test args>]
#
# Everything throwaway lives under dev/e2e/ (wallet, sequencer log). The guest
# `.bin` must already be built and staged in
# lez-rln/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/.
#
# The membership tree is not on chain: the test rebuilds it from the
# registration program's events, which only the LEZ indexer serves
# (`getEvents`; the sequencer RPC has none). At v0.3.1 the indexer follows
# blocks through a Bedrock channel, and the standalone sequencer `dev.sh`
# boots publishes to none, so set LEZ_RLN_INDEXER_URL to an indexer that
# follows THIS sequencer (LEZ's lez/configs/docker-all-in-one stack, with
# `"event_filter": "archival"`). Without it the script refuses to start.
set -euo pipefail

if [ -z "${LEZ_RLN_INDEXER_URL:-}" ]; then
  cat >&2 <<'MSG'
error: LEZ_RLN_INDEXER_URL is not set.
The lifecycle test reads the membership tree from the program's events, which
only a LEZ indexer serves, and the v0.3.1 indexer follows blocks through a
Bedrock channel that dev.sh's standalone sequencer does not publish to. Point
LEZ_RLN_INDEXER_URL at an indexer following this sequencer (e.g. LEZ's
docker-all-in-one stack, event_filter "archival").
MSG
  exit 2
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
E2E="$REPO/dev/e2e"
SEQ_LOG="$E2E/sequencer.log"
PORT=3040

# Seconds, so `extend` becomes legal after one CLOCK_50 tick and `erase` after
# two or three. The guest refuses a zero active duration.
export LEZ_RLN_ACTIVE_DURATION_SECS="${LEZ_RLN_ACTIVE_DURATION_SECS:-1}"
export LEZ_RLN_GRACE_PERIOD_DURATION_SECS="${LEZ_RLN_GRACE_PERIOD_DURATION_SECS:-60}"
export LEZ_RLN_LOCAL_SEQUENCER=1
export LEE_WALLET_HOME_DIR="$E2E/wallet"
export RUST_LOG="${RUST_LOG:-warn}"

if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
  echo "error: port $PORT is already in use; stop that sequencer first" >&2
  exit 1
fi

rm -rf "$E2E"
mkdir -p "$LEE_WALLET_HOME_DIR"
cat > "$LEE_WALLET_HOME_DIR/wallet_config.json" <<JSON
{
  "sequencer": { "sequencer_addr": "http://127.0.0.1:$PORT/" },
  "seq_poll_timeout": "30s",
  "seq_tx_poll_max_blocks": 15,
  "seq_poll_max_retries": 10,
  "seq_block_poll_max_amount": 100
}
JSON

echo "Building host binaries and the lifecycle test..."
cargo build --manifest-path "$REPO/lez-rln/Cargo.toml" --bin mint_payer
cargo test --manifest-path "$REPO/lez-rln/Cargo.toml" --test local_sequencer --no-run

PAYER="$("$REPO/lez-rln/target/debug/mint_payer" | tail -1)"
export LEZ_RLN_PAYER="$PAYER"
echo "Payer: $PAYER"

echo "Starting the sequencer (log: $SEQ_LOG)..."
LEZ_RLN_GENESIS_FUND="$PAYER" "$REPO/dev.sh" > "$SEQ_LOG" 2>&1 &
SEQ_PID=$!
cleanup() {
  # dev.sh execs cargo run, which spawns the sequencer binary; kill by port.
  kill "$(lsof -ti tcp:$PORT 2>/dev/null)" "$SEQ_PID" 2>/dev/null || true
}
trap cleanup EXIT

python3 - "$PORT" <<'PY'
import json, sys, time, urllib.request
port = sys.argv[1]
deadline = time.time() + 600
while time.time() < deadline:
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/",
            data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getLastBlockId", "params": []}).encode(),
            headers={"content-type": "application/json"},
        )
        print("sequencer up at block", json.load(urllib.request.urlopen(req, timeout=3))["result"])
        sys.exit(0)
    except Exception:
        time.sleep(3)
print("sequencer never came up; see the log", file=sys.stderr)
sys.exit(1)
PY

echo "Running the lifecycle test..."
DYLD_FRAMEWORK_PATH="${DYLD_FRAMEWORK_PATH:-/Library/Developer/CommandLineTools/Library/Frameworks}" \
  cargo test --manifest-path "$REPO/lez-rln/Cargo.toml" --test local_sequencer -- --nocapture "$@"
