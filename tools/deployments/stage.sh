#!/usr/bin/env bash
# Stage a deployment descriptor into a flat fixture dir the daemons/binaries consume.
# FEATURE: deployment-profile tooling — one descriptor+wallet is the source of truth.
#
#   bash stage.sh <deployment_dir> <out_dir>
#
# A deployment is captured by tree_id + the two program ids + wallet
# (storage.json). The program ids (registration_program_id, merkle_program_id)
# are the header accounts run_setup deployed — recorded state, not derivable
# from the guest binaries. config is a derived cache of (registration program
# id, tree_id); payer_account is a pointer into the wallet — the account that
# signs a registration, pays its price in native, and pays its fee.
# Emits storage.json.seed, wallet_config.json, {config,payer}_account.txt,
# treasury_account.txt, env.sh (tree id, payer and both program ids), enforcing
# the wallet<->deployment binding so a mismatched wallet fails here, not at
# runtime. Bash+jq (no Python) so every sim + the image build share it.
# The consistency check (re-deriving config from the ids) is verify.sh.
set -euo pipefail

case "${1:-}" in -h|--help) echo "usage: stage.sh <deployment_dir> <out_dir>" >&2; exit 0;; esac
DEP_DIR="${1:?usage: stage.sh <deployment_dir> <out_dir>}"
OUT="${2:?usage: stage.sh <deployment_dir> <out_dir>}"
DESC="$DEP_DIR/deployment.json"
WALLET="$DEP_DIR/storage.json"
command -v jq >/dev/null || { echo "stage: FAIL: jq not found (apt install jq)" >&2; exit 1; }
[ -f "$DESC" ]   || { echo "stage: FAIL: missing $DESC" >&2; exit 1; }
[ -f "$WALLET" ] || { echo "stage: FAIL: missing $WALLET" >&2; exit 1; }

fail(){ echo "stage: FAIL: $1" >&2; exit 1; }
field(){ jq -re ".$1 // empty" "$DESC" 2>/dev/null || fail "descriptor missing required field '$1'"; }

NAME=$(field name); TREE=$(field tree_id); SEQ=$(field sequencer)
CFG=$(field config_account); PAY=$(field payer_account); TREASURY=$(field treasury_account)
REG=$(field registration_program_id); MRK=$(field merkle_program_id)
# A pre-native descriptor names payment_account/supply_holding/funding and no
# payer_account, so `field payer_account` above already failed it — which is
# what we want: its config account belongs to a program that no longer exists,
# and every offset in it decodes to something plausible and wrong.
[[ "$TREE" =~ ^[0-9a-f]{64}$ ]] || fail "tree_id must be 64 lowercase hex chars, got '$TREE'"
[[ "$REG" =~ ^[0-9a-f]{64}$ ]] || fail "registration_program_id must be 64 lowercase hex chars, got '$REG'"
[[ "$MRK" =~ ^[0-9a-f]{64}$ ]] || fail "merkle_program_id must be 64 lowercase hex chars, got '$MRK'"

# Wallet schema — refuse a storage.json without the top-level 'key_chain.accounts'.
jq -e '.key_chain.accounts' "$WALLET" >/dev/null 2>&1 \
  || fail "wallet schema unrecognised (expected top-level 'key_chain.accounts')"
# wallet<->deployment binding: the wallet must actually hold the payer, since
# nothing else can sign a registration against this deployment. The treasury is
# only ever credited, so no wallet need hold it.
holds(){ jq -e --arg a "$1" 'any(.key_chain.accounts[]; .Public.account_id == $a)' "$WALLET" >/dev/null 2>&1; }
holds "$PAY" || fail "wallet does not contain payer_account=$PAY — descriptor and storage.json are mismatched (wrong wallet)"

mkdir -p "$OUT"
printf '%s' "$CFG" > "$OUT/config_account.txt"
printf '%s' "$PAY" > "$OUT/payer_account.txt"
printf '%s' "$TREASURY" > "$OUT/treasury_account.txt"
jq '.last_synced_block = 0' "$WALLET" > "$OUT/storage.json.seed"
# Triple-shape sequencer field: the v0.3.1 wallet reads `sequencer`, the
# v0.3.0 wallet `sequencers` (multi-client), the module's wallet flat
# `sequencer_addr`. No struct denies unknown fields, so one file serves all.
# multi_sequencer_client_config is read by the v0.3.0 wallet only: its open
# calibrates each sequencer with calibration_limit sequential getLastBlockId
# probes (default 100) when no statistics file exists — minutes against a slow
# chain. One sequencer needs no leader election; 3 probes suffice.
# gas_limit: the wallet's own default is 2,000,000, and a registration costs
# about 9.1M — an on-chain merkle insert is one Poseidon compression, roughly
# 902,000 cycles, per level of tree depth, and gas is cycles. A wallet that
# declares too little has its transaction refused for running out of gas, with
# nothing in the reply naming the limit it hit. MAX_GAS_EXEC (10M) is the
# ceiling the protocol enforces; declaring more is refused outright.
jq -n --arg s "$SEQ" '{sequencer_addr:$s, sequencer:{sequencer_addr:$s}, sequencers:[{sequencer_addr:$s}], seq_poll_timeout:"30s", seq_tx_poll_max_blocks:15, seq_poll_max_retries:10, seq_block_poll_max_amount:100, gas_limit:10000000, multi_sequencer_client_config:{distribution_limit:1, calibration_limit:3}}' > "$OUT/wallet_config.json"
cat > "$OUT/env.sh" <<EOF
#!/usr/bin/env bash
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
export LEE_WALLET_HOME_DIR="\$SCRIPT_DIR"
export LEZ_RLN_TREE_ID_HEX=$TREE
export LEZ_RLN_PAYER=$PAY
export LEZ_RLN_REGISTRATION_PROGRAM_ID=$REG
export LEZ_RLN_MERKLE_PROGRAM_ID=$MRK
EOF

echo "stage: OK  $NAME  tree=${TREE:0:8}…  reg=${REG:0:8}…  merkle=${MRK:0:8}…  config=$CFG  payer=$PAY  treasury=$TREASURY  -> $OUT"
