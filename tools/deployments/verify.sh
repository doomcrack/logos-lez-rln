#!/usr/bin/env bash
# Verify a deployment descriptor is self-consistent and matches recorded program ids.
# FEATURE: deployment-profile tooling — the descriptor consistency guard.
#
#   bash verify.sh <deployment_dir>
#
# Program ids are deployment state (the header accounts run_setup deployed), so
# they cannot be re-derived from the guest binaries. This script:
#   1. re-derives config_account from the descriptor's registration_program_id
#      and tree_id via derive_accounts (the real PDA math) and asserts it equals
#      the descriptor's cache;
#   2. when the tree's record (~/.logos-lez-rln/programs_<tree>.json) exists,
#      asserts it names the descriptor's program ids, so a descriptor and the
#      ids every tool reads back cannot silently diverge;
#   3. runs stage.sh's wallet binding.
# The image ids the program headers carry are checked by run_setup at deploy
# time, not here.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"                    # logos-lez-rln root
case "${1:-}" in -h|--help) echo "usage: verify.sh <deployment_dir>" >&2; exit 0;; esac
DEP_DIR="${1:?usage: verify.sh <deployment_dir>}"
DERIVE="${DERIVE_BIN:-$REPO/lez-rln/target/release/derive_accounts}"
export DYLD_FRAMEWORK_PATH="${DYLD_FRAMEWORK_PATH:-/Library/Developer/CommandLineTools/Library/Frameworks}"

[ -x "$DERIVE" ] || { echo "verify: FAIL: derive_accounts not built at $DERIVE
  build: (cd $REPO/lez-rln && PYO3_PYTHON=\$(command -v python3) cargo build --release --bin derive_accounts)" >&2; exit 1; }

f(){ jq -re ".$1" "$DEP_DIR/deployment.json"; }
TREE=$(f tree_id); WANT_REG=$(f registration_program_id); WANT_CFG=$(f config_account)

fail(){ echo "verify: FAIL: $1" >&2; exit 1; }

# The descriptor's ids go in through the env overrides, so derive_accounts
# reads them instead of whatever record the running HOME holds.
DERIVED=$(cd "$REPO/lez-rln" && LEZ_RLN_TREE_ID_HEX="$TREE" \
  LEZ_RLN_REGISTRATION_PROGRAM_ID="$WANT_REG" "$DERIVE")
GOT_CFG=$(echo "$DERIVED" | jq -r .config_account)
[ "$GOT_CFG" = "$WANT_CFG" ] || fail "config account mismatch (tree_id/program_id inconsistent)
  descriptor: $WANT_CFG
  re-derived: $GOT_CFG"

RECORD="${HOME:-.}/.logos-lez-rln/programs_${TREE}.json"
if [ -f "$RECORD" ]; then
  REC_REG=$(jq -re .registration_program_id "$RECORD")
  [ "$REC_REG" = "$WANT_REG" ] || fail "registration program id differs from the record $RECORD
  descriptor: $WANT_REG
  record:     $REC_REG"
  RECORD_NOTE="program id matches $RECORD"
else
  RECORD_NOTE="no record at $RECORD (program id not cross-checked)"
fi

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
bash "$HERE/stage.sh" "$DEP_DIR" "$tmp" >/dev/null

echo "verify: OK  $(f name)  config re-derives from the descriptor's ids; $RECORD_NOTE; wallet binding holds."
