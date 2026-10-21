#!/usr/bin/env bash
# Source this in your terminal before running RLN binaries against the local dev sequencer.
# Usage: source dev/env.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LEE_WALLET_HOME_DIR="$SCRIPT_DIR"
# The membership tree is rebuilt from the program's events, which only a LEZ
# indexer serves. Set LEZ_RLN_INDEXER_URL to one following your sequencer for
# get_roots / run_rln_proof (the standalone dev.sh sequencer has none).
