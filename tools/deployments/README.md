# Deployment profiles (shared tooling)

Canonical home for the RLN deployment layer. Every sim that vendors `logos-lez-rln`
(mix_lez_chat, mixnet-logos-core, the dst-libp2p Docker pipeline, …) calls these
scripts instead of re-implementing staging.

A **deployment** = one on-chain RLN instance, fully captured by two files:

```
deployments/<name>/
  deployment.json   # tree_id + sequencer + program id + derived config + payer/treasury
  storage.json      # the wallet (holds the payer's keypair)
```

`deployment.json`:

```json
{
  "name": "<name>",
  "tree_id": "<64 hex>",
  "sequencer": "<url>",
  "registration_program_id": "<64 hex>",
  "config_account": "<base58>",
  "payer_account": "<base58>",
  "treasury_account": "<base58>"
}
```

**The program id is recorded, not derived.** A program's account id is the header account its
deployer created and signed in `run_setup`; it is not a function of the guest `.bin`.
`run_setup` writes it to `~/.logos-lez-rln/programs_<tree_hex>.json`, `provision.sh` copies it
into `registration_program_id`, and `stage.sh`'s `env.sh` exports it as
`LEZ_RLN_REGISTRATION_PROGRAM_ID`, which every tool reads in preference to the record.

There is no merkle program and no tree account: the registration program emits one event per
successful action, and readers rebuild the membership tree from them (`lez-rln/src/zone`). A
descriptor that still names a `merkle_program_id` is an on-chain-tree deployment whose
144-byte config this program cannot read, and `stage.sh` refuses it.

`tree_id` and the registration program id together determine `config`, a **derived** PDA of
`(registration_program_id, tree_id)`; `payer_account` is a **pointer
into the wallet**. `treasury_account` is neither — it is a plain account created at
provisioning time, so the descriptor is the only record of where a registry's revenue
accrues. A stale `config` can't silently disagree with the ids (`verify.sh`). All scripts are
bash+jq (no Python) so they run in-sim and in image builds.

## Paying for a membership

There is one asset and one way to pay. A membership costs
`rate_limit x price_per_unit` of **native** balance, debited from the account that
signs the `Register` transaction — which is also that transaction's fee payer.
One account, one balance, no holding to derive and nothing to claim first.

That account is `payer_account`, and it must already hold native balance:
**no program can mint native**, so it arrives at genesis (`mint_payer` prints an
id, `dev.sh`'s `LEZ_RLN_GENESIS_FUND` funds it), over the L1 bridge, or by a
transfer from something already funded. Budget roughly
`rate_limit x price_per_unit + 6.5e8` per registration — the fee reserve dwarfs
the price, so an account sized only for the price cannot transact at all.

There is no funding policy to choose any more, and no free-registration quota:
the RLNTOK payment token, the RLNREC credit token, the faucet and `RegisterFree`
were all removed together. A descriptor carrying `funding`, `supply_holding` or
`payment_account` predates that change and is not merely stale — its config
account belongs to a program that no longer exists, and every offset in it
decodes to something plausible and wrong. `stage.sh` refuses it.

## Consumer contract

```bash
bash tools/deployments/stage.sh <deployment_dir> <out_dir>
```

Emits the flat files `run_setup`/`register_member`/node daemons already expect
(`storage.json.seed`, `wallet_config.json`, `config_account.txt`,
`payer_account.txt`, `treasury_account.txt`, `env.sh`). `env.sh` exports
`LEE_WALLET_HOME_DIR`, `LEZ_RLN_TREE_ID_HEX`, `LEZ_RLN_PAYER` and the program id.
Requires the program id as a 64-hex field, asserts the wallet has
`key_chain.accounts`, and that it actually contains the descriptor's payer account —
a mismatched wallet fails at stage time, not at runtime. The treasury is only ever
credited, so no wallet need hold it.

## Workflows

**Run against an existing deployment** — drop a `deployments/<name>/` in and `stage.sh` it.

**Redeploy fresh** (needs `run_setup` + `derive_accounts` built):
```bash
(cd lez-rln && PYO3_PYTHON=$(command -v python3) cargo build --release --bin run_setup --bin derive_accounts)

# fresh tree + fresh wallet. --payer is required: it pays the deploy fees and
# becomes the deployment's payer_account. Deploy and init transactions declare
# the wallet's gas_limit (10,000,000 in the generated wallet_config.json), so the
# payer's balance must cover gas_limit x base fee per transaction.
bash tools/deployments/provision.sh --name my-run --payer <account-id>

# reuse a program already on the chain: export its header id first.
LEZ_RLN_REGISTRATION_PROGRAM_ID=<64hex> \
  bash tools/deployments/provision.sh --name my-run --payer <account-id>

# reuse another sim's wallet (shared accounts), specific tree, write into a consumer repo:
bash tools/deployments/provision.sh --name shared --payer <account-id> --tree <64hex> \
     --adopt-wallet /path/to/other/storage.json --outdir /path/to/consumer/deployments
```

## verify.sh — descriptor consistency guard

```bash
bash tools/deployments/verify.sh deployments/<name>
```

Re-derives `config_account` from the descriptor's `registration_program_id` and `tree_id`
(via `derive_accounts`, reusing the real PDA math) and diffs the descriptor's cache. If
`~/.logos-lez-rln/programs_<tree_hex>.json` exists it must name the descriptor's two
program ids; otherwise that cross-check is skipped and says so. Then it runs `stage.sh`'s
wallet binding. Program ids cannot be re-derived from the guest binaries, so this does not
detect a rebuilt guest: `run_setup` checks that each program header carries the local
binary's image id when it deploys or reuses a program.
Staging itself trusts the descriptor (so it needs no toolchain); `verify.sh` is the
dev/CI gate that keeps the cached `config` honest.
