# Deployment profiles

Each `deployments/<name>/` is one provisioned RLN registry, captured as
`{deployment.json, storage.json}`. The tooling that writes and consumes them
lives in [`tools/deployments/`](../tools/deployments/README.md).

**This directory is currently empty, and that is deliberate.**

Registration became native-asset-only, which changed the guest program, and
program ids became deployment state: each program's account id is a header
account created and signed at deploy time, recorded by `run_setup`, and every
PDA hangs off it. The eight profiles that used to live here addressed a program
that no longer exists, carry no program ids, and describe a config layout — 296
bytes with a payment token, a faucet cap and a free-quota registrar — that
nothing can decode any more. `stage.sh` refuses them (missing `payer_account`).

They were deleted rather than left as history, because a deployment profile
that cannot be staged is not a record of anything: it is a trap for whoever
tries it next. `git log -- deployments/` has them if you need to look.

A descriptor is:

```json
{
  "name": "<name>", "tree_id": "<64 hex>", "sequencer": "<url>",
  "registration_program_id": "<64 hex>",
  "config_account": "<base58>", "payer_account": "<base58>", "treasury_account": "<base58>"
}
```

To provision one against the new program:

```sh
bash tools/deployments/provision.sh --name <name> --payer <account-id>
```

`--payer` must already hold native balance. No program can mint native, so it
arrives at genesis, over the L1 bridge, or by transfer from something already
funded.
