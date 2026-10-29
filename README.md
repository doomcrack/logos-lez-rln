# logos-lez-rln

This repository contains the LEZ program for the RLN (Rate-Limiting Nullifiers) membership registry.

The program keeps **no on-chain Merkle tree**. It takes deposits, validates
commitments and runs the membership lifecycle (register, extend, slash, erase),
and emits one LEZ `ProgramEvent` per successful action. Separate
services rebuild the membership tree from those events
([Events and the off-chain tree](#events-and-the-off-chain-tree)).

## Prerequisites

- Rust
```bash
# Install rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add nightly toolchain (required for guest unit tests)
rustup toolchain install nightly
```
- [RISC Zero toolchain](https://dev.risczero.com/api/zkvm/install)
- Docker (for guest program compilation)

The Rust toolchain is pinned via `rust-toolchain.toml`. LEZ
(`logos-execution-zone`) is consumed as **git dependencies pinned by tag** in
`lez-rln/Cargo.toml` and `lez-rln/methods/guest/Cargo.toml` — a fresh clone
builds with no sibling checkouts to place by hand. `dev.sh` pins the same tag
in `LEZ_REF`; move all three together.

## Usage
### Build

```bash
cd lez-rln
cargo risczero build --manifest-path methods/guest/Cargo.toml   # reproducible deploy guest bin
cargo build                                                     # host
(cd methods && cargo build)                                     # strips the deploy bin's user ELF
```

Order matters: `cargo risczero build` produces the deploy artifact under
`methods/guest/target/.../docker/`, and a subsequent `cargo build` in
`methods/` runs `methods/build.rs`, which strips the user ELF inside it (and
the local build). The kernel ELF is left untouched — the program loader only accepts the
canonical `risc0_zkos_v1compat` kernel. Re-run `cargo build` after any
`cargo risczero build`.

### Test

```bash
cd lez-rln
(cd methods/guest && cargo +nightly-2025-12-15 test --lib)   # guest unit tests (CI's pinned nightly)
cargo test                                                # host unit tests
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true RISC0_DEV_MODE=1 \
  cargo test --release --features rc5-state-tests         # in-process state tests + cycle harness
bash ../tools/e2e-local.sh                                # lifecycle against a local sequencer
```

`tools/e2e-local.sh` boots the pinned sequencer with `dev.sh`, funds a payer at
genesis, and runs `lez-rln/tests/local_sequencer.rs`: deploy, init, three
registrations, an RLN proof against the root a reader rebuilds from the
program's events, a refused duplicate, slash, extend and erase. The events come
from a LEZ indexer (`LEZ_RLN_INDEXER_URL`), and at v0.3.1 the indexer follows
blocks through a Bedrock channel that `dev.sh`'s standalone sequencer does not
publish to, so the script refuses to start without an indexer that follows the
sequencer under test (LEZ's `lez/configs/docker-all-in-one` stack). It stamps memberships with second-long durations so
the two time-gated steps clear within a few `CLOCK_50` ticks; expect it to take
a few minutes. On macOS the state tests need
`DYLD_FRAMEWORK_PATH=/Library/Developer/CommandLineTools/Library/Frameworks`
(see `lez-rln/CLAUDE.md`).

### Run end-to-end against a sequencer

Terminal 1:

```bash
./dev.sh   # fetches the pinned sequencer source into a cache on first run, then starts it
```

Terminal 2:

```bash
source dev/env.sh
cd lez-rln
cargo run --bin run_setup        # deploys the program, initializes the registry
cargo run --bin register_member  # registers a single identity (--count N to batch)
cargo run --bin get_roots        # rebuilds the tree from events, prints its root
cargo run --bin run_rln_proof    # generate + verify an RLN proof against that root
```

`get_roots` and `run_rln_proof` read the program's events from the indexer at
`LEZ_RLN_INDEXER_URL`. `run_rln_proof` is the canonical end-to-end smoke test:
it registers an identity, waits for its `Registered` event, rebuilds the tree,
generates an RLN proof via zerokit, and verifies it against the rebuilt root.

## Structure

- `rln-layouts/` - Shared instruction, state and event layouts, constants, and PDA seed construction (no_std, used by both host and guest)
- `methods/guest/` - the zkVM guest program (`rln_registration`)
- `src/rln/` - RLN client library (PDA derivation, transactions)
- `src/zone/` - the off-chain tree: event decoding, the derivation rules (`MembershipSet`), the indexer client
- `src/bin/` - CLI tools

## Execution model

LEZ runs a program in two phases. **Plan** sees only account ids and
authorization flags plus the instruction, and emits *effects* (one per shard it
touches) and chained calls. **Apply** runs once per effect, sees exactly one
shard's bytes, and returns that shard's new bytes. Every value a handler needs
from an account — the clock's timestamp, the config's price, a membership's
rate limit and expiry — therefore travels in the instruction as a **claim**,
and the apply that can see the account asserts it. Effects are applied before
the plan's chained calls run, so a false claim fails the transaction before
anything downstream executes.

**Events are emitted by the plan too** (`Plan::event`; an apply cannot emit),
so every field an event carries is a claim or an argument that some apply
asserts. A transaction that fails anywhere — a refused claim, an unaffordable
payment — is reverted and emits nothing.

Each account is a map of per-program **shards**. Registration state lives in
the registration program's shard of its PDAs, balances in the native shard,
and the clock in the clock program's shard of `CLOCK_50`. A program can write
only its own shards.

## Events and the off-chain tree

Every successful action emits exactly one event (`rln-layouts/src/events.rs`).
Selectors follow LEZ's `bridge::Deposit`: the first 8 bytes of
`sha256("rln_registration::<Event>")`, pinned as literals. Data is the borsh
encoding, fixed-width little-endian fields in this order (`RlnEvent::decode`
reads both, for a Rust reader that depends on `rln-layouts`):

| Event        | Emitted by | Selector           | Data                                                            | Size |
|--------------|------------|--------------------|-----------------------------------------------------------------|------|
| `Registered` | `Register` | `b7ab5ade1703cde8` | `tree_id(32) id_commitment(32) rate_limit(u64) expiry_timestamp_ms(u64) leaf_index(u64)` | 88 B |
| `Extended`   | `Extend`   | `631ffa56866231d2` | `tree_id(32) id_commitment(32) expiry_timestamp_ms(u64)`         | 72 B |
| `Slashed`    | `Slash`    | `19e9a783dd521a1b` | `tree_id(32) id_commitment(32)`                                  | 64 B |
| `Erased`     | `Erase`    | `88af4b20b9dcb6aa` | `tree_id(32) id_commitment(32)`                                  | 64 B |

`expiry_timestamp_ms` is the end of the membership's grace period (the instant
from which it is expired). `tree_id` names the registry, since one deployed
program can serve several; a reader keeps one tree per `tree_id`. Only
`Registered` carries `rate_limit`: the later events name the membership by
`id_commitment`, and a reader takes the rate limit from its registration.

**Leaf indices are assigned on chain.** The config counts every registration
ever made in `next_leaf_index` (a slash or erase never rewinds it, so an index
is never reused). `Register` claims that value, the config apply asserts it
(`EXIT_STALE_LEAF_INDEX` otherwise) and advances it, and `Registered` carries
it. A registry's `Registered` events therefore carry 0, 1, 2… in LEZ block
order (block, transaction index, emission order); a reader checks each is the
next one, which catches a missed or misordered event. The cost is contention:
two registrations built from the same chain state claim the same index, and
the one that lands second is refused (charged only its cycles) and must be
rebuilt.

The derivation rules (`src/zone/reader.rs`, `MembershipSet`), per event in
order:

- `Registered` → `Insert{leaf_index, poseidon(id_commitment, rate_limit)}` at
  the event's `leaf_index`.
- `Slashed` → `Remove{leaf_index}` if the leaf is live; nothing if it already
  expired.
- `Extended` → no change; the reader keeps the new expiry. If the reader had
  already expired the leaf (the chain accepts a clock claim up to
  `CLOCK_CLAIM_TOLERANCE_MS` old), the leaf goes back at its own index.
- `Erased` → no change, since erase needs an expired membership; a leaf the
  reader still holds as live is removed defensively.
- Expiry step (`MembershipSet::expire(now_ms)`): remove every live leaf whose
  expiry is at or before `now_ms`.

Readers build the tree at the depth of the RLN circuit their provers use: this
repository's reference reader at `proof_circuit::CIRCUIT_DEPTH` (10, the
smallest zerokit publishes), the membership module and the zone service at
zerokit's default 20. Capacity is bounded by `max_total_rate_limit` on chain
and by the readers' tree depth off it.

This repository's reader takes events from the LEZ indexer's `getEvents`
(`src/zone/indexer.rs`): at most 1000 blocks per query, paged from the
deployment's start block to `getLastFinalizedBlockId`, and only if the
indexer's `event_filter` covers the program (`"archival"` or a source naming
its id). To follow new events without a gap, subscribe (`subscribeToEvents`)
before paging the past and drop duplicates by (block, transaction index,
emission position). Leave the selector filter out: all four event types in one
stream, in order. Private transactions carry no events, so a registration must
be public to be seen.

## RLN Registration Program

The registration program manages membership: deposits, commitment
validation, the rate-limit budget and each membership's lifecycle. It writes no
tree; every action it accepts is published as an event instead.

### Accounts

All accounts are PDAs derived from the registration program's account id — the
header account the deployer created, recorded in the deployment descriptor —
and a 32-byte `tree_id`. Each PDA's address is
`for_public_pda(program, SHA-256(seed_1 || seed_2 || ...))` where each seed is
zero-padded to 32 bytes (string labels) or passed through (32-byte args).

| Account          | Seeds                                       | Contents                                              |
|------------------|---------------------------------------------|-------------------------------------------------------|
| Config           | `["config", tree_id]`                       | Tree ID, price, treasury, rate limit tracking, membership durations |
| Membership       | `["membership", tree_id, id_commitment]`    | Per-identity (rate_limit, expiry timestamps) |

The treasury is deliberately **not** a PDA. A PDA is spendable only through a
chained call carrying its seeds, issued by its owning program, and this program
has no instruction that would issue one — so a PDA treasury would accrue revenue
nothing could ever move. It is a plain account named in the config instead.

### Instructions

Instructions are the Borsh `Instruction` enum in `rln-layouts/src/instruction.rs`,
shared by the guest (`methods/guest/src/program.rs`, entry point
`methods/guest/src/bin/rln_registration.rs`) and the host. The doc comment
there lists which fields are claims and which apply asserts each one.

**Initialize** — Writes the config PDA: tree ID, price, treasury, rate-limit
cap and membership durations. Emits no event.

**Register** — Atomic payment + registration, in one asset. Chains a native
transfer of `rate_limit * price_per_unit` from the signing account to the
treasury, checks that `id_commitment` is a non-zero BN254 field element
(readers hash it into a Poseidon leaf), creates a membership PDA (apply refuses
a non-empty shard, which is what makes an `id_commitment` unique), takes the
config's `next_leaf_index` (claimed by the instruction, asserted and advanced
by the config apply), and emits `Registered` with it. The clock
timestamp is claimed and guarded by a read-only effect on `CLOCK_50`: the claim
may trail the clock by up to `CLOCK_CLAIM_TOLERANCE_MS` (one clock step, so a
register straddling a step still lands) and never lead it. The
signer is also the transaction's fee payer, so one account and one balance
cover the whole thing.

**Slash** — Anyone can remove a spammer by providing their `identity_secret`.
The program verifies `id_commitment = hash(identity_secret)`, the membership
apply checks the claimed rate limit and clears the membership, and the plan
emits `Slashed`. Frees the consumed rate limit.

**Extend** — Renews an existing membership's active period from the current
clock (a membership in its grace period can be extended rather than
re-registered). Anyone may call it, including on someone else's behalf, but it
costs the same as registering that membership's rate limit — free renewal would
let a third party pin an abandoned membership's share of the rate-limit budget
indefinitely. The instruction claims the expiry the extension produces, the
membership apply asserts it (`EXIT_STALE_EXPIRY` otherwise), and `Extended`
carries it.

**Erase** — Removes an expired membership, returning the member's rate limit
to the pool, and emits `Erased`.

There is no faucet and no free-registration path. A faucet is not expressible
for the native asset — no program can mint it — so balance arrives only at
genesis, over the L1 bridge, or by transfer. See
`tools/deployments/README.md` for the profile workflow.

### Rate Limits

Each registration consumes rate limit from a global pool (`current_total_rate_limit` in config). Rate limit per member must be between 100 and 600. Slashing returns the member's rate limit to the pool.

## Testnet deployments

Reusable on-chain deployments (one RLN tree + its wallet) are captured as
**deployment profiles** under `deployments/<name>/` and managed by the shared
tooling in [`tools/deployments/`](tools/deployments/README.md):
`provision.sh` deploys a fresh tree (`--payer` is required — it pays the deploy
fees and becomes the deployment's `payer_account`), `stage.sh` stages an
existing profile into the flat files consumers expect, and `verify.sh` guards
against guest drift. See that README for the profile format and the
run-against-existing / redeploy-fresh workflows.

**`testnet-zone-events`** is the events-era deployment on the public testnet
(sequencer `https://testnet.lez.logos.co/`), deployed at block **49431**; no
event precedes it. Its profile is not committed (see the note below); a reader
needs these values:

| What | Value |
|---|---|
| Program account (base58, what to filter events on) | `HAxY9SiqUjJQHdtvazFDWFCxn1Jw1dtbUGio8DMC4bBw` |
| The same id as hex (`registration_program_id`) | `f04803944507677bb79b27b61cd0ad6eea81928f281570347e2df6249495106a` |
| Registry (`tree_id`, the first field of every event) | `47b2de4f08080e74e2d4beffe8e5e87e709dd598619c9b322b64f2756979b4cf` |
| Config account | `BpxYQFLWf6Wi5HhWAaZRtbhxmeKa5P9THK7WBDCoXRg9` |

**Security note:** a profile's `storage.json` contains signing keys and may be
committed to a repo. That warning is stronger now than it was: the key it
carries no longer unlocks test tokens with no value, it unlocks an account
holding **native** balance — the same asset that pays every fee on the chain.
Treat any key in a committed profile as public, fund it only with what a run
needs, and do not reuse this pattern for any environment with real value.
