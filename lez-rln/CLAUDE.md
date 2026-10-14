# lez-rln — non-obvious facts (LEZ v0.3.0)

## Guest binaries: two stale-binary traps
- Building or testing the host crate NEVER rebuilds the guest — lez-rln has
  no cargo dependency on `methods/`. Edits to `methods/guest/src/` silently
  keep executing the old ELF until you build inside `methods/` yourself
  (observed: a July 6 `.bin` serving July 31 source edits, tests "passing"
  against unfixed code).
- The deploy host reads `methods/guest/target/riscv32im-risc0-zkvm-elf/docker/*.bin`
  (`REGISTRATION_BINARY`), but a local `cargo build` in `methods/` writes to
  `methods/target/riscv-guest/.../riscv32im-risc0-zkvm-elf/release/`.
  build.rs strips both dirs but copies nothing between them — copy the fresh
  release `.bin`s into the `docker/` dir before provisioning, or you deploy
  stale code with no error.
- Known-good force rebuild: `rm -rf methods/target/riscv-guest && touch
  methods/build.rs && (cd methods && cargo build --release)`, then copy the
  two `.bin`s. Docker is NOT required — build.rs builds the guest locally.
- build.rs strips the USER ELF only. The kernel ELF inside the R0BF `.bin`
  must stay byte-identical to `risc0_zkos_v1compat::V1COMPAT_ELF`: the
  program loader refuses any other kernel, and only the user ELF is uploaded
  (96 KiB segments, at most 20), so stripping the kernel buys nothing and
  bricks the deploy.
- Builds are reproducible but LINE-SENSITIVE: panic `Location` metadata
  embeds file:line, so adding a blank line or editing a comment in the guest
  produces a different image id. The program's ACCOUNT id (and so every PDA)
  is the deployer-chosen header account, not the image id, so a rebuilt guest
  can be redeployed under the same ids with `UpdateHeader` — but the image id
  the host compares against changes, so finish guest comment churn BEFORE
  provisioning.
- The same metadata embeds the cargo git-checkout path of every dependency,
  which contains the pinned commit hash. Bumping the LEZ tag therefore changes
  both image ids even when `lee_core` and `clock_core` are byte-identical
  across the tags (v0.3.0 -> v0.3.1: no source change, both bins differ), so
  every dependency bump is a redeploy.

## Execution model: plan, then apply, one shard per session
- A program's `plan` sees `AccountMeta { account_id, is_authorized,
  program_account_id }` and the instruction — never account data. Everything
  a handler used to read from an account (clock timestamp, config price /
  callee id, membership rate limit) travels in the instruction as a CLAIM
  (`rln_layouts::Instruction`, "Claimed values"), and the `apply` session that
  does see the shard asserts the claim. A wrong claim panics the apply and the
  whole transaction fails.
- The leaf index is deliberately NOT a claim: the merkle `Insert` takes it
  from the tree's own `next_index`. An index claim goes stale the moment any
  other registration lands first, so two registrations built from the same
  state would contend and one would revert; without it they compose
  (`same_block_registrations_compose`). Slash/erase send the index as a hint
  and the merkle `Remove` checks the leaf there equals
  `H(id_commitment, rate_limit)` — the membership apply has already pinned
  `rate_limit`, so a wrong hint removes nothing
  (`remove_refuses_a_wrong_index_or_leaf`). Clients locate a leaf by scanning
  the tree (`merkle_tree::find_leaf_index`); no account stores it.
- In a public transaction, effects are applied immediately after their plan,
  BEFORE the plan's chained calls run (`execution_state.rs::run`). In a
  privacy-preserving transaction public effects are deferred to settlement
  (`DeferPublicEffects`), so the merkle call may run first — but the
  transaction is still all-or-nothing, so a false `merkle_program_id` claim
  still fails it and the callee's writes are discarded with it. That is what
  keeps the "chained-call targets come from config" rule alive: the config
  apply asserts the claimed `merkle_program_id` against the stored one, and
  nothing lands unless it matches.
- Each shard belongs to one program: registration data lives in the
  registration program's shard of its PDA, the tree in the merkle program's
  shard of `tree_main`, balances in the native shard (`[0;32]`), clock data in
  `clock_account_id()`'s shard of `CLOCK_50`. The host selects shards with
  `ProgramShardSelector`; a program can write only its own shard.
- Every plan and every apply is a separate zkVM session, and the transaction's
  gas (`≤ MAX_GAS_EXEC = 10M`, one gas per cycle) is the SUM. A register runs
  six sessions; measured (RISC0_DEV_MODE, `cycle_harness`): registration plan
  933,829 (one Poseidon for the leaf), config/clock/membership applies
  ~12K/7K/8K, merkle plan ~10K, merkle Insert apply 8,173,396 (nine Poseidons)
  — whole tx 9,143,916, 91.4% of the ceiling. Session overhead is noise;
  Poseidon is the budget, which is why the tree is depth 9 and a tenth level
  (+~0.9M) does not fit. Re-measure with `cycle_harness` and
  `register_transaction_fits_the_gas_ceiling` after any guest change.
- Slash is the tightest transaction, not register: its plan hashes the
  identity secret AND the member's leaf (for the merkle `Remove` content
  check) before the nine-Poseidon root update — 9,736,047 cycles, 97.4% of the
  ceiling (erase 9,135,211; `slash_and_erase_transactions_fit_the_gas_ceiling`).
  Any guest change that adds a hash to slash does not fit.
- A guest PANIC is charged the transaction's full declared gas; a guest that
  halts with `env::exit(code != 0)` is charged the cycles it ran
  (`ProgramExitedWithCode`, `validated_state_diff::from_public_transaction_metered`).
  Checks an honest client fails only because the chain moved after it read it
  use `ensure!(cond, EXIT_*, ..)` (`methods/guest/src/fail.rs`, codes in
  `rln_layouts::exit`); malformed-input checks stay `assert!`s and keep the
  full charge. Measured: a register with a stale clock claim costs 953,532
  cycles (exit) vs 10,000,000 (panic) — almost all of it the plan's leaf
  Poseidon, which runs before any apply, so effect order barely matters
  (ClockIs first: 941,292). `a_stale_clock_claim_is_charged_measured_cycles`.

## Init guards are apply-side empty checks
Public transactions need no signature for PDA rows, so any instruction that
writes a PDA is submittable by anyone. What makes an initializer one-shot is
the apply asserting `pre_data.is_empty()` before writing (`InitConfig`,
`InitMembership`, merkle `Initialize`). Authorization (`is_authorized`) only
says the caller may write the account, never that the account is unclaimed.

History: `initialize_merkle_tree` once shipped with authorization only, so
replaying it against a live tree reset `next_index` and the root history —
invalidating every member's proof while their membership PDAs survived.
Regressions: `test_initialize_merkle_tree_cannot_reset_a_live_tree` (state)
and `merkle_tree::tests::test_initialize_rejects_live_tree` (guest unit).
Duplicate registration is refused SOLELY by the membership init guard — the
register plan has no duplicate check and the merkle insert doesn't dedupe.
Regression: `test_register_same_commitment_twice_fails`.

## Program ids are deployment state
`CreateHeader` requires an `is_authorized` target, so a program lives at a
keypair account the deployer created and signed — there is no bytecode-derived
address. `run_setup` creates the two header accounts and records them; every
PDA hangs off those ids, and every tool must be told them (deployment
descriptor, `~/.logos-lez-rln/programs_<tree_hex>.json`, or `LEZ_RLN_REGISTRATION_PROGRAM_ID` / `LEZ_RLN_MERKLE_PROGRAM_ID`), never derive them from the `.bin`. The `.bin`
still determines the IMAGE id the header must carry.

## Renewal is priced, not permissioned
`extend` deliberately does not check caller identity — `MembershipState`
records no owner, and a third party paying for someone's renewal is
harmless. What is not harmless is renewal being FREE: `erase` reclaims a
membership's `rate_limit` only once it expires, so anyone could keep
abandoned memberships alive one cheap tx per grace window and pin
`current_total_rate_limit` at `max_total_rate_limit`, blocking all new
registrations. `extend` charges `rate_limit * price_per_unit` — the same as
registering — which also gives `active_duration` economic force.

## The tree holds 512 leaves, and that is a lifetime count
`next_index` only advances and an erased leaf's index is never reused, so
`TREE_LEAVES` bounds total registrations over the tree's life, not concurrent
members. The whole tree is one sparse node map in one shard (u16 BFS offsets,
`TREE_SHARD_MAX_BYTES` under the 100 KiB shard cap, asserted at build time);
an index past the last leaf would alias live nodes and return a wrong root
WITHOUT failing, so `insert_leaf` asserts the bound (the register plan cannot:
it never sees `next_index`). `MerkleInstruction::Set` exists with no callers
and is the only index-reuse path if capacity ever has to grow.

## Running state_tests.rs
Plain `cargo test` prints "0 passed, N filtered out" and exits 0 — it ran
nothing. The suite is feature-gated, and on macOS PyO3 needs the framework
path or tests die in dyld with SIGABRT
("Library not loaded: @rpath/Python3.framework"):

    CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true \
    RISC0_DEV_MODE=1 \
    DYLD_FRAMEWORK_PATH=/Library/Developer/CommandLineTools/Library/Frameworks \
    cargo test --release --features rc5-state-tests

`CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true` is not optional: lee's
`test-utils` feature (which the `nssa` dev-dependency enables) is a
`compile_error!` in a release profile without debug assertions.

`state_tests` reads the guest `.bin`s from the same `docker/` dir the deploy
host uses, which is also the record of what is live. Set `LEZ_RLN_GUEST_DIR`
to a fresh build's `release/` dir to test guest changes without overwriting
the artifacts `verify.sh` compares against.

The in-process suite never touches a sequencer. `bash tools/e2e-local.sh`
runs `lez-rln/tests/local_sequencer.rs` — the whole lifecycle including slash,
extend and erase — against a `dev.sh` sequencer at the pinned tag, with
second-long membership durations (`LEZ_RLN_ACTIVE_DURATION_SECS` /
`LEZ_RLN_GRACE_PERIOD_DURATION_SECS`). ~5 minutes, most of it waiting for
`CLOCK_50` ticks. The test is a no-op without `LEZ_RLN_LOCAL_SEQUENCER`.

## Testnet operations
- register_member's "Timeout waiting for leaf N" panic is often a FALSE
  negative: `wait_for_leaf` polls a hardcoded 30 × 500 ms and testnet
  confirmation regularly exceeds 15 s. Measured: the panic fired while the
  registration had actually landed (tree `next_index` and config
  `total_registrations` both advanced).
- Do NOT blindly re-run after that panic. The tx was submitted (and paid)
  before the poll; a re-run mints a fresh identity + payer and registers a
  SECOND distinct member at a second full payment. Worse, the first
  membership's IDENTITY_SECRET_HASH is lost — it prints only after the
  panic point. Recoverable in principle (the wallet account persists;
  `seeded_keygen` is deterministic) but no tool does that recovery. Check
  on-chain state first.
- A failed transaction is left out of the block entirely: submission returns
  a hash, `getTransaction` → null, and the concrete error appears only in
  the sequencer's own log. Run a local sequencer (`dev.sh`) and read its log
  before believing any client-side diagnosis.
- Deploying new program instances to https://testnet.lez.logos.co/ is
  normal, routine development practice (`tools/deployments/provision.sh`).
- The wallet declares `WalletConfig.gas_limit` (default 2M) on every
  deploy/init transaction it sends, so the payer's reserve must cover
  `gas_limit × base_fee_exec` per transaction; `send_metered_tx` declares its
  own `LEZ_RLN_GAS_LIMIT` (default the 10M cap).
- Wallet sync is only required for tree insertion (registration); claims and
  reads work against an unsynced wallet.
