# lez-rln — non-obvious facts (LEZ v0.3.1)

The program keeps no on-chain membership tree: it emits one
`rln_layouts::events` event per successful action and readers rebuild the
tree (`src/zone`). There is one guest binary, `rln_registration`.

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
  release `.bin` into the `docker/` dir before provisioning, or you deploy
  stale code with no error.
- Known-good force rebuild: `rm -rf methods/target/riscv-guest && touch
  methods/build.rs && (cd methods && cargo build --release)`, then copy the
  `.bin`. Docker is NOT required — build.rs builds the guest locally — unless
  the host has no rzup toolchain (Intel macOS): then `cargo risczero build`
  (Docker) produces the bin, `RISC0_SKIP_BUILD=1` lets `methods/build.rs` run
  just the strip step, and `RISC0_LLVM_STRIP` can point at any llvm-strip
  (the builder image's own, run through `docker run`, gives identical bytes).
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
  the image id even when `lee_core` and `clock_core` are byte-identical
  across the tags (v0.3.0 -> v0.3.1: no source change, the bin differs), so
  every dependency bump is a redeploy.

## Execution model: plan, then apply, one shard per session
- A program's `plan` sees `AccountMeta { account_id, is_authorized,
  program_account_id }` and the instruction — never account data. Everything
  a handler used to read from an account (clock timestamp, config price,
  membership rate limit and expiry) travels in the instruction as a CLAIM
  (`rln_layouts::Instruction`, "Claimed values"), and the `apply` session that
  does see the shard asserts the claim. A wrong claim panics the apply and the
  whole transaction fails.
- EVENTS COME FROM THE PLAN ONLY (`Plan::event`; `ApplyOutput` has no
  events field). So every field an event carries must be an instruction
  argument the plan validated or a claim some apply asserts — never something
  read from an account. That is why `Extend` claims `expiry_timestamp_ms` (the
  post-extension expiry) and `ExtendMembership` asserts it
  (`EXIT_STALE_EXPIRY`): the plan cannot compute it, since it never sees the
  membership's grace start. A transaction that fails anywhere drops ALL its
  events (`from_public_transaction_metered` settles with `events: vec![]`),
  including ones a plan emitted before a later chained call failed
  (`register_rejects_an_underfunded_payer`). Private transactions carry no
  events at all.
- Every event names its `tree_id`: one deployed program can serve several
  registries, and the indexer filters by program id, not registry. A reader
  keeps one `MembershipSet` per tree id (`zone::for_registry`,
  `registries_sharing_a_program_keep_separate_trees`).
- The leaf index IS a claim: `ConfigState::next_leaf_index` (offset 112; the
  config is 120 B) counts every registration ever made and is never rewound
  by slash/erase, `Register` claims it, `RegisterConfig` asserts and advances
  it (`EXIT_STALE_LEAF_INDEX` = 22), and `Registered` carries it. Consequence:
  two registrations built from the same state CONTEND — the second exits 22,
  charged only its cycles, and must be rebuilt
  (`same_state_registrations_contend_for_the_leaf_index`). Don't confuse it
  with `total_registrations`, which slash/erase decrement. The reader checks
  each `Registered` index is its `next_index` (`ReaderError::LeafIndexMismatch`),
  so a missed or misordered event is an error, not a silent shift.
- Only `Registered` carries `rate_limit`; `Extended`/`Slashed`/`Erased` carry
  `tree_id`, `id_commitment` (+ expiry for `Extended`), and the reader takes
  the rate limit from the registration. The instructions still CLAIM
  `rate_limit` (slash and erase release it, extend prices by it).
- Each shard belongs to one program: registration data lives in the
  registration program's shard of its PDA, balances in the native shard
  (`[0;32]`), clock data in `clock_account_id()`'s shard of `CLOCK_50`. The
  host selects shards with `ProgramShardSelector`; a program can write only
  its own shard.
- Every plan and every apply is a separate zkVM session, and the transaction's
  gas (`≤ MAX_GAS_EXEC = 10M`, one gas per cycle) is the SUM. Measured
  (RISC0_DEV_MODE, `cycle_harness`, `membership_transactions_fit_the_gas_ceiling`),
  register 52,012 (plan 26,724 + three ~7-11K applies; the plan hashes
  nothing), extend 51,461, erase 46,502, slash 647,141 — the slash plan's one
  Poseidon (`hash_single(identity_secret)`) is ~600K of it. Re-measure after
  any guest change.
- A guest PANIC is charged the transaction's full declared gas; a guest that
  halts with `env::exit(code != 0)` is charged the cycles it ran
  (`ProgramExitedWithCode`, `validated_state_diff::from_public_transaction_metered`).
  Checks an honest client fails only because the chain moved after it read it
  use `ensure!(cond, EXIT_*, ..)` (`methods/guest/src/fail.rs`, codes in
  `rln_layouts::exit`); malformed-input checks stay `assert!`s and keep the
  full charge. Measured: a register with a stale clock claim is charged
  45,217 cycles (exit) vs 10,000,000 (panic).
  `a_stale_clock_claim_is_charged_measured_cycles`.

## Init guards are apply-side empty checks
Public transactions need no signature for PDA rows, so any instruction that
writes a PDA is submittable by anyone. What makes an initializer one-shot is
the apply asserting `pre_data.is_empty()` before writing (`InitConfig`,
`InitMembership`). Authorization (`is_authorized`) only says the caller may
write the account, never that the account is unclaimed.

Duplicate registration is refused SOLELY by the membership init guard — the
register plan has no duplicate check — and a weakened guard would also emit a
second `Registered` for the commitment, which readers refuse
(`ReaderError::AlreadyRegistered`). Regression:
`test_register_same_commitment_twice_fails`.

## Program ids are deployment state
`CreateHeader` requires an `is_authorized` target, so a program lives at a
keypair account the deployer created and signed — there is no bytecode-derived
address. `run_setup` creates the header account and records it; every PDA
hangs off that id, and every tool must be told it (deployment descriptor,
`~/.logos-lez-rln/programs_<tree_hex>.json`, or
`LEZ_RLN_REGISTRATION_PROGRAM_ID`), never derive it from the `.bin`. The
`.bin` still determines the IMAGE id the header must carry. The program id is
also what readers filter the indexer's events by.

## Renewal is priced, not permissioned
`extend` deliberately does not check caller identity — `MembershipState`
records no owner, and a third party paying for someone's renewal is
harmless. What is not harmless is renewal being FREE: `erase` reclaims a
membership's `rate_limit` only once it expires, so anyone could keep
abandoned memberships alive one cheap tx per grace window and pin
`current_total_rate_limit` at `max_total_rate_limit`, blocking all new
registrations. `extend` charges `rate_limit * price_per_unit` — the same as
registering — which also gives `active_duration` economic force.

## Readers, not the chain, hold the tree
Readers build at `proof_circuit::CIRCUIT_DEPTH` (10, the smallest published zerokit
circuit), so a reader's capacity is 1024 lifetime registrations per registry
(`ReaderError::TreeFull`); the chain bounds only `max_total_rate_limit`.
Expiry is a READER step (`MembershipSet::expire(now_ms)`): the chain never
removes a leaf on expiry, and because a clock claim may be up to
`CLOCK_CLAIM_TOLERANCE_MS` old, an `Extend` can land after a reader judged the
leaf expired — the reader re-inserts it at its own index
(`a_late_extension_reinserts_the_leaf_at_its_index`).

Events are served only by the LEZ indexer (`getEvents`; the sequencer RPC has
none, only an FFI). At v0.3.1 the indexer follows blocks through a Bedrock
channel, so it cannot follow `dev.sh`'s standalone sequencer;
`tools/e2e-local.sh` refuses to start without `LEZ_RLN_INDEXER_URL`. The
indexer's `event_filter` defaults to storing nothing: it must be `"archival"`
or name the program, or queries answer `UncoveredEventQuery`.

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

`state_tests` reads the guest `.bin` from the same `docker/` dir the deploy
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
- register_member's "Timeout waiting for the membership" panic can be a FALSE
  negative: testnet confirmation regularly exceeds a short poll (raise
  `LEZ_RLN_ACCOUNT_WAIT_ATTEMPTS`); it has fired while the registration had
  actually landed.
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
- The state tests need an `r0vm` on PATH (the risc0 executor shells out to
  it; rzup installs one). Without it every zkVM test fails with
  `ProgramExecutionFailed("No such file or directory")`. In a Linux container:
  `cargo install cargo-risczero@3.0.5 --locked` provides it.
