//! Guest cycle-count measurement harness.
//!
//! A public transaction runs one zkVM session per plan and one per apply, and
//! its gas (`fee_core::market::MAX_GAS_EXEC = 10M`, one gas per cycle) is the
//! SUM over every session of every program in the call chain. This harness
//! replays a full `Register` and a `Slash` (whose plan hashes the identity
//! secret, the one Poseidon the program still computes) one session at a
//! time, framing each call with `Program::write_plan_inputs` /
//! `write_apply_inputs` exactly as lee does, and prints every session's cycles
//! next to the whole-transaction count lee's own metering reports for the same
//! call. The only chained call left is the native transfer, which lee runs as
//! Rust, not as a session.
//!
//! Run:
//! ```bash
//! RISC0_DEV_MODE=1 cargo test --release --features rc5-state-tests \
//!   cycle_harness -- --nocapture
//! ```
//! `execute()` never proves, so dev mode is optional. The `.bin`s must be
//! staged (see `lez-rln/CLAUDE.md`); if they are absent the tests fail.

#[cfg(all(test, feature = "rc5-state-tests"))]
mod tests {
    use std::collections::HashMap;

    use nssa::{
        AccountId, PublicTransaction, V03State, ValidatedStateDiff,
        program::{DEFAULT_PUBLIC_CYCLE_BUDGET, Program},
    };
    use nssa_core::{
        account::ShardData,
        native_token::NATIVE_TOKEN_PROGRAM_ID,
        program::{AccountMeta, ApplyInput, ApplyOutput, GuestOutput, PlanInput, PlanOutput},
    };
    use risc0_zkvm::{ExecutorEnv, ExecutorEnvBuilder, default_executor};

    use crate::{
        fr_bytes::{bytes_le_to_fr, fr_to_bytes_le},
        state_tests::fixtures::{
            REG_ID, TestSetup, load_registration, register, register_ix, register_tx, setup,
            slash_ix, slash_tx,
        },
    };

    /// risc0's per-session limit; no single plan or apply may cross it.
    const SESSION_LIMIT: u64 = 1 << 25;

    /// What rejects a transaction: the summed cycles of all its sessions.
    const MAX_GAS_EXEC: u64 = 10_000_000;

    /// Early-warning budget for a whole membership transaction. With no
    /// tree to update, the heaviest is a slash at about one Poseidon
    /// compression; this sits well above it and well below `MAX_GAS_EXEC`, so
    /// a codegen or dependency change that inflates cycles is caught with
    /// margin to react.
    const TX_EARLY_WARNING: u64 = 3_000_000;

    fn programs() -> HashMap<AccountId, Program> {
        HashMap::from([(
            REG_ID,
            load_registration().expect("registration .bin staged"),
        )])
    }

    /// One zkVM session, framed by `write`, under the session limit.
    fn session(
        program: &Program,
        write: impl FnOnce(&mut ExecutorEnvBuilder<'_>),
    ) -> (u64, GuestOutput) {
        let mut builder = ExecutorEnv::builder();
        builder.session_limit(Some(DEFAULT_PUBLIC_CYCLE_BUDGET.min(SESSION_LIMIT)));
        write(&mut builder);
        let env = builder.build().expect("build executor env");
        let info = default_executor()
            .execute(env, program.elf())
            .expect("guest trapped or exceeded the session limit");
        let payload = nssa_core::from_frame(&info.journal.bytes).expect("framed journal");
        (
            info.cycles(),
            borsh::from_slice(payload).expect("journal decodes as GuestOutput"),
        )
    }

    fn plan(program: &Program, input: &PlanInput) -> (u64, PlanOutput) {
        match session(program, |env| {
            Program::write_plan_inputs(input, env).expect("frame plan input");
        }) {
            (cycles, GuestOutput::Plan(out)) => (cycles, out),
            (_, GuestOutput::Apply(_)) => panic!("a plan returned an apply journal"),
        }
    }

    fn apply(program: &Program, input: &ApplyInput) -> (u64, ApplyOutput) {
        match session(program, |env| {
            Program::write_apply_inputs(input, env).expect("frame apply input");
        }) {
            (cycles, GuestOutput::Apply(out)) => (cycles, out),
            (_, GuestOutput::Plan(_)) => panic!("an apply returned a plan journal"),
        }
    }

    /// Shards keyed by `(account, owning program)`, seeded from a state.
    type Shards = HashMap<(AccountId, AccountId), ShardData>;

    /// Replay one call and its chained calls in lee's order (a call's effects
    /// apply right after its plan, then its chained calls run), recording
    /// every session. Native transfers run as Rust in lee — no session — and
    /// are skipped.
    fn replay(
        programs: &HashMap<AccountId, Program>,
        shards: &mut Shards,
        program_id: AccountId,
        caller: Option<AccountId>,
        accounts: Vec<AccountMeta>,
        instruction_data: Vec<u8>,
        log: &mut Vec<(String, u64)>,
    ) {
        let program = &programs[&program_id];
        let name = "registration";
        let input = PlanInput {
            self_account_id: program_id,
            caller_account_id: caller,
            accounts,
            instruction_data,
        };
        let (cycles, out) = plan(program, &input);
        log.push((format!("{name} plan"), cycles));

        for effect in &out.effects {
            let key = (
                effect.selector.account_id,
                effect.selector.program_account_id,
            );
            let pre_data = shards.get(&key).cloned().unwrap_or_default();
            let (cycles, applied) = apply(
                program,
                &ApplyInput {
                    self_account_id: program_id,
                    selector: effect.selector,
                    pre_data,
                    effect_data: effect.data.clone(),
                },
            );
            log.push((format!("{name} apply {:?}", short(&key.0)), cycles));
            if let Some(post) = applied.post_data {
                shards.insert(key, post);
            }
        }

        for call in out.chained_calls {
            if call.program_account_id == NATIVE_TOKEN_PROGRAM_ID {
                continue;
            }
            let metas = call
                .shard_selectors
                .iter()
                .map(|s| AccountMeta::new(s.account_id, true, s.program_account_id))
                .collect();
            replay(
                programs,
                shards,
                call.program_account_id,
                Some(program_id),
                metas,
                call.instruction_data,
                log,
            );
        }
    }

    fn short(id: &AccountId) -> String {
        hex::encode(&id.value()[..4])
    }

    /// Every shard of every account the transaction names, from `state`.
    fn shards_of(state: &V03State, tx: &PublicTransaction) -> Shards {
        tx.message()
            .shard_selectors
            .iter()
            .map(|s| {
                (
                    (s.account_id, s.program_account_id),
                    state
                        .get_account_by_id(s.account_id)
                        .data
                        .shard(s.program_account_id)
                        .clone(),
                )
            })
            .collect()
    }

    fn whole_tx_cycles(state: &V03State, tx: &PublicTransaction) -> u64 {
        ValidatedStateDiff::from_public_transaction_with_cycle_budget(tx, state, 1, 0, MAX_GAS_EXEC)
            .expect("transaction executes within MAX_GAS_EXEC")
            .1
            .cycles
    }

    /// Replay `tx` session by session, print the table, and check it against
    /// lee's whole-transaction count.
    fn measure(
        label: &str,
        state: &V03State,
        tx: &PublicTransaction,
        payer: Option<AccountId>,
    ) -> Vec<(String, u64)> {
        let programs = programs();
        let mut shards = shards_of(state, tx);
        let message = tx.message();
        let accounts = message
            .shard_selectors
            .iter()
            .map(|s| {
                AccountMeta::new(
                    s.account_id,
                    Some(s.account_id) == payer,
                    s.program_account_id,
                )
            })
            .collect();
        let mut log = Vec::new();
        replay(
            &programs,
            &mut shards,
            message.program_account_id,
            None,
            accounts,
            message.instruction_data.clone(),
            &mut log,
        );

        let sum: u64 = log.iter().map(|(_, c)| c).sum();
        let whole = whole_tx_cycles(state, tx);
        println!("── {label} ──");
        for (what, cycles) in &log {
            println!("  {what:<32} {cycles:>10}");
        }
        println!(
            "  {:<32} {sum:>10}\n  {:<32} {whole:>10} ({:.1}% of MAX_GAS_EXEC)",
            "sum of sessions",
            "whole tx (lee metering)",
            whole as f64 / MAX_GAS_EXEC as f64 * 100.0
        );
        assert_eq!(
            sum, whole,
            "{label}: the session replay must account for every metered cycle"
        );
        for (what, cycles) in &log {
            assert!(
                *cycles < SESSION_LIMIT,
                "{label}: {what} crosses the session limit"
            );
        }
        assert!(
            whole <= MAX_GAS_EXEC,
            "{label}: {whole} cycles over MAX_GAS_EXEC"
        );
        log
    }

    #[test]
    fn register_cycles_under_budget() {
        let setup: TestSetup = setup().expect("guest .bins staged");
        let mut id_commitment = [0u8; 32];
        id_commitment[0] = 0x42;
        let tx = register_tx(&setup, register_ix(&setup.state, id_commitment, 100));
        let log = measure("Register", &setup.state, &tx, Some(setup.payer_id));
        assert!(
            log.iter().all(|(w, _)| w.starts_with("registration")),
            "a register runs no other program's sessions: {log:?}"
        );
        let whole: u64 = log.iter().map(|(_, c)| c).sum();
        assert!(
            whole < TX_EARLY_WARNING,
            "Register {whole} cycles exceeds the early-warning budget {TX_EARLY_WARNING}"
        );
    }

    #[test]
    fn slash_cycles_under_budget() {
        let mut setup: TestSetup = setup().expect("guest .bins staged");
        let mut secret = [0u8; 32];
        secret[0] = 0x42;
        let id_commitment = fr_to_bytes_le(
            &rln::prelude::Hasher::<rln::prelude::PoseidonHash>::hash_single(
                bytes_le_to_fr(&secret).expect("valid secret"),
            ),
        );
        register(&mut setup, id_commitment, 100);
        let tx = slash_tx(&setup.state, slash_ix(&setup.state, secret, id_commitment));
        let log = measure("Slash", &setup.state, &tx, None);
        let whole: u64 = log.iter().map(|(_, c)| c).sum();
        assert!(
            whole < TX_EARLY_WARNING,
            "Slash {whole} cycles exceeds the early-warning budget {TX_EARLY_WARNING}"
        );
    }

    /// The deploy path uploads only the user ELF and re-attaches the
    /// protocol's kernel; the loader refuses a `.bin` whose kernel is anything
    /// but `V1COMPAT_ELF`. The staged `.bin` must pass that check as-is.
    #[test]
    fn staged_bins_carry_the_canonical_kernel() {
        let name = "rln_registration";
        let path = crate::state_tests::fixtures::guest_binary_dir().join(format!("{name}.bin"));
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        let segments = crate::rln::client::deploy_segment_count(&bytes)
            .unwrap_or_else(|e| panic!("{name}.bin is not deployable: {e}"));
        println!(
            "{name}.bin: {} B, {segments} deploy segment(s)",
            bytes.len()
        );
    }
}
