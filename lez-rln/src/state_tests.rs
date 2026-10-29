//! State-level tests for the RLN registration program.
//!
//! Every test drives the real guest `.bin` through `V03State`, the same state
//! machine the sequencer runs, so a transaction here plans and applies exactly
//! as it would on chain, and emits the events it would emit there.
//!
//! The program sits at a fixed header account (`REG_ID`), seeded with
//! `V03State::with_named_programs` the way a deployer's `CreateHeader` would
//! place it; every PDA hangs off `REG_ID`. Instruction claims (clock
//! timestamp, config price and durations, membership rate limit and expiry)
//! are read from the state just before a transaction is built, as the host
//! client does, and the wrong-claim tests below mutate one claim at a time.
//!
//! There is no on-chain tree. Each test setup keeps the events its successful
//! transactions emitted, in order, and the tree tests rebuild the membership
//! set from them with `crate::zone`, as a Zone reader would.
//!
//! Run (the suite is feature-gated; see `lez-rln/CLAUDE.md`):
//! ```bash
//! RISC0_DEV_MODE=1 cargo test --release --features rc5-state-tests
//! ```
//!
//! TODO(v0.3.0 privacy port): the `rc5-state-tests-privacy` tests
//! (`register_from_a_private_payer`, `tokens_survive_a_shield_transfer_deshield_round_trip`)
//! were written against the rc6 account model (`AccountWithMetadata`,
//! `balance` field, token program payment) and are not ported yet. They need
//! `ProvingInput { shard_selectors, .. }`, the new `PrivateWitness` shape and
//! a private payer whose native shard is paid through the chained native
//! transfer. A private transaction carries no events, so a privately paid
//! registration also needs a reader story. The feature still builds and runs
//! the public suite.

/// Fixtures shared by `state_tests` and `cycle_harness`.
pub(crate) mod fixtures {
    use std::{fs, path::PathBuf};

    use borsh::BorshSerialize;
    use nssa::{
        AccountId, PrivateKey, ProgramShardSelector, PublicKey, PublicTransaction, V03State,
        error::LeeError,
        program::Program,
        public_transaction::{Message, WitnessSet},
    };
    use nssa_core::account::Account;
    use rln_layouts::{ConfigState, Instruction, MembershipState};

    use crate::{
        rln::{
            CLOCK_50_ACCOUNT_ID_BYTES,
            client::{clock_selector, extended_expiry_ms},
            derive_config_account, derive_membership_account,
        },
        zone::{RlnEvent, decode_transaction_events},
    };

    // ── deployment ─────────────────────────────────────────────────────

    /// Header account of the registration program.
    pub const REG_ID: AccountId = AccountId::new([0xA1; 32]);

    /// Test tree ID (first 24 bytes carry data, last 8 zero).
    pub const TREE_ID: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    pub const PRICE_PER_UNIT: u128 = 10_000;
    pub const DEFAULT_MAX_TOTAL_RATE_LIMIT: u64 = 1_000_000;

    /// Non-zero so time-travel tests can reason about past and future.
    pub const GENESIS_TIMESTAMP_MS: u64 = 1_700_000_000_000;

    /// Compressed durations (1 h active, 10 min grace) for expiration tests.
    pub const DEFAULT_ACTIVE_DURATION_SEC: u32 = 3_600;
    pub const DEFAULT_GRACE_PERIOD_DURATION_SEC: u32 = 600;
    pub const ACTIVE_MS: u64 = rln_layouts::secs_to_millis(DEFAULT_ACTIVE_DURATION_SEC);
    pub const GRACE_MS: u64 = rln_layouts::secs_to_millis(DEFAULT_GRACE_PERIOD_DURATION_SEC);

    /// Covers a registration at the default rate limit plus a renewal, with
    /// room left over so a debit is observable.
    pub const DEFAULT_PAYER_BALANCE: u128 = 10_000_000;

    // ── guest binaries ─────────────────────────────────────────────────

    /// Directory holding the guest `.bin` under test: the `docker/` dir the
    /// deploy host reads, or `LEZ_RLN_GUEST_DIR` to test a fresh build without
    /// overwriting the artifacts `verify.sh` compares against.
    pub fn guest_binary_dir() -> PathBuf {
        match std::env::var_os("LEZ_RLN_GUEST_DIR") {
            Some(dir) => PathBuf::from(dir),
            None => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("methods/guest/target/riscv32im-risc0-zkvm-elf/docker"),
        }
    }

    pub fn load_program(name: &str) -> Option<Program> {
        let bytes = fs::read(guest_binary_dir().join(format!("{name}.bin"))).ok()?;
        Program::new(bytes.into()).ok()
    }

    pub fn load_registration() -> Option<Program> {
        load_program("rln_registration")
    }

    /// Fresh state with the program at its header account, `CLOCK_50` at
    /// genesis time.
    pub fn state_with_program() -> Option<V03State> {
        let registration = load_registration()?;
        let mut state = V03State::new().with_named_programs([(REG_ID, registration)]);
        set_clock_50(&mut state, GENESIS_TIMESTAMP_MS, 0);
        Some(state)
    }

    /// Overwrite `CLOCK_50`'s clock shard. The sequencer refreshes it only
    /// every 50 blocks, so tests time-travel through the `test-utils` hatch.
    pub fn set_clock_50(state: &mut V03State, timestamp_ms: u64, block_id: u64) {
        let data = clock_core::ClockAccountData {
            block_id,
            timestamp: timestamp_ms,
        }
        .to_bytes();
        state.force_insert_account(
            AccountId::new(CLOCK_50_ACCOUNT_ID_BYTES),
            Account::default().with_shard(
                clock_core::clock_account_id(),
                data.try_into().expect("clock data fits"),
            ),
        );
    }

    // ── keys and balances ──────────────────────────────────────────────

    pub fn keypair(seed: u8) -> (PrivateKey, AccountId) {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        let key = PrivateKey::try_new(bytes).unwrap();
        let id = AccountId::from(&PublicKey::new_from_private_key(&key));
        (key, id)
    }

    /// A funded wallet account: a native shard and nothing else. No program
    /// can mint native balance, hence the escape hatch. Keeps the nonce.
    pub fn fund_native(state: &mut V03State, account_id: &AccountId, balance: u128) {
        let nonce = state.get_account_by_id(*account_id).nonce;
        state.force_insert_account(
            *account_id,
            Account {
                nonce,
                ..Account::funded(balance)
            },
        );
    }

    pub fn native_balance(state: &V03State, account_id: &AccountId) -> u128 {
        state
            .get_account_by_id(*account_id)
            .data
            .native_balance()
            .expect("native shard decodes")
    }

    // ── selectors ──────────────────────────────────────────────────────

    pub fn config_selector(tree_id: &[u8; 32]) -> ProgramShardSelector {
        ProgramShardSelector::new(derive_config_account(&REG_ID, tree_id), REG_ID)
    }

    pub fn membership_selector(
        tree_id: &[u8; 32],
        id_commitment: &[u8; 32],
    ) -> ProgramShardSelector {
        ProgramShardSelector::new(
            derive_membership_account(&REG_ID, tree_id, id_commitment),
            REG_ID,
        )
    }

    // ── readers ────────────────────────────────────────────────────────

    pub fn shard(state: &V03State, selector: ProgramShardSelector) -> Vec<u8> {
        state
            .get_account_by_id(selector.account_id)
            .data
            .shard(selector.program_account_id)
            .as_ref()
            .to_vec()
    }

    pub fn config_bytes(state: &V03State) -> Vec<u8> {
        shard(state, config_selector(&TREE_ID))
    }

    pub fn config(state: &V03State) -> ConfigState {
        borsh::from_slice(&config_bytes(state)).expect("config shard decodes")
    }

    pub fn membership(state: &V03State, id_commitment: &[u8; 32]) -> Option<MembershipState> {
        let bytes = shard(state, membership_selector(&TREE_ID, id_commitment));
        (!bytes.is_empty()).then(|| borsh::from_slice(&bytes).expect("membership shard decodes"))
    }

    pub fn clock_ms(state: &V03State) -> u64 {
        clock_core::ClockAccountData::from_bytes(&shard(state, clock_selector())).timestamp
    }

    // ── transactions ───────────────────────────────────────────────────

    /// A public transaction signed by `signers`, each at its current nonce.
    pub fn public_tx(
        state: &V03State,
        selectors: Vec<ProgramShardSelector>,
        instruction: impl BorshSerialize,
        program: AccountId,
        signers: &[&PrivateKey],
    ) -> PublicTransaction {
        let nonces = signers
            .iter()
            .map(|key| {
                let id = AccountId::from(&PublicKey::new_from_private_key(key));
                state.get_account_by_id(id).nonce
            })
            .collect();
        let message =
            Message::try_new(program, selectors, nonces, instruction).expect("valid message");
        let witness = WitnessSet::for_message(&message, signers);
        PublicTransaction::new(message, witness)
    }

    pub fn registration_tx(
        state: &V03State,
        selectors: Vec<ProgramShardSelector>,
        instruction: Instruction,
        signers: &[&PrivateKey],
    ) -> PublicTransaction {
        public_tx(state, selectors, instruction, REG_ID, signers)
    }

    /// Run `tx` against `state`; on success, the events the registration
    /// program emitted, decoded, in emission order.
    pub fn apply_to(
        state: &mut V03State,
        tx: &PublicTransaction,
    ) -> Result<Vec<RlnEvent>, LeeError> {
        let events = state.transition_from_public_transaction(tx, 1, 0)?;
        Ok(decode_transaction_events(&REG_ID, &events)
            .expect("the program emits only events a reader decodes"))
    }

    pub fn init_config_tx(
        state: &V03State,
        treasury_id: &AccountId,
        max_total_rate_limit: u64,
        active_duration_sec: u32,
        grace_period_duration_sec: u32,
    ) -> PublicTransaction {
        registration_tx(
            state,
            vec![config_selector(&TREE_ID)],
            Instruction::Initialize {
                tree_id: TREE_ID,
                price_per_unit: PRICE_PER_UNIT,
                treasury_account_id: *treasury_id.value(),
                max_total_rate_limit,
                active_duration_for_new_memberships_sec: active_duration_sec,
                grace_period_duration_for_new_memberships_sec: grace_period_duration_sec,
            },
            &[],
        )
    }

    pub struct TestSetup {
        pub state: V03State,
        /// Where the price is credited. Deliberately never seeded: a native
        /// credit lands on an account that has never been written to, which
        /// is what `run_setup` relies on in a real deployment.
        pub treasury_id: AccountId,
        /// Signs register/extend and pays the price from its native shard.
        pub payer_id: AccountId,
        pub payer_key: PrivateKey,
        /// Every event a transaction applied through [`TestSetup::apply`]
        /// emitted, in order: what a reader of this chain would see.
        pub events: Vec<RlnEvent>,
    }

    impl TestSetup {
        /// Run `tx`; on success record and return the events it emitted.
        pub fn apply(&mut self, tx: &PublicTransaction) -> Result<Vec<RlnEvent>, LeeError> {
            let events = apply_to(&mut self.state, tx)?;
            self.events.extend(events.iter().cloned());
            Ok(events)
        }
    }

    /// Program deployed, payer funded, config written.
    pub fn setup_with(
        max_total_rate_limit: u64,
        active_duration_sec: u32,
        grace_period_duration_sec: u32,
    ) -> Option<TestSetup> {
        let mut state = state_with_program()?;
        let (_, treasury_id) = keypair(1);
        let (payer_key, payer_id) = keypair(2);
        fund_native(&mut state, &payer_id, DEFAULT_PAYER_BALANCE);
        let tx = init_config_tx(
            &state,
            &treasury_id,
            max_total_rate_limit,
            active_duration_sec,
            grace_period_duration_sec,
        );
        let events = apply_to(&mut state, &tx).expect("Initialize should succeed");
        assert!(events.is_empty(), "Initialize emits no event");
        Some(TestSetup {
            state,
            treasury_id,
            payer_id,
            payer_key,
            events: Vec::new(),
        })
    }

    pub fn setup() -> Option<TestSetup> {
        setup_with(
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            DEFAULT_ACTIVE_DURATION_SEC,
            DEFAULT_GRACE_PERIOD_DURATION_SEC,
        )
    }

    /// `Register` with every claim read from `state`, as the host client does.
    pub fn register_ix(state: &V03State, id_commitment: [u8; 32], rate_limit: u64) -> Instruction {
        let config = config(state);
        Instruction::Register {
            tree_id: TREE_ID,
            id_commitment,
            rate_limit,
            now_ms: clock_ms(state),
            price_per_unit: config.price_per_unit,
            active_duration_sec: config.active_duration_for_new_memberships_sec,
            grace_period_duration_sec: config.grace_period_duration_for_new_memberships_sec,
            leaf_index: config.next_leaf_index,
        }
    }

    /// A `Register` transaction paying `treasury`; accounts follow the claims.
    pub fn register_tx_to(
        state: &V03State,
        payer_key: &PrivateKey,
        payer_id: &AccountId,
        treasury: &AccountId,
        ix: Instruction,
    ) -> PublicTransaction {
        let Instruction::Register {
            tree_id,
            id_commitment,
            ..
        } = ix
        else {
            panic!("not a Register instruction");
        };
        let selectors = vec![
            config_selector(&tree_id),
            ProgramShardSelector::native_balance(*payer_id),
            ProgramShardSelector::native_balance(*treasury),
            clock_selector(),
            membership_selector(&tree_id, &id_commitment),
        ];
        registration_tx(state, selectors, ix, &[payer_key])
    }

    pub fn register_tx(setup: &TestSetup, ix: Instruction) -> PublicTransaction {
        register_tx_to(
            &setup.state,
            &setup.payer_key,
            &setup.payer_id,
            &setup.treasury_id,
            ix,
        )
    }

    /// Register `id_commitment` with correct claims; panics on failure.
    pub fn register(setup: &mut TestSetup, id_commitment: [u8; 32], rate_limit: u64) {
        let tx = register_tx(setup, register_ix(&setup.state, id_commitment, rate_limit));
        setup.apply(&tx).expect("Register should succeed");
    }

    pub fn slash_ix(
        state: &V03State,
        identity_secret: [u8; 32],
        id_commitment: [u8; 32],
    ) -> Instruction {
        Instruction::Slash {
            tree_id: TREE_ID,
            id_commitment,
            identity_secret,
            rate_limit: membership(state, &id_commitment).map_or(0, |m| m.rate_limit),
        }
    }

    /// Slash needs no signer: the identity secret is the authorization.
    pub fn slash_tx(state: &V03State, ix: Instruction) -> PublicTransaction {
        let Instruction::Slash {
            tree_id,
            id_commitment,
            ..
        } = ix
        else {
            panic!("not a Slash instruction");
        };
        let selectors = vec![
            config_selector(&tree_id),
            membership_selector(&tree_id, &id_commitment),
        ];
        registration_tx(state, selectors, ix, &[])
    }

    /// `Extend` with every claim read from `state`, including the expiry the
    /// extension will produce.
    pub fn extend_ix(state: &V03State, id_commitment: [u8; 32]) -> Instruction {
        let membership = membership(state, &id_commitment);
        Instruction::Extend {
            tree_id: TREE_ID,
            id_commitment,
            now_ms: clock_ms(state),
            price_per_unit: config(state).price_per_unit,
            rate_limit: membership.as_ref().map_or(0, |m| m.rate_limit),
            expiry_timestamp_ms: membership.as_ref().map_or(0, extended_expiry_ms),
        }
    }

    /// Renewal is paid, so `payer_key` signs and is debited.
    pub fn extend_tx(
        setup: &TestSetup,
        payer_key: &PrivateKey,
        ix: Instruction,
    ) -> PublicTransaction {
        let Instruction::Extend {
            tree_id,
            id_commitment,
            ..
        } = ix
        else {
            panic!("not an Extend instruction");
        };
        let payer_id = AccountId::from(&PublicKey::new_from_private_key(payer_key));
        let selectors = vec![
            config_selector(&tree_id),
            membership_selector(&tree_id, &id_commitment),
            ProgramShardSelector::native_balance(payer_id),
            ProgramShardSelector::native_balance(setup.treasury_id),
            clock_selector(),
        ];
        registration_tx(&setup.state, selectors, ix, &[payer_key])
    }

    pub fn erase_ix(state: &V03State, id_commitment: [u8; 32]) -> Instruction {
        Instruction::Erase {
            tree_id: TREE_ID,
            id_commitment,
            rate_limit: membership(state, &id_commitment).map_or(0, |m| m.rate_limit),
            now_ms: clock_ms(state),
        }
    }

    pub fn erase_tx(state: &V03State, ix: Instruction) -> PublicTransaction {
        let Instruction::Erase {
            tree_id,
            id_commitment,
            ..
        } = ix
        else {
            panic!("not an Erase instruction");
        };
        let selectors = vec![
            config_selector(&tree_id),
            membership_selector(&tree_id, &id_commitment),
            clock_selector(),
        ];
        registration_tx(state, selectors, ix, &[])
    }
}

#[cfg(test)]
mod tests {
    use nssa::{AccountId, ProgramShardSelector, PublicTransaction, V03State, error::LeeError};
    use rand_chacha::ChaCha20Rng;
    use rln::prelude::{Fr, Hasher, IdentityKeys, PoseidonHash, RLNWitnessInput, hash_to_field_le};
    use rln_layouts::{
        CLOCK_CLAIM_TOLERANCE_MS, Instruction,
        events::{Erased, Extended, Registered, Slashed},
        exit::{EXIT_STALE_CLOCK, EXIT_STALE_EXPIRY, EXIT_STALE_LEAF_INDEX, exit_code_name},
    };

    use super::fixtures::*;
    use crate::{
        fr_bytes::{bytes_le_to_fr, fr_to_bytes_le},
        proof_circuit::CIRCUIT_DEPTH,
        rln::{
            CONFIG_OFFSET_ACTIVE_DURATION, CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT,
            CONFIG_OFFSET_GRACE_PERIOD_DURATION, CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT,
            CONFIG_OFFSET_PRICE_PER_UNIT, CONFIG_OFFSET_TOTAL_REGISTRATIONS,
            CONFIG_OFFSET_TREASURY_ACCOUNT_ID, CONFIG_OFFSET_TREE_ID, CONFIG_SIZE, MEMBERSHIP_SIZE,
            client::{clock_selector, membership_expiry_ms, registration_leaf},
            derive_config_account, derive_membership_account,
        },
        zone::{Change, MembershipSet, MerkleProof, RlnEvent, for_registry, proof_to_circuit},
    };

    /// `fee_core::market::MAX_GAS_EXEC`: one gas per cycle, summed over every
    /// plan and apply session of a transaction.
    const MAX_GAS_EXEC: u64 = 10_000_000;

    /// Cycles a whole transaction costs against `state`, all sessions summed.
    fn whole_tx_cycles(state: &V03State, tx: &PublicTransaction) -> u64 {
        let (_diff, charge) = nssa::ValidatedStateDiff::from_public_transaction_with_cycle_budget(
            tx,
            state,
            1,
            0,
            MAX_GAS_EXEC,
        )
        .expect("the transaction should execute within the ceiling");
        charge.cycles
    }

    /// A valid BN254 field element with `seed` in the lowest byte.
    fn valid_field_element(seed: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = seed;
        out
    }

    /// `(identity_secret, id_commitment)` with the commitment derived the way
    /// the slash path checks it: `id_commitment = Poseidon(identity_secret)`.
    fn slashable_identity(seed: u8) -> ([u8; 32], [u8; 32]) {
        let secret = valid_field_element(seed);
        let secret_fr = bytes_le_to_fr(&secret).expect("valid secret");
        (
            secret,
            fr_to_bytes_le(&Hasher::<PoseidonHash>::hash_single(secret_fr)),
        )
    }

    fn setup_or_skip() -> TestSetup {
        setup().expect(
            "guest .bin must be built and staged in methods/guest/target/riscv32im-risc0-zkvm-elf/docker/",
        )
    }

    /// `result` is a guest halting with exit `code`.
    fn assert_exit<T: std::fmt::Debug>(result: Result<T, LeeError>, code: u8, what: &str) {
        match result {
            Err(LeeError::ProgramExitedWithCode { code: got, .. }) => assert_eq!(
                got,
                u32::from(code),
                "{what}: exit {got} ({:?}), expected {:?}",
                exit_code_name(got),
                exit_code_name(u32::from(code))
            ),
            other => panic!("{what}: expected exit {code}, got {other:?}"),
        }
    }

    /// Replace one field of an instruction, keeping every other claim.
    macro_rules! with_claim {
        ($ix:expr, $variant:ident { $field:ident : $value:expr }) => {{
            let mut ix = $ix;
            match &mut ix {
                Instruction::$variant { $field, .. } => *$field = $value,
                _ => panic!(concat!("not a ", stringify!($variant), " instruction")),
            }
            ix
        }};
    }

    /// The membership set a reader of this chain derives from its events.
    fn reader(setup: &TestSetup) -> MembershipSet {
        MembershipSet::from_events(CIRCUIT_DEPTH, for_registry(&TREE_ID, &setup.events))
            .expect("the chain's events apply cleanly")
    }

    fn rate_commitment_fr(id_commitment: &[u8; 32], rate_limit: u64) -> Fr {
        bytes_le_to_fr(&registration_leaf(id_commitment, rate_limit)).expect("valid leaf")
    }

    /// The root of a depth-`CIRCUIT_DEPTH` tree holding `leaves` from index
    /// 0, computed densely and independently of `MembershipSet`.
    fn dense_root(leaves: &[Fr]) -> [u8; 32] {
        let mut level: Vec<Fr> = (0..1usize << CIRCUIT_DEPTH)
            .map(|i| leaves.get(i).copied().unwrap_or(Fr::from(0u64)))
            .collect();
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| Hasher::<PoseidonHash>::hash_pair(pair[0], pair[1]))
                .collect();
        }
        fr_to_bytes_le(&level[0])
    }

    // ====================================================================
    // Program loading and PDAs
    // ====================================================================

    #[test]
    fn test_rln_registration_program_loads() {
        assert!(
            load_registration().is_some(),
            "registration .bin must be built and staged in {:?}",
            guest_binary_dir()
        );
    }

    #[test]
    fn test_registration_pdas_are_distinct() {
        let config = derive_config_account(&REG_ID, &TREE_ID);
        let membership = derive_membership_account(&REG_ID, &TREE_ID, &valid_field_element(0x42));
        assert_ne!(config, membership);
        for id in [config, membership] {
            assert_ne!(id, REG_ID);
        }
    }

    // ====================================================================
    // Initialization
    // ====================================================================

    #[test]
    fn test_registration_init_creates_config() {
        let setup = setup_or_skip();
        let data = config_bytes(&setup.state);

        // Exact length first: ConfigState carries no version discriminator,
        // so its size is what tells this layout from any older one, and every
        // offset below is meaningless unless it holds.
        assert_eq!(
            data.len(),
            CONFIG_SIZE,
            "config shard must be exactly CONFIG_SIZE bytes"
        );

        let u64_at = |off: usize| u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let u32_at = |off: usize| u32::from_le_bytes(data[off..off + 4].try_into().unwrap());

        assert_eq!(
            &data[CONFIG_OFFSET_TREE_ID..CONFIG_OFFSET_TREE_ID + 32],
            &TREE_ID
        );
        assert_eq!(
            u128::from_le_bytes(
                data[CONFIG_OFFSET_PRICE_PER_UNIT..CONFIG_OFFSET_PRICE_PER_UNIT + 16]
                    .try_into()
                    .unwrap()
            ),
            PRICE_PER_UNIT
        );
        assert_eq!(
            &data[CONFIG_OFFSET_TREASURY_ACCOUNT_ID..CONFIG_OFFSET_TREASURY_ACCOUNT_ID + 32],
            setup.treasury_id.value()
        );
        assert_eq!(u64_at(CONFIG_OFFSET_TOTAL_REGISTRATIONS), 0);
        assert_eq!(
            u64_at(CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT),
            DEFAULT_MAX_TOTAL_RATE_LIMIT
        );
        assert_eq!(u64_at(CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT), 0);
        assert_eq!(
            u32_at(CONFIG_OFFSET_ACTIVE_DURATION),
            DEFAULT_ACTIVE_DURATION_SEC
        );
        assert_eq!(
            u32_at(CONFIG_OFFSET_GRACE_PERIOD_DURATION),
            DEFAULT_GRACE_PERIOD_DURATION_SEC
        );
    }

    #[test]
    fn test_registration_init_prevents_reinit() {
        let mut setup = setup_or_skip();
        let config_before = config_bytes(&setup.state);

        let (_, other_treasury) = keypair(9);
        let reinit = init_config_tx(
            &setup.state,
            &other_treasury,
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            DEFAULT_ACTIVE_DURATION_SEC,
            DEFAULT_GRACE_PERIOD_DURATION_SEC,
        );
        assert!(
            setup.apply(&reinit).is_err(),
            "Initialize must refuse a config shard that already holds data"
        );
        assert_eq!(config_bytes(&setup.state), config_before);
    }

    // ====================================================================
    // Register
    // ====================================================================

    /// A register emits exactly one event, from this program, carrying the
    /// commitment, the rate limit, the expiry the membership now has and the
    /// leaf index the config assigned.
    #[test]
    fn test_register_emits_registered() {
        let mut setup = setup_or_skip();
        let idc = valid_field_element(0x42);
        let tx = register_tx(&setup, register_ix(&setup.state, idc, 300));
        let raw = setup
            .state
            .transition_from_public_transaction(&tx, 1, 0)
            .expect("Register should succeed");

        let ours: Vec<_> = raw.iter().filter(|e| e.account_id == REG_ID).collect();
        assert_eq!(ours.len(), 1, "exactly one registration-program event");
        assert_eq!(ours[0].event.selector, Registered::SELECTOR);
        let event = Registered::from_bytes(&ours[0].event.data).expect("Registered decodes");
        let m = membership(&setup.state, &idc).expect("membership");
        assert_eq!(
            event,
            Registered {
                tree_id: TREE_ID,
                id_commitment: idc,
                rate_limit: 300,
                expiry_timestamp_ms: GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS,
                leaf_index: 0,
            }
        );
        assert_eq!(config(&setup.state).next_leaf_index, 1);
        assert_eq!(event.expiry_timestamp_ms, membership_expiry_ms(&m));
    }

    #[test]
    fn test_register_increments_total_registrations() {
        let mut setup = setup_or_skip();
        assert_eq!(config(&setup.state).total_registrations, 0);
        register(&mut setup, valid_field_element(0x42), 300);
        assert_eq!(config(&setup.state).total_registrations, 1);
    }

    #[test]
    fn test_register_creates_membership_pda() {
        let mut setup = setup_or_skip();
        let id_commitment = valid_field_element(0x42);
        register(&mut setup, id_commitment, 300);

        assert_eq!(
            shard(&setup.state, membership_selector(&TREE_ID, &id_commitment)).len(),
            MEMBERSHIP_SIZE
        );
        let m = membership(&setup.state, &id_commitment).expect("membership shard exists");
        assert_eq!(m.rate_limit, 300);
        assert_eq!(m.id_commitment, id_commitment);
        assert_eq!(
            m.grace_period_start_timestamp_ms,
            GENESIS_TIMESTAMP_MS + ACTIVE_MS
        );
        assert_eq!(m.active_duration_sec, DEFAULT_ACTIVE_DURATION_SEC);
        assert_eq!(
            m.grace_period_duration_sec,
            DEFAULT_GRACE_PERIOD_DURATION_SEC
        );
    }

    /// The membership init guard is the ONLY duplicate check: the register
    /// plan does not dedupe, and a reader would otherwise see two
    /// `Registered` events for one commitment.
    #[test]
    fn test_register_same_commitment_twice_fails() {
        let mut setup = setup_or_skip();
        let id_commitment = valid_field_element(0x42);
        register(&mut setup, id_commitment, 300);

        let payer_before = native_balance(&setup.state, &setup.payer_id);
        let tx = register_tx(&setup, register_ix(&setup.state, id_commitment, 300));
        assert!(
            setup.apply(&tx).is_err(),
            "a second registration of the same id_commitment must fail"
        );
        assert_eq!(setup.events.len(), 1, "no second Registered");
        assert_eq!(native_balance(&setup.state, &setup.payer_id), payer_before);
        assert_eq!(config(&setup.state).total_registrations, 1);
    }

    /// Readers hash the commitment into a Poseidon leaf, so the program must
    /// refuse one that is not a BN254 field element, though it never
    /// hashes it itself.
    #[test]
    fn register_rejects_a_commitment_outside_the_field() {
        let mut setup = setup_or_skip();
        let ix = register_ix(&setup.state, [0xFF; 32], 300);
        assert_register_refused(&mut setup, ix, "a commitment past the BN254 modulus");
    }

    // ── wrong claims ────────────────────────────────────────────────────
    //
    // Plan sees no account data, so each of these values is a claim that an
    // apply asserts against the stored bytes. Every one must fail the whole
    // transaction, emit no event, and leave no trace.

    fn assert_register_refused(setup: &mut TestSetup, ix: Instruction, what: &str) {
        let Instruction::Register { id_commitment, .. } = ix else {
            unreachable!()
        };
        let payer_before = native_balance(&setup.state, &setup.payer_id);
        let config_before = config_bytes(&setup.state);
        let events_before = setup.events.len();

        let tx = register_tx(setup, ix);
        let result = setup.apply(&tx);
        assert!(
            result.is_err(),
            "register with {what} must fail, got {result:?}"
        );

        assert!(
            membership(&setup.state, &id_commitment).is_none(),
            "{what}: no membership"
        );
        assert_eq!(setup.events.len(), events_before, "{what}: no event");
        assert_eq!(
            config_bytes(&setup.state),
            config_before,
            "{what}: config untouched"
        );
        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            payer_before,
            "{what}: payer not charged"
        );
    }

    /// Two registrations built from the SAME pre-state — as two clients
    /// reading the chain at the same height would build them — claim the same
    /// leaf index. The first takes it; the second exits
    /// `EXIT_STALE_LEAF_INDEX`, charged only its cycles, and leaves nothing
    /// behind. Rebuilt from the new state, it lands at the next index.
    #[test]
    fn same_state_registrations_contend_for_the_leaf_index() {
        let mut setup = setup_or_skip();
        let (key_b, payer_b) = keypair(3);
        fund_native(&mut setup.state, &payer_b, DEFAULT_PAYER_BALANCE);
        let (idc_a, idc_b) = (valid_field_element(0x0A), valid_field_element(0x0B));

        let snapshot = &setup.state;
        let tx_a = register_tx(&setup, register_ix(snapshot, idc_a, 100));
        let tx_b = register_tx_to(
            snapshot,
            &key_b,
            &payer_b,
            &setup.treasury_id,
            register_ix(snapshot, idc_b, 200),
        );

        setup.apply(&tx_a).expect("first registration of the block");
        let config_before = config_bytes(&setup.state);
        let payer_b_before = native_balance(&setup.state, &payer_b);
        assert_exit(
            setup.apply(&tx_b),
            EXIT_STALE_LEAF_INDEX,
            "a registration whose leaf index was taken",
        );
        assert!(membership(&setup.state, &idc_b).is_none());
        assert_eq!(setup.events.len(), 1, "no Registered for the refused one");
        assert_eq!(config_bytes(&setup.state), config_before);
        assert_eq!(native_balance(&setup.state, &payer_b), payer_b_before);

        let retry = register_tx_to(
            &setup.state,
            &key_b,
            &payer_b,
            &setup.treasury_id,
            register_ix(&setup.state, idc_b, 200),
        );
        let events = setup.apply(&retry).expect("rebuilt from the new state");
        assert!(matches!(
            events.as_slice(),
            [RlnEvent::Registered(Registered { leaf_index: 1, .. })]
        ));

        let set = reader(&setup);
        assert_eq!(set.next_index(), 2);
        assert_eq!(set.leaf_index_of(&idc_a), Some(0));
        assert_eq!(set.leaf_index_of(&idc_b), Some(1));
        assert_eq!(
            set.root(),
            dense_root(&[
                rate_commitment_fr(&idc_a, 100),
                rate_commitment_fr(&idc_b, 200)
            ])
        );
        let config = config(&setup.state);
        assert_eq!(config.total_registrations, 2);
        assert_eq!(config.current_total_rate_limit, 300);
        assert_eq!(config.next_leaf_index, 2);
    }

    /// A slash or erase uncounts the member but never rewinds
    /// `next_leaf_index`, so a re-registration takes a fresh leaf.
    #[test]
    fn leaf_indices_are_never_reused() {
        let mut setup = setup_or_skip();
        let (secret, idc) = registered_slashable(&mut setup, 0x31);
        slash(&mut setup, secret, idc).expect("slash");
        assert_eq!(config(&setup.state).total_registrations, 0);
        assert_eq!(config(&setup.state).next_leaf_index, 1);
        register(&mut setup, idc, 100);
        assert!(matches!(
            setup.events.last(),
            Some(RlnEvent::Registered(Registered { leaf_index: 1, .. }))
        ));
    }

    /// One program, two registries: every event names its `tree_id`, and a
    /// reader of one registry never sees the other's members.
    #[test]
    fn registries_sharing_a_program_keep_separate_trees() {
        let mut setup = setup_or_skip();
        let other_tree = [0x99u8; 32];
        let config = config(&setup.state);
        let init_other = registration_tx(
            &setup.state,
            vec![config_selector(&other_tree)],
            Instruction::Initialize {
                tree_id: other_tree,
                price_per_unit: config.price_per_unit,
                treasury_account_id: config.treasury_account_id,
                max_total_rate_limit: config.max_total_rate_limit,
                active_duration_for_new_memberships_sec: config
                    .active_duration_for_new_memberships_sec,
                grace_period_duration_for_new_memberships_sec: config
                    .grace_period_duration_for_new_memberships_sec,
            },
            &[],
        );
        setup.apply(&init_other).expect("a second registry");

        let (idc_a, idc_b) = (valid_field_element(0x0A), valid_field_element(0x0B));
        register(&mut setup, idc_a, 100);
        // The second registry counts its own leaves from 0.
        let ix = with_claim!(
            with_claim!(
                register_ix(&setup.state, idc_b, 200),
                Register {
                    tree_id: other_tree
                }
            ),
            Register { leaf_index: 0 }
        );
        let tx = register_tx(&setup, ix);
        let events = setup.apply(&tx).expect("register in the second registry");
        assert_eq!(events[0].tree_id(), other_tree);

        let ours = reader(&setup);
        assert_eq!(ours.next_index(), 1);
        assert_eq!(ours.leaf_index_of(&idc_a), Some(0));
        assert_eq!(ours.leaf_index_of(&idc_b), None);
        let theirs =
            MembershipSet::from_events(CIRCUIT_DEPTH, for_registry(&other_tree, &setup.events))
                .expect("applies");
        assert_eq!(theirs.leaf_index_of(&idc_b), Some(0));
        assert_eq!(theirs.leaf_index_of(&idc_a), None);
    }

    #[test]
    fn register_rejects_a_wrong_price_claim() {
        let mut setup = setup_or_skip();
        let ix = register_ix(&setup.state, valid_field_element(0x42), 300);
        assert_register_refused(
            &mut setup,
            with_claim!(
                ix.clone(),
                Register {
                    price_per_unit: PRICE_PER_UNIT - 1
                }
            ),
            "an under-priced claim",
        );
        assert_register_refused(
            &mut setup,
            with_claim!(ix, Register { price_per_unit: 0 }),
            "a zero price claim",
        );
    }

    #[test]
    fn register_rejects_a_wrong_now_ms_claim() {
        let mut setup = setup_or_skip();
        let ix = register_ix(&setup.state, valid_field_element(0x42), 300);
        // A future clock would extend the membership for free; a claim older
        // than the tolerance is a stale read. Both are refused.
        assert_register_refused(
            &mut setup,
            with_claim!(
                ix.clone(),
                Register {
                    now_ms: GENESIS_TIMESTAMP_MS + ACTIVE_MS
                }
            ),
            "a future now_ms",
        );
        assert_register_refused(
            &mut setup,
            with_claim!(
                ix,
                Register {
                    now_ms: GENESIS_TIMESTAMP_MS - CLOCK_CLAIM_TOLERANCE_MS - 1
                }
            ),
            "a now_ms older than the tolerance",
        );
    }

    /// `CLOCK_50` steps once per 50 blocks; a register read just before a
    /// step and included just after it carries a claim one step behind. That
    /// is accepted, and the membership — and its `Registered` expiry — is
    /// dated by the claim: earlier than the chain's time, which only shortens
    /// the member's own window.
    #[test]
    fn a_clock_claim_slightly_behind_the_clock_is_accepted() {
        let mut setup = setup_or_skip();
        let idc = valid_field_element(0x42);
        let ix = register_ix(&setup.state, idc, 300);
        let read_at = clock_ms(&setup.state);
        set_clock_50(&mut setup.state, read_at + 750_000, 100);

        let tx = register_tx(&setup, ix);
        let events = setup
            .apply(&tx)
            .expect("a claim one clock step behind is accepted");
        assert_eq!(
            membership(&setup.state, &idc)
                .unwrap()
                .grace_period_start_timestamp_ms,
            read_at + ACTIVE_MS,
            "dated by the claim, not by the clock"
        );
        assert!(matches!(
            events.as_slice(),
            [RlnEvent::Registered(Registered { expiry_timestamp_ms, .. })]
                if *expiry_timestamp_ms == read_at + ACTIVE_MS + GRACE_MS
        ));

        // The tolerance itself is inclusive.
        let idc = valid_field_element(0x43);
        let ix = with_claim!(
            register_ix(&setup.state, idc, 300),
            Register {
                now_ms: clock_ms(&setup.state) - CLOCK_CLAIM_TOLERANCE_MS
            }
        );
        let tx = register_tx(&setup, ix);
        setup
            .apply(&tx)
            .expect("a claim exactly the tolerance behind is accepted");
    }

    /// A claim ahead of the clock, or further behind it than the tolerance,
    /// exits `EXIT_STALE_CLOCK` and leaves nothing behind.
    #[test]
    fn a_clock_claim_ahead_or_older_than_the_tolerance_is_refused() {
        let mut setup = setup_or_skip();
        let idc = valid_field_element(0x42);
        let now = clock_ms(&setup.state);
        for (what, claim) in [
            ("1 ms ahead", now + 1),
            (
                "1 ms past the tolerance",
                now - CLOCK_CLAIM_TOLERANCE_MS - 1,
            ),
        ] {
            let ix = with_claim!(
                register_ix(&setup.state, idc, 300),
                Register { now_ms: claim }
            );
            let tx = register_tx(&setup, ix);
            assert_exit(setup.apply(&tx), EXIT_STALE_CLOCK, what);
            assert!(membership(&setup.state, &idc).is_none(), "{what}");
            assert_eq!(config(&setup.state).total_registrations, 0, "{what}");
            assert!(setup.events.is_empty(), "{what}: no event");
        }
    }

    #[test]
    fn register_rejects_wrong_duration_claims() {
        let mut setup = setup_or_skip();
        let ix = register_ix(&setup.state, valid_field_element(0x42), 300);
        assert_register_refused(
            &mut setup,
            with_claim!(
                ix.clone(),
                Register {
                    active_duration_sec: DEFAULT_ACTIVE_DURATION_SEC * 10
                }
            ),
            "an inflated active duration",
        );
        assert_register_refused(
            &mut setup,
            with_claim!(
                ix,
                Register {
                    grace_period_duration_sec: DEFAULT_GRACE_PERIOD_DURATION_SEC * 10
                }
            ),
            "an inflated grace duration",
        );
    }

    // ====================================================================
    // Slash
    // ====================================================================

    fn registered_slashable(setup: &mut TestSetup, seed: u8) -> ([u8; 32], [u8; 32]) {
        let (secret, idc) = slashable_identity(seed);
        register(setup, idc, 300);
        assert!(membership(&setup.state, &idc).is_some());
        (secret, idc)
    }

    fn slash(
        setup: &mut TestSetup,
        secret: [u8; 32],
        idc: [u8; 32],
    ) -> Result<Vec<RlnEvent>, LeeError> {
        let tx = slash_tx(&setup.state, slash_ix(&setup.state, secret, idc));
        setup.apply(&tx)
    }

    #[test]
    fn test_slash_clears_the_membership_and_emits_slashed() {
        let mut setup = setup_or_skip();
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        let events = slash(&mut setup, secret, idc).expect("slash");
        assert_eq!(
            events,
            vec![RlnEvent::Slashed(Slashed {
                tree_id: TREE_ID,
                id_commitment: idc,
            })]
        );
        assert!(
            shard(&setup.state, membership_selector(&TREE_ID, &idc)).is_empty(),
            "the membership shard is cleared"
        );
    }

    #[test]
    fn test_slash_decrements_total_registrations() {
        let mut setup = setup_or_skip();
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        assert_eq!(config(&setup.state).total_registrations, 1);
        slash(&mut setup, secret, idc).expect("slash");
        assert_eq!(config(&setup.state).total_registrations, 0);
    }

    /// A reader removes a slashed member's leaf, and the root returns to what
    /// it was without them.
    #[test]
    fn test_slash_removes_the_leaf_for_a_reader() {
        let mut setup = setup_or_skip();
        let empty_root = reader(&setup).root();
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        assert_ne!(reader(&setup).root(), empty_root);
        slash(&mut setup, secret, idc).expect("slash");
        let set = reader(&setup);
        assert_eq!(set.root(), empty_root, "removing the only leaf");
        assert_eq!(set.next_index(), 1, "indices are never reused");
    }

    #[test]
    fn test_slash_invalid_secret_fails() {
        let mut setup = setup_or_skip();
        let (_, idc) = registered_slashable(&mut setup, 0x42);
        let (wrong_secret, _) = slashable_identity(0x99);
        assert!(slash(&mut setup, wrong_secret, idc).is_err());
        assert!(membership(&setup.state, &idc).is_some());
        assert_eq!(setup.events.len(), 1, "no Slashed");
    }

    #[test]
    fn test_slash_double_slash_fails() {
        let mut setup = setup_or_skip();
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        slash(&mut setup, secret, idc).expect("first slash");
        // Claims as a slasher would guess them (the membership is gone).
        let ix = Instruction::Slash {
            tree_id: TREE_ID,
            id_commitment: idc,
            identity_secret: secret,
            rate_limit: 300,
        };
        let tx = slash_tx(&setup.state, ix);
        assert!(setup.apply(&tx).is_err(), "double slash must fail");
        assert_eq!(setup.events.len(), 2, "one Registered, one Slashed");
    }

    /// The rate limit a slash releases is asserted against the membership.
    #[test]
    fn slash_rejects_a_wrong_rate_limit_claim() {
        let mut setup = setup_or_skip();
        register(&mut setup, valid_field_element(0x01), 100);
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        let ix = slash_ix(&setup.state, secret, idc);

        for claimed in [100, 600] {
            let tx = slash_tx(
                &setup.state,
                with_claim!(
                    ix.clone(),
                    Slash {
                        rate_limit: claimed
                    }
                ),
            );
            assert!(
                setup.apply(&tx).is_err(),
                "slash claiming rate limit {claimed} must fail"
            );
            assert!(membership(&setup.state, &idc).is_some(), "membership kept");
            assert_eq!(setup.events.len(), 2, "no Slashed");
        }
    }

    /// Slashing clears the membership shard, so the init guard no longer
    /// stands in the way: the commitment can register again, and a reader
    /// gives it a new leaf.
    #[test]
    fn a_slashed_commitment_can_register_again() {
        let mut setup = setup_or_skip();
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        slash(&mut setup, secret, idc).expect("slash");

        register(&mut setup, idc, 300);
        assert!(membership(&setup.state, &idc).is_some(), "re-registered");
        let set = reader(&setup);
        assert_eq!(
            set.leaf_index_of(&idc),
            Some(1),
            "the old leaf index is never reused"
        );
        assert_eq!(set.proof(0).leaf, [0; 32], "the old leaf stays zeroed");
        assert_eq!(
            set.root(),
            dense_root(&[Fr::from(0u64), rate_commitment_fr(&idc, 300)])
        );
        assert_eq!(config(&setup.state).total_registrations, 1);
    }

    // ====================================================================
    // Rate-limit accounting
    // ====================================================================

    #[test]
    fn test_total_rate_limit_cap_enforced() {
        let mut setup = setup_with(
            500,
            DEFAULT_ACTIVE_DURATION_SEC,
            DEFAULT_GRACE_PERIOD_DURATION_SEC,
        )
        .expect("setup");
        register(&mut setup, valid_field_element(0x01), 300);

        let tx = register_tx(
            &setup,
            register_ix(&setup.state, valid_field_element(0x02), 300),
        );
        assert!(
            setup.apply(&tx).is_err(),
            "a registration past max_total_rate_limit must fail"
        );
        assert_eq!(config(&setup.state).current_total_rate_limit, 300);
        assert_eq!(setup.events.len(), 1);
    }

    #[test]
    fn test_current_total_rate_limit_tracking() {
        let mut setup = setup_or_skip();
        assert_eq!(config(&setup.state).current_total_rate_limit, 0);
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        assert_eq!(config(&setup.state).current_total_rate_limit, 300);
        slash(&mut setup, secret, idc).expect("slash");
        assert_eq!(config(&setup.state).current_total_rate_limit, 0);
    }

    // ====================================================================
    // Native payment
    // ====================================================================
    //
    // The price moves through a chained call to the native token program,
    // which refuses an unauthorized sender and an insufficient balance. The
    // destination is the registry's to check, against the config's treasury.

    #[test]
    fn register_debits_payer_and_credits_treasury_natively() {
        let mut setup = setup_or_skip();
        let price = 300 * PRICE_PER_UNIT;
        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            DEFAULT_PAYER_BALANCE
        );
        assert_eq!(native_balance(&setup.state, &setup.treasury_id), 0);

        register(&mut setup, valid_field_element(0x42), 300);

        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            DEFAULT_PAYER_BALANCE - price
        );
        assert_eq!(native_balance(&setup.state, &setup.treasury_id), price);
    }

    /// SECURITY (payment routing): the treasury check in the config apply is
    /// the only thing deciding where the price lands.
    #[test]
    fn register_rejects_a_treasury_that_is_not_the_configured_one() {
        let mut setup = setup_or_skip();
        let (_, attacker_treasury) = keypair(9);
        assert_ne!(attacker_treasury, setup.treasury_id);

        let idc = valid_field_element(0x42);
        let tx = register_tx_to(
            &setup.state,
            &setup.payer_key,
            &setup.payer_id,
            &attacker_treasury,
            register_ix(&setup.state, idc, 300),
        );
        let result = setup.apply(&tx);
        assert!(
            result.is_err(),
            "an unconfigured treasury must be refused; got {result:?}"
        );
        assert_eq!(native_balance(&setup.state, &attacker_treasury), 0);
        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            DEFAULT_PAYER_BALANCE
        );
        assert!(membership(&setup.state, &idc).is_none());
        assert!(setup.events.is_empty());
    }

    /// An unsigned payer row: the payer is named but does not sign.
    #[test]
    fn register_rejects_an_unauthorized_payer() {
        let mut setup = setup_or_skip();
        let (other_key, other_id) = keypair(7);
        fund_native(&mut setup.state, &other_id, DEFAULT_PAYER_BALANCE);

        // `other` signs, but the payer row names `setup.payer`.
        let idc = valid_field_element(0x42);
        let tx = register_tx_to(
            &setup.state,
            &other_key,
            &setup.payer_id,
            &setup.treasury_id,
            register_ix(&setup.state, idc, 300),
        );
        assert!(
            setup.apply(&tx).is_err(),
            "a payer that did not sign must not be debited"
        );
        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            DEFAULT_PAYER_BALANCE
        );
        assert_eq!(
            native_balance(&setup.state, &other_id),
            DEFAULT_PAYER_BALANCE
        );
        assert!(membership(&setup.state, &idc).is_none());
    }

    /// One unit short of the price is refused — and emits nothing, though the
    /// registration plan already emitted its event before the transfer
    /// failed; exactly the price is accepted.
    #[test]
    fn register_rejects_an_underfunded_payer() {
        let mut setup = setup_or_skip();
        let price = 300 * PRICE_PER_UNIT;
        let payer_id = setup.payer_id;
        fund_native(&mut setup.state, &payer_id, price - 1);

        let idc = valid_field_element(0x42);
        let tx = register_tx(&setup, register_ix(&setup.state, idc, 300));
        assert!(setup.apply(&tx).is_err(), "one unit short must be refused");
        assert_eq!(native_balance(&setup.state, &payer_id), price - 1);
        assert!(membership(&setup.state, &idc).is_none());
        assert!(
            setup.events.is_empty(),
            "a reverted register emits no event"
        );

        fund_native(&mut setup.state, &payer_id, price);
        register(&mut setup, idc, 300);
        assert_eq!(
            native_balance(&setup.state, &payer_id),
            0,
            "exactly the price empties the payer"
        );
    }

    /// Across every account a register touches, native balance is moved,
    /// never minted or burnt.
    #[test]
    fn register_conserves_total_balance() {
        let mut setup = setup_or_skip();
        let idc = valid_field_element(0x42);
        let accounts: Vec<AccountId> = [
            config_selector(&TREE_ID),
            ProgramShardSelector::native_balance(setup.payer_id),
            ProgramShardSelector::native_balance(setup.treasury_id),
            clock_selector(),
            membership_selector(&TREE_ID, &idc),
        ]
        .iter()
        .map(|s| s.account_id)
        .collect();
        let total = |state: &V03State| -> u128 {
            accounts.iter().map(|id| native_balance(state, id)).sum()
        };

        let before = total(&setup.state);
        register(&mut setup, idc, 300);
        assert_eq!(total(&setup.state), before);
        assert!(
            native_balance(&setup.state, &setup.treasury_id) > 0,
            "the transfer happened"
        );
    }

    // ====================================================================
    // Gas
    // ====================================================================

    /// The error a transaction fails with, and what the sequencer charges for
    /// it under a `MAX_GAS_EXEC` declaration.
    fn failure_and_charge(state: &V03State, tx: &PublicTransaction) -> (LeeError, u64) {
        let err = nssa::ValidatedStateDiff::from_public_transaction_with_cycle_budget(
            tx,
            state,
            1,
            0,
            MAX_GAS_EXEC,
        )
        .err()
        .expect("the transaction should fail");
        let (charge, settled) = nssa::ValidatedStateDiff::from_public_transaction_metered(
            tx,
            state,
            1,
            0,
            MAX_GAS_EXEC,
        );
        assert!(
            settled.is_ok(),
            "a chargeable failure settles as nonce bumps, got {:?}",
            settled.err()
        );
        (err, charge.cycles)
    }

    /// A claim that went stale because the chain moved (here: the clock) halts
    /// the guest with an exit code, and is charged the cycles that ran — with
    /// no leaf Poseidon in the plan any more, a few small sessions — not the
    /// declared gas. A malformed transaction still panics and pays the full
    /// budget.
    #[test]
    fn a_stale_clock_claim_is_charged_measured_cycles() {
        let setup = setup_or_skip();
        let ix = register_ix(&setup.state, valid_field_element(0x42), 100);

        let stale = with_claim!(
            ix.clone(),
            Register {
                now_ms: clock_ms(&setup.state) + 1
            }
        );
        let (err, charged) = failure_and_charge(&setup.state, &register_tx(&setup, stale));
        println!(
            "stale clock claim: {err:?} ({}), charged {charged} cycles ({:.1}% of MAX_GAS_EXEC)",
            exit_code_name(u32::from(EXIT_STALE_CLOCK)).unwrap(),
            charged as f64 / MAX_GAS_EXEC as f64 * 100.0
        );
        assert!(
            matches!(err, LeeError::ProgramExitedWithCode { code, .. } if code == u32::from(EXIT_STALE_CLOCK)),
            "got {err:?}"
        );
        assert!(
            charged < 300_000,
            "a stale claim must not pay the ceiling: {charged}"
        );

        // A registry that does not exist: its config PDA is empty, and the
        // config apply panics decoding it.
        let malformed = with_claim!(
            ix,
            Register {
                tree_id: [0x99; 32]
            }
        );
        let (err, charged) = failure_and_charge(&setup.state, &register_tx(&setup, malformed));
        assert!(
            matches!(err, LeeError::ProgramExecutionFailed(_)),
            "got {err:?}"
        );
        assert_eq!(
            charged, MAX_GAS_EXEC,
            "a malformed transaction still pays the full budget"
        );
    }

    /// Every membership transaction — every plan and apply session — against
    /// the ceiling that rejects it (`fee_core::market::MAX_GAS_EXEC`, one gas
    /// per cycle). With no tree to update, the only Poseidon left is a
    /// slash's hash of the identity secret. Printed for the record.
    #[test]
    fn membership_transactions_fit_the_gas_ceiling() {
        let mut setup = setup_or_skip();
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS, 50);
        let (secret, idc) = slashable_identity(0x42);
        let register_cost = whole_tx_cycles(
            &setup.state,
            &register_tx(&setup, register_ix(&setup.state, idc, 100)),
        );
        register(&mut setup, idc, 100);

        let slash_cost = whole_tx_cycles(
            &setup.state,
            &slash_tx(&setup.state, slash_ix(&setup.state, secret, idc)),
        );
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1, 100);
        let extend_cost = whole_tx_cycles(
            &setup.state,
            &extend_tx(&setup, &setup.payer_key, extend_ix(&setup.state, idc)),
        );
        set_clock_50(
            &mut setup.state,
            GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1,
            150,
        );
        let erase_cost = whole_tx_cycles(
            &setup.state,
            &erase_tx(&setup.state, erase_ix(&setup.state, idc)),
        );
        for (what, used) in [
            ("register", register_cost),
            ("slash", slash_cost),
            ("extend", extend_cost),
            ("erase", erase_cost),
        ] {
            println!(
                "{what} transaction: {used} cycles ({:.1}% of MAX_GAS_EXEC)",
                used as f64 / MAX_GAS_EXEC as f64 * 100.0
            );
            assert!(used <= MAX_GAS_EXEC, "{what} costs {used} cycles");
        }
        assert!(
            register_cost < slash_cost,
            "a register hashes nothing; a slash hashes the identity secret"
        );
    }

    // ====================================================================
    // RLN proofs against the reader's tree
    // ====================================================================

    fn recompute_root(proof: &MerkleProof) -> [u8; 32] {
        let mut current = bytes_le_to_fr(&proof.leaf).expect("valid leaf");
        for (sibling, &right) in proof.path_elements.iter().zip(&proof.path_indices) {
            let sibling = bytes_le_to_fr(sibling).expect("valid sibling");
            current = if right == 0 {
                Hasher::<PoseidonHash>::hash_pair(current, sibling)
            } else {
                Hasher::<PoseidonHash>::hash_pair(sibling, current)
            };
        }
        fr_to_bytes_le(&current)
    }

    fn external_nullifier(epoch: &[u8]) -> Fr {
        Hasher::<PoseidonHash>::hash_pair(
            hash_to_field_le(epoch),
            hash_to_field_le(b"lssa-rln-test"),
        )
    }

    #[test]
    fn test_merkle_proof_from_the_reader() {
        let mut setup = setup_or_skip();
        let idc = valid_field_element(0x42);
        register(&mut setup, idc, 300);

        let proof = reader(&setup).proof(0);
        assert_eq!(proof.path_elements.len(), CIRCUIT_DEPTH);
        assert_eq!(proof.path_indices.len(), CIRCUIT_DEPTH);
        assert_eq!(proof.leaf, registration_leaf(&idc, 300));
        assert_eq!(
            recompute_root(&proof),
            proof.root,
            "the proof reproduces the reader's root"
        );
    }

    fn prove_and_verify(setup: &TestSetup, keys: &IdentityKeys, rate_limit: u64) {
        let set = reader(setup);
        let idc = fr_to_bytes_le(&keys.id_commitment());
        let proof = set.proof(set.leaf_index_of(&idc).expect("registered"));
        assert_eq!(proof.leaf, registration_leaf(&idc, rate_limit));
        let (merkle_proof, root) = proof_to_circuit(&proof);
        let x = hash_to_field_le(b"Hello, RLN!");
        let witness = RLNWitnessInput::new_single()
            .identity_secret(keys.identity_secret())
            .user_message_limit(Fr::from(rate_limit))
            .merkle_proof(merkle_proof)
            .x(x)
            .external_nullifier(external_nullifier(b"test-epoch"))
            .message_id(Fr::from(0u64))
            .build()
            .expect("witness");
        let rln = crate::proof_circuit::engine();
        let (rln_proof, values) = rln.generate_proof(&witness).expect("proof");
        assert_eq!(values.root(), root, "proof root is the reader's root");
        assert!(
            rln.verify_with_roots(&rln_proof, &values, &x, &[root])
                .expect("verify"),
            "RLN proof must verify against the reader's root"
        );
    }

    #[test]
    fn test_rln_proof_generation_and_verification() {
        let mut setup = setup_or_skip();
        let keys = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(&[0x42; 32]);
        register(&mut setup, fr_to_bytes_le(&keys.id_commitment()), 300);
        prove_and_verify(&setup, &keys, 300);
    }

    #[test]
    fn test_rln_proof_with_multiple_registrations() {
        let mut setup = setup_or_skip();
        let keys: Vec<IdentityKeys> = (1u8..=3)
            .map(|s| IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(&[s; 32]))
            .collect();
        for k in &keys {
            register(&mut setup, fr_to_bytes_le(&k.id_commitment()), 100);
        }
        prove_and_verify(&setup, &keys[1], 100);
    }

    #[test]
    fn test_rln_proof_invalid_after_slash() {
        let mut setup = setup_or_skip();
        let empty_root = reader(&setup).root();
        let (secret, idc) = registered_slashable(&mut setup, 0x42);
        let root_registered = reader(&setup).root();

        slash(&mut setup, secret, idc).expect("slash");

        let proof = reader(&setup).proof(0);
        assert_ne!(proof.root, root_registered, "the root moved");
        assert_ne!(proof.leaf, registration_leaf(&idc, 300), "the leaf is gone");
        assert_eq!(proof.root, empty_root, "back to the empty root");
    }

    #[test]
    fn test_rln_double_message_detection() {
        let mut setup = setup_or_skip();
        let keys = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(&[0x99; 32]);
        register(&mut setup, fr_to_bytes_le(&keys.id_commitment()), 300);

        let (merkle_proof, root) = proof_to_circuit(&reader(&setup).proof(0));
        let rln = crate::proof_circuit::engine();
        let prove = |msg: &[u8]| {
            let x = hash_to_field_le(msg);
            let witness = RLNWitnessInput::new_single()
                .identity_secret(keys.identity_secret())
                .user_message_limit(Fr::from(300u64))
                .merkle_proof(merkle_proof.clone())
                .x(x)
                .external_nullifier(external_nullifier(b"epoch-1"))
                .message_id(Fr::from(0u64))
                .build()
                .expect("witness");
            let (p, v) = rln.generate_proof(&witness).expect("proof");
            assert!(rln.verify_with_roots(&p, &v, &x, &[root]).expect("verify"));
            v
        };
        let v1 = prove(b"First message");
        let v2 = prove(b"Second message");
        // Same identity + epoch + message_id → same nullifier: the double
        // signal is detectable.
        assert_eq!(
            v1.nullifier().expect("single"),
            v2.nullifier().expect("single")
        );
    }

    /// The whole lifecycle through the chain, then through a reader: the
    /// changes it derives from the emitted events and the root it ends at
    /// match a tree built independently from what should be in it.
    #[test]
    fn a_reader_derives_the_lifecycle_from_the_chains_events() {
        let mut setup = setup_or_skip();
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS, 50);
        let (secret_a, idc_a) = slashable_identity(0x41);
        let idc_b = valid_field_element(0x0B);
        let idc_c = valid_field_element(0x0C);
        register(&mut setup, idc_a, 100);
        register(&mut setup, idc_b, 200);
        slash(&mut setup, secret_a, idc_a).expect("slash A");

        // B renews in its grace period; C registers later.
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1, 100);
        let tx = extend_tx(&setup, &setup.payer_key, extend_ix(&setup.state, idc_b));
        setup.apply(&tx).expect("extend B");
        register(&mut setup, idc_c, 300);

        let mut set = MembershipSet::new(CIRCUIT_DEPTH);
        let changes: Vec<Option<Change>> = setup
            .events
            .iter()
            .map(|e| set.apply(e).expect("applies"))
            .collect();
        assert_eq!(
            changes,
            vec![
                Some(Change::Insert {
                    leaf_index: 0,
                    rate_commitment: registration_leaf(&idc_a, 100)
                }),
                Some(Change::Insert {
                    leaf_index: 1,
                    rate_commitment: registration_leaf(&idc_b, 200)
                }),
                Some(Change::Remove { leaf_index: 0 }),
                None,
                Some(Change::Insert {
                    leaf_index: 2,
                    rate_commitment: registration_leaf(&idc_c, 300)
                }),
            ]
        );
        assert_eq!(
            set.root(),
            dense_root(&[
                Fr::from(0u64),
                rate_commitment_fr(&idc_b, 200),
                rate_commitment_fr(&idc_c, 300)
            ])
        );
        assert_eq!(
            set.member(&idc_b).unwrap().expiry_timestamp_ms,
            membership_expiry_ms(&membership(&setup.state, &idc_b).unwrap()),
            "the reader's expiry for B is the chain's"
        );

        // C's original expiry passes; B's extended one has not.
        let c_expiry = membership_expiry_ms(&membership(&setup.state, &idc_c).unwrap());
        let b_expiry = membership_expiry_ms(&membership(&setup.state, &idc_b).unwrap());
        assert!(c_expiry < b_expiry);
        assert_eq!(set.expire(c_expiry), vec![Change::Remove { leaf_index: 2 }]);
        assert_eq!(
            set.root(),
            dense_root(&[Fr::from(0u64), rate_commitment_fr(&idc_b, 200)])
        );

        // Erasing C on chain changes nothing more for the reader.
        set_clock_50(&mut setup.state, c_expiry + 1, 200);
        let tx = erase_tx(&setup.state, erase_ix(&setup.state, idc_c));
        let events = setup.apply(&tx).expect("erase C");
        assert_eq!(
            events,
            vec![RlnEvent::Erased(Erased {
                tree_id: TREE_ID,
                id_commitment: idc_c,
            })]
        );
        assert_eq!(set.apply(&events[0]).unwrap(), None);
    }

    // ====================================================================
    // Expiration
    // ====================================================================

    const EXP_RATE_LIMIT: u64 = 300;

    fn extend(setup: &mut TestSetup, idc: [u8; 32]) -> Result<Vec<RlnEvent>, LeeError> {
        let tx = extend_tx(setup, &setup.payer_key, extend_ix(&setup.state, idc));
        setup.apply(&tx)
    }

    fn erase(setup: &mut TestSetup, idc: [u8; 32]) -> Result<Vec<RlnEvent>, LeeError> {
        let tx = erase_tx(&setup.state, erase_ix(&setup.state, idc));
        setup.apply(&tx)
    }

    /// Registered at `GENESIS_TIMESTAMP_MS`.
    fn registered_at_genesis(seed: u8) -> (TestSetup, [u8; 32]) {
        let mut setup = setup_or_skip();
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS, 50);
        let idc = valid_field_element(seed);
        register(&mut setup, idc, EXP_RATE_LIMIT);
        (setup, idc)
    }

    #[test]
    fn test_register_snapshots_grace_period_start() {
        let mut setup = setup_or_skip();
        let at = GENESIS_TIMESTAMP_MS + 500;
        set_clock_50(&mut setup.state, at, 50);
        let idc = valid_field_element(0xA1);
        register(&mut setup, idc, EXP_RATE_LIMIT);

        let m = membership(&setup.state, &idc).unwrap();
        assert_eq!(m.grace_period_start_timestamp_ms, at + ACTIVE_MS);
        assert_eq!(m.active_duration_sec, DEFAULT_ACTIVE_DURATION_SEC);
        assert_eq!(
            m.grace_period_duration_sec,
            DEFAULT_GRACE_PERIOD_DURATION_SEC
        );
    }

    /// A fresh chain carries the genesis CLOCK_50 (timestamp 0) until block
    /// 50. A membership stamped from it would expire the instant the clock is
    /// first written, so registration refuses — even with a matching claim.
    #[test]
    fn test_register_is_refused_while_the_clock_reads_zero() {
        let mut setup = setup_or_skip();
        set_clock_50(&mut setup.state, 0, 0);
        let idc = valid_field_element(0xB2);
        let ix = register_ix(&setup.state, idc, EXP_RATE_LIMIT);
        assert!(matches!(ix, Instruction::Register { now_ms: 0, .. }));
        let tx = register_tx(&setup, ix);
        assert!(setup.apply(&tx).is_err());
        assert!(membership(&setup.state, &idc).is_none());
    }

    /// The production defaults over a realistic timeline: guards the bug that
    /// turned a 30-day membership into a 43-minute one.
    #[test]
    fn test_production_durations_span_real_days_of_chain_time() {
        use crate::rln::client::{
            DEFAULT_ACTIVE_DURATION_SECS, DEFAULT_GRACE_PERIOD_DURATION_SECS,
        };
        const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

        let mut setup = setup_with(
            DEFAULT_MAX_TOTAL_RATE_LIMIT,
            DEFAULT_ACTIVE_DURATION_SECS,
            DEFAULT_GRACE_PERIOD_DURATION_SECS,
        )
        .expect("setup");
        let t0 = GENESIS_TIMESTAMP_MS;
        set_clock_50(&mut setup.state, t0, 50);
        let idc = valid_field_element(0xB1);
        register(&mut setup, idc, EXP_RATE_LIMIT);
        assert_eq!(
            membership(&setup.state, &idc)
                .unwrap()
                .grace_period_start_timestamp_ms,
            t0 + 30 * DAY_MS
        );

        set_clock_50(&mut setup.state, t0 + 29 * DAY_MS, 100);
        assert!(extend(&mut setup, idc).is_err(), "still active on day 29");

        set_clock_50(&mut setup.state, t0 + 31 * DAY_MS, 150);
        let events = extend(&mut setup, idc).expect("in grace on day 31");
        assert_eq!(
            membership(&setup.state, &idc)
                .unwrap()
                .grace_period_start_timestamp_ms,
            t0 + (30 + 7 + 30) * DAY_MS,
            "extend adds one grace + one active period"
        );
        assert_eq!(
            events,
            vec![RlnEvent::Extended(Extended {
                tree_id: TREE_ID,
                id_commitment: idc,
                expiry_timestamp_ms: t0 + (30 + 7 + 30 + 7) * DAY_MS,
            })]
        );

        set_clock_50(&mut setup.state, t0 + 75 * DAY_MS, 200);
        erase(&mut setup, idc).expect("expired by day 75");
        assert!(membership(&setup.state, &idc).is_none());
    }

    #[test]
    fn test_extend_succeeds_in_grace_period_and_emits_the_new_expiry() {
        let (mut setup, idc) = registered_at_genesis(0xA2);
        let grace_start = GENESIS_TIMESTAMP_MS + ACTIVE_MS;
        set_clock_50(&mut setup.state, grace_start + GRACE_MS / 2, 100);
        let events = extend(&mut setup, idc).expect("extend during grace");
        let m = membership(&setup.state, &idc).unwrap();
        assert_eq!(
            m.grace_period_start_timestamp_ms,
            grace_start + GRACE_MS + ACTIVE_MS
        );
        assert_eq!(
            events,
            vec![RlnEvent::Extended(Extended {
                tree_id: TREE_ID,
                id_commitment: idc,
                expiry_timestamp_ms: membership_expiry_ms(&m),
            })]
        );
    }

    /// `Extended` carries the expiry the instruction claims, so the apply
    /// must refuse every claim but the one the extension produces: an
    /// overstated one would tell readers to keep the leaf too long, the
    /// pre-extension one to drop it too early.
    #[test]
    fn extend_rejects_a_wrong_expiry_claim() {
        let (mut setup, idc) = registered_at_genesis(0xAD);
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1, 100);
        let ix = extend_ix(&setup.state, idc);
        let Instruction::Extend {
            expiry_timestamp_ms: honest,
            ..
        } = ix
        else {
            unreachable!()
        };
        let current = membership_expiry_ms(&membership(&setup.state, &idc).unwrap());
        for (what, claim) in [
            ("an overstated expiry", honest + 1),
            ("the pre-extension expiry", current),
        ] {
            let tx = extend_tx(
                &setup,
                &setup.payer_key,
                with_claim!(
                    ix.clone(),
                    Extend {
                        expiry_timestamp_ms: claim
                    }
                ),
            );
            assert_exit(setup.apply(&tx), EXIT_STALE_EXPIRY, what);
            assert_eq!(
                membership_expiry_ms(&membership(&setup.state, &idc).unwrap()),
                current,
                "{what}: membership untouched"
            );
            assert_eq!(setup.events.len(), 1, "{what}: no Extended");
        }
    }

    #[test]
    fn test_extend_fails_when_still_active() {
        let (mut setup, idc) = registered_at_genesis(0xA3);
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS + 10, 100);
        assert!(extend(&mut setup, idc).is_err());
    }

    #[test]
    fn test_extend_fails_when_expired() {
        let (mut setup, idc) = registered_at_genesis(0xA4);
        set_clock_50(
            &mut setup.state,
            GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1,
            100,
        );
        assert!(extend(&mut setup, idc).is_err());
    }

    /// SECURITY (rate-limit pinning): extend does not check who pays — a
    /// membership records no owner — but it charges the registration price,
    /// so keeping an abandoned membership alive is not free.
    #[test]
    fn test_extend_by_a_third_party_is_allowed_but_charged() {
        let (mut setup, idc) = registered_at_genesis(0xA5);
        let (third_key, third_id) = keypair(5);
        fund_native(&mut setup.state, &third_id, DEFAULT_PAYER_BALANCE);
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1, 100);

        let treasury_before = native_balance(&setup.state, &setup.treasury_id);
        let owner_before = native_balance(&setup.state, &setup.payer_id);
        let tx = extend_tx(&setup, &third_key, extend_ix(&setup.state, idc));
        setup.apply(&tx).expect("a paying third party may renew");

        let price = u128::from(EXP_RATE_LIMIT) * PRICE_PER_UNIT;
        assert!(price > 0, "a zero-priced renewal would restore the grief");
        assert_eq!(
            native_balance(&setup.state, &third_id),
            DEFAULT_PAYER_BALANCE - price
        );
        assert_eq!(
            native_balance(&setup.state, &setup.treasury_id) - treasury_before,
            price
        );
        assert_eq!(
            native_balance(&setup.state, &setup.payer_id),
            owner_before,
            "owner untouched"
        );
    }

    #[test]
    fn test_extend_fails_when_payer_cannot_cover_the_price() {
        let (mut setup, idc) = registered_at_genesis(0xA7);
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1, 100);
        let payer = setup.payer_id;
        fund_native(&mut setup.state, &payer, 0);
        assert!(
            extend(&mut setup, idc).is_err(),
            "an unfunded renewal must fail"
        );
        assert_eq!(setup.events.len(), 1, "no Extended");
    }

    /// Renewal claims: a cheaper price or a lower rate limit would renew for
    /// less than registering costs.
    #[test]
    fn extend_rejects_wrong_price_and_rate_limit_claims() {
        let (mut setup, idc) = registered_at_genesis(0xA9);
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1, 100);
        let before = membership(&setup.state, &idc)
            .unwrap()
            .grace_period_start_timestamp_ms;
        let payer_before = native_balance(&setup.state, &setup.payer_id);
        let ix = extend_ix(&setup.state, idc);

        for (what, bad) in [
            (
                "an under-priced claim",
                with_claim!(ix.clone(), Extend { price_per_unit: 1 }),
            ),
            (
                "a lower rate limit",
                with_claim!(ix.clone(), Extend { rate_limit: 100 }),
            ),
            (
                "a now_ms ahead of the clock",
                with_claim!(
                    ix,
                    Extend {
                        now_ms: GENESIS_TIMESTAMP_MS + ACTIVE_MS + 2
                    }
                ),
            ),
        ] {
            let tx = extend_tx(&setup, &setup.payer_key, bad);
            assert!(setup.apply(&tx).is_err(), "extend with {what} must fail");
            assert_eq!(
                membership(&setup.state, &idc)
                    .unwrap()
                    .grace_period_start_timestamp_ms,
                before
            );
            assert_eq!(native_balance(&setup.state, &setup.payer_id), payer_before);
        }
    }

    #[test]
    fn test_erase_succeeds_when_expired_and_emits_erased() {
        let (mut setup, idc) = registered_at_genesis(0xA6);
        set_clock_50(
            &mut setup.state,
            GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1,
            100,
        );
        let events = erase(&mut setup, idc).expect("erase of an expired membership");
        assert!(membership(&setup.state, &idc).is_none());
        assert_eq!(
            events,
            vec![RlnEvent::Erased(Erased {
                tree_id: TREE_ID,
                id_commitment: idc,
            })]
        );
    }

    #[test]
    fn test_erase_fails_when_active() {
        let (mut setup, idc) = registered_at_genesis(0xA7);
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS + 1, 100);
        assert!(erase(&mut setup, idc).is_err());
        assert_eq!(setup.events.len(), 1, "no Erased");
    }

    #[test]
    fn test_erase_fails_in_grace_period() {
        let (mut setup, idc) = registered_at_genesis(0xA8);
        set_clock_50(&mut setup.state, GENESIS_TIMESTAMP_MS + ACTIVE_MS + 1, 100);
        assert!(erase(&mut setup, idc).is_err());
    }

    #[test]
    fn test_erase_decrements_total_rate_limit() {
        let (mut setup, idc) = registered_at_genesis(0xAA);
        assert_eq!(
            config(&setup.state).current_total_rate_limit,
            EXP_RATE_LIMIT
        );
        set_clock_50(
            &mut setup.state,
            GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1,
            100,
        );
        erase(&mut setup, idc).expect("erase");
        assert_eq!(config(&setup.state).current_total_rate_limit, 0);
    }

    /// The rate limit an `Erased` carries is asserted against the membership.
    #[test]
    fn erase_rejects_a_wrong_rate_limit_claim() {
        let (mut setup, idc) = registered_at_genesis(0xAB);
        set_clock_50(
            &mut setup.state,
            GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1,
            100,
        );
        let ix = erase_ix(&setup.state, idc);
        for claimed in [100, 600] {
            let tx = erase_tx(
                &setup.state,
                with_claim!(
                    ix.clone(),
                    Erase {
                        rate_limit: claimed
                    }
                ),
            );
            assert!(
                setup.apply(&tx).is_err(),
                "erase claiming rate limit {claimed} must fail"
            );
            assert!(membership(&setup.state, &idc).is_some(), "membership kept");
        }
    }

    /// Erase clears the membership shard, so the commitment can register
    /// again, at a new leaf.
    #[test]
    fn an_erased_commitment_can_register_again() {
        let (mut setup, idc) = registered_at_genesis(0xAC);
        set_clock_50(
            &mut setup.state,
            GENESIS_TIMESTAMP_MS + ACTIVE_MS + GRACE_MS + 1,
            100,
        );
        erase(&mut setup, idc).expect("erase");

        register(&mut setup, idc, EXP_RATE_LIMIT);
        assert!(membership(&setup.state, &idc).is_some(), "re-registered");
        assert_eq!(reader(&setup).leaf_index_of(&idc), Some(1));
        assert_eq!(
            config(&setup.state).current_total_rate_limit,
            EXP_RATE_LIMIT
        );
    }
}
