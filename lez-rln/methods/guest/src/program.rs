//! The RLN registration program: `plan` turns an instruction plus account
//! metadata into shard effects, chained calls and events; `apply` runs one
//! effect against one shard's bytes.
//!
//! Plan sees no account data, so every stored value an instruction depends on
//! travels in it as a claim (see `rln_layouts::instruction`). Each claim is
//! asserted by the apply of the shard that stores it; a wrong claim fails the
//! transaction, and with it every chained call and event the plan emitted.
//!
//! There is no on-chain membership tree. Each successful action emits one
//! `rln_layouts::events` event, built only from asserted claims, and readers
//! rebuild the tree from those events in block order.

use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::{
    account::{AccountId, ProgramShardSelector},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{AccountMeta, ChainedCall, PdaSeed, Plan, PlanInput, ProgramEvent},
};
use rln_layouts::{
    ConfigState, Instruction, MembershipState, combine_seeds,
    events::{Erased, Extended, Registered, Slashed},
    exit::{
        EXIT_MEMBERSHIP_EXISTS, EXIT_MEMBERSHIP_MISSING, EXIT_NOT_EXPIRED,
        EXIT_NOT_IN_GRACE_PERIOD, EXIT_RATE_LIMIT_FULL, EXIT_STALE_CONFIG, EXIT_STALE_EXPIRY,
        EXIT_STALE_LEAF_INDEX, EXIT_STALE_RATE_LIMIT,
    },
    expiry_ms, is_expired, is_in_grace_period, label_seed, secs_to_millis,
};

use crate::{
    ensure,
    hash::{hash_single, validate_field_element},
    registration::{
        assert_clock_is, calculate_payment_amount, require_clock_account, validate_rate_limit,
    },
};

// ─── effects ───────────────────────────────────────────────────────────

/// One shard mutation or guard, planned by `plan` and executed by `apply`.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub enum Effect {
    /// Config shard: write the initial config. One-shot.
    InitConfig(ConfigState),
    /// Config shard: assert every claim a registration relies on, then count
    /// the new member and advance `next_leaf_index`.
    RegisterConfig {
        tree_id: [u8; 32],
        price_per_unit: u128,
        treasury: [u8; 32],
        rate_limit: u64,
        active_duration_sec: u32,
        grace_period_duration_sec: u32,
        leaf_index: u64,
    },
    /// Membership shard: write the new membership. One-shot.
    InitMembership(MembershipState),
    /// Clock shard (foreign, read-only): the claim is at most
    /// `CLOCK_CLAIM_TOLERANCE_MS` behind its timestamp, never ahead.
    ClockIs(u64),
    /// Config shard: assert the tree id, then uncount a member of
    /// `rate_limit` (slash, erase).
    ReleaseConfig { tree_id: [u8; 32], rate_limit: u64 },
    /// Membership shard: assert the claims, then clear.
    SlashMembership {
        id_commitment: [u8; 32],
        rate_limit: u64,
    },
    /// Config shard: assert the renewal's price and payee; keep.
    ExtendConfig {
        tree_id: [u8; 32],
        price_per_unit: u128,
        treasury: [u8; 32],
    },
    /// Membership shard: assert the claims and the grace window, then renew.
    ExtendMembership {
        now_ms: u64,
        rate_limit: u64,
        expiry_timestamp_ms: u64,
    },
    /// Membership shard: assert the claim and expiry, then clear.
    EraseMembership { now_ms: u64, rate_limit: u64 },
}

// ─── PDA seeds ─────────────────────────────────────────────────────────

pub fn config_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("config"), tree_id])
}

pub fn membership_seed(tree_id: &[u8; 32], id_commitment: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("membership"), tree_id, id_commitment])
}

fn pda(input: &PlanInput, seed: [u8; 32]) -> AccountId {
    AccountId::for_public_pda(&input.self_account_id, &PdaSeed::new(seed))
}

// ─── plan-side account checks ──────────────────────────────────────────

fn accounts<'a, const N: usize>(input: &'a PlanInput, what: &str) -> &'a [AccountMeta; N] {
    input
        .accounts
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("{what} takes exactly {N} accounts"))
}

/// `meta` is this program's shard of the PDA derived from `seed`.
fn require_own_pda(input: &PlanInput, meta: &AccountMeta, seed: [u8; 32], what: &str) {
    assert!(meta.account_id == pda(input, seed), "Wrong {what} PDA");
    assert!(
        meta.program_account_id == input.self_account_id,
        "{what} must select this program's shard"
    );
}

// ─── chained calls ─────────────────────────────────────────────────────

/// Move `amount` of the native asset from `payer` to `treasury`. The native
/// program refuses an unauthorized sender and an insufficient balance; the
/// destination is ours to check, against the config's treasury.
fn native_payment(payer: &AccountMeta, treasury: &AccountMeta, amount: u128) -> ChainedCall {
    ChainedCall::new(
        NATIVE_TOKEN_PROGRAM_ID,
        vec![
            ProgramShardSelector::native_balance(payer.account_id),
            ProgramShardSelector::native_balance(treasury.account_id),
        ],
        &native_token::Instruction::Transfer { amount },
    )
}

// ─── plan ──────────────────────────────────────────────────────────────

/// Plan one instruction.
///
/// Accounts, in order:
/// - `Initialize`: `[config]`
/// - `Register`: `[config, payer, treasury, clock, membership]`
/// - `Slash`: `[config, membership]`
/// - `Extend`: `[config, membership, payer, treasury, clock]`
/// - `Erase`: `[config, membership, clock]`
///
/// `config` and `membership` select this program's shard of their PDAs,
/// `clock` the clock program's shard of `CLOCK_50`. `payer` must be
/// authorized; `payer` and `treasury` are paid through their native shards,
/// whatever shard their metadata selects.
///
/// Every instruction but `Initialize` emits exactly one event, last. Each of
/// its fields is an argument the plan validated or a claim an apply asserts,
/// so a transaction that emits it is one whose every claim held.
pub fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    let mut plan = Plan::new(input);
    match instruction {
        Instruction::Initialize {
            tree_id,
            price_per_unit,
            treasury_account_id,
            max_total_rate_limit,
            active_duration_for_new_memberships_sec,
            grace_period_duration_for_new_memberships_sec,
        } => {
            let [config] = accounts(input, "Initialize");
            require_own_pda(input, config, config_seed(&tree_id), "config");
            assert!(
                max_total_rate_limit > 0,
                "Max total rate limit must be positive"
            );
            assert!(
                active_duration_for_new_memberships_sec > 0,
                "Active duration must be positive"
            );
            plan.effect(
                config,
                &Effect::InitConfig(ConfigState {
                    tree_id,
                    price_per_unit,
                    treasury_account_id,
                    total_registrations: 0,
                    max_total_rate_limit,
                    current_total_rate_limit: 0,
                    active_duration_for_new_memberships_sec,
                    grace_period_duration_for_new_memberships_sec,
                    next_leaf_index: 0,
                }),
            );
        }
        Instruction::Register {
            tree_id,
            id_commitment,
            rate_limit,
            now_ms,
            price_per_unit,
            active_duration_sec,
            grace_period_duration_sec,
            leaf_index,
        } => {
            let [config, payer, treasury, clock, membership] = accounts(input, "Register");
            // Readers hash `(id_commitment, rate_limit)` into a Poseidon leaf,
            // so the commitment must be a BN254 field element; the program
            // itself no longer hashes it.
            validate_field_element(&id_commitment);
            // Zero is the empty-leaf value and no identity secret hashes to it.
            assert!(id_commitment != [0u8; 32], "id_commitment must not be zero");
            validate_rate_limit(rate_limit);
            require_own_pda(input, config, config_seed(&tree_id), "config");
            require_own_pda(
                input,
                membership,
                membership_seed(&tree_id, &id_commitment),
                "membership",
            );
            require_clock_account(clock);
            assert!(payer.is_authorized, "Payer must authorize payment");

            let grace_period_start_timestamp_ms =
                now_ms.saturating_add(secs_to_millis(active_duration_sec));
            plan.effect(
                config,
                &Effect::RegisterConfig {
                    tree_id,
                    price_per_unit,
                    treasury: *treasury.account_id.value(),
                    rate_limit,
                    active_duration_sec,
                    grace_period_duration_sec,
                    leaf_index,
                },
            );
            plan.inspect(clock, clock.program_account_id, &Effect::ClockIs(now_ms));
            plan.effect(
                membership,
                &Effect::InitMembership(MembershipState {
                    rate_limit,
                    id_commitment,
                    grace_period_start_timestamp_ms,
                    active_duration_sec,
                    grace_period_duration_sec,
                }),
            );
            plan.call(native_payment(
                payer,
                treasury,
                calculate_payment_amount(rate_limit, price_per_unit),
            ));
            plan.event(event(
                Registered::SELECTOR,
                Registered {
                    tree_id,
                    id_commitment,
                    rate_limit,
                    expiry_timestamp_ms: expiry_ms(
                        grace_period_start_timestamp_ms,
                        secs_to_millis(grace_period_duration_sec),
                    ),
                    leaf_index,
                }
                .to_bytes(),
            ));
        }
        Instruction::Slash {
            tree_id,
            id_commitment,
            identity_secret,
            rate_limit,
        } => {
            let [config, membership] = accounts(input, "Slash");
            validate_field_element(&identity_secret);
            assert_eq!(
                hash_single(&identity_secret),
                id_commitment,
                "id_commitment arg must match hash(identity_secret)"
            );
            require_own_pda(input, config, config_seed(&tree_id), "config");
            require_own_pda(
                input,
                membership,
                membership_seed(&tree_id, &id_commitment),
                "membership",
            );

            plan.effect(
                config,
                &Effect::ReleaseConfig {
                    tree_id,
                    rate_limit,
                },
            );
            plan.effect(
                membership,
                &Effect::SlashMembership {
                    id_commitment,
                    rate_limit,
                },
            );
            plan.event(event(
                Slashed::SELECTOR,
                Slashed {
                    tree_id,
                    id_commitment,
                }
                .to_bytes(),
            ));
        }
        // Renewal is priced, not permissioned: the membership records no
        // owner and anyone may pay for anyone's renewal, but it costs what
        // registering the same rate limit costs. `erase` reclaims a rate
        // limit only once the membership expires, so free renewal would let
        // any passer-by keep abandoned memberships alive one tx per grace
        // window and pin `current_total_rate_limit` at its maximum.
        Instruction::Extend {
            tree_id,
            id_commitment,
            now_ms,
            price_per_unit,
            rate_limit,
            expiry_timestamp_ms,
        } => {
            let [config, membership, payer, treasury, clock] = accounts(input, "Extend");
            require_own_pda(input, config, config_seed(&tree_id), "config");
            require_own_pda(
                input,
                membership,
                membership_seed(&tree_id, &id_commitment),
                "membership",
            );
            require_clock_account(clock);
            assert!(payer.is_authorized, "Payer must authorize payment");

            plan.effect(
                config,
                &Effect::ExtendConfig {
                    tree_id,
                    price_per_unit,
                    treasury: *treasury.account_id.value(),
                },
            );
            plan.inspect(clock, clock.program_account_id, &Effect::ClockIs(now_ms));
            plan.effect(
                membership,
                &Effect::ExtendMembership {
                    now_ms,
                    rate_limit,
                    expiry_timestamp_ms,
                },
            );
            plan.call(native_payment(
                payer,
                treasury,
                calculate_payment_amount(rate_limit, price_per_unit),
            ));
            plan.event(event(
                Extended::SELECTOR,
                Extended {
                    tree_id,
                    id_commitment,
                    expiry_timestamp_ms,
                }
                .to_bytes(),
            ));
        }
        Instruction::Erase {
            tree_id,
            id_commitment,
            rate_limit,
            now_ms,
        } => {
            let [config, membership, clock] = accounts(input, "Erase");
            require_own_pda(input, config, config_seed(&tree_id), "config");
            require_own_pda(
                input,
                membership,
                membership_seed(&tree_id, &id_commitment),
                "membership",
            );
            require_clock_account(clock);

            plan.effect(
                config,
                &Effect::ReleaseConfig {
                    tree_id,
                    rate_limit,
                },
            );
            plan.inspect(clock, clock.program_account_id, &Effect::ClockIs(now_ms));
            plan.effect(membership, &Effect::EraseMembership { now_ms, rate_limit });
            plan.event(event(
                Erased::SELECTOR,
                Erased {
                    tree_id,
                    id_commitment,
                }
                .to_bytes(),
            ));
        }
    }
    plan
}

fn event(selector: [u8; 8], data: Vec<u8>) -> ProgramEvent {
    ProgramEvent { selector, data }
}

// ─── apply ─────────────────────────────────────────────────────────────

fn encode<T: BorshSerialize>(value: &T) -> Vec<u8> {
    borsh::to_vec(value).expect("borsh serialization is infallible")
}

fn decode_config(pre_data: &[u8]) -> ConfigState {
    ConfigState::try_from_slice(pre_data).expect("decode ConfigState")
}

/// An empty shard means the membership was slashed or erased since the
/// caller read it: a stale view, not a malformed transaction.
fn decode_membership(pre_data: &[u8], empty_msg: &str) -> MembershipState {
    ensure!(!pre_data.is_empty(), EXIT_MEMBERSHIP_MISSING, "{empty_msg}");
    MembershipState::try_from_slice(pre_data).expect("decode MembershipState")
}

fn assert_tree_id(config: &ConfigState, tree_id: &[u8; 32]) {
    assert!(config.tree_id == *tree_id, "tree_id arg must match config");
}

/// Apply one effect to its shard's bytes. `None` keeps the shard; `Some`
/// replaces it, and an empty `Some` clears it.
pub fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        // One-shot: a public transaction needs no signature, so the config
        // PDA is writable by anyone; an empty shard is what makes
        // initialization happen once.
        Effect::InitConfig(state) => {
            assert!(
                pre_data.is_empty(),
                "AccountAlreadyInitialized: config shard already holds data"
            );
            Some(encode(&state))
        }
        Effect::RegisterConfig {
            tree_id,
            price_per_unit,
            treasury,
            rate_limit,
            active_duration_sec,
            grace_period_duration_sec,
            leaf_index,
        } => {
            let mut config = decode_config(pre_data);
            assert_tree_id(&config, &tree_id);
            ensure!(
                config.price_per_unit == price_per_unit,
                EXIT_STALE_CONFIG,
                "price_per_unit claim must match config"
            );
            ensure!(
                config.treasury_account_id == treasury,
                EXIT_STALE_CONFIG,
                "Wrong treasury"
            );
            ensure!(
                config.active_duration_for_new_memberships_sec == active_duration_sec,
                EXIT_STALE_CONFIG,
                "active_duration_sec claim must match config"
            );
            ensure!(
                config.grace_period_duration_for_new_memberships_sec == grace_period_duration_sec,
                EXIT_STALE_CONFIG,
                "grace_period_duration_sec claim must match config"
            );
            ensure!(
                config.can_register(rate_limit),
                EXIT_RATE_LIMIT_FULL,
                "Would exceed max total rate limit"
            );
            // The `Registered` event carries the claim; this is what makes it
            // the index no other registration has taken.
            ensure!(
                config.next_leaf_index == leaf_index,
                EXIT_STALE_LEAF_INDEX,
                "leaf_index claim must match config"
            );
            config.next_leaf_index = config.next_leaf_index.saturating_add(1);
            config.total_registrations = config.total_registrations.saturating_add(1);
            config.current_total_rate_limit =
                config.current_total_rate_limit.saturating_add(rate_limit);
            Some(encode(&config))
        }
        // One-shot, and the only duplicate-registration guard: the membership
        // PDA is derived from the id_commitment, and the register plan does
        // not dedupe. Weaken this check and re-registering a commitment
        // silently overwrites its membership and emits a second `Registered`.
        Effect::InitMembership(state) => {
            ensure!(
                pre_data.is_empty(),
                EXIT_MEMBERSHIP_EXISTS,
                "AccountAlreadyInitialized: membership already exists"
            );
            Some(encode(&state))
        }
        Effect::ClockIs(now_ms) => {
            assert_clock_is(pre_data, now_ms);
            None
        }
        Effect::ReleaseConfig {
            tree_id,
            rate_limit,
        } => {
            let mut config = decode_config(pre_data);
            assert_tree_id(&config, &tree_id);
            config.current_total_rate_limit =
                config.current_total_rate_limit.saturating_sub(rate_limit);
            config.total_registrations = config.total_registrations.saturating_sub(1);
            Some(encode(&config))
        }
        Effect::SlashMembership {
            id_commitment,
            rate_limit,
        } => {
            let membership = decode_membership(
                pre_data,
                "Membership account is empty - member doesn't exist or already slashed",
            );
            assert!(
                membership.id_commitment == id_commitment,
                "membership id_commitment mismatch"
            );
            ensure!(
                membership.rate_limit == rate_limit,
                EXIT_STALE_RATE_LIMIT,
                "rate_limit claim must match membership"
            );
            Some(Vec::new())
        }
        Effect::ExtendConfig {
            tree_id,
            price_per_unit,
            treasury,
        } => {
            let config = decode_config(pre_data);
            assert_tree_id(&config, &tree_id);
            ensure!(
                config.price_per_unit == price_per_unit,
                EXIT_STALE_CONFIG,
                "price_per_unit claim must match config"
            );
            ensure!(
                config.treasury_account_id == treasury,
                EXIT_STALE_CONFIG,
                "Wrong treasury"
            );
            None
        }
        Effect::ExtendMembership {
            now_ms,
            rate_limit,
            expiry_timestamp_ms,
        } => {
            let mut membership = decode_membership(
                pre_data,
                "Membership account is empty - cannot extend a non-existent membership",
            );
            ensure!(
                membership.rate_limit == rate_limit,
                EXIT_STALE_RATE_LIMIT,
                "rate_limit claim must match membership"
            );
            ensure!(
                is_in_grace_period(
                    membership.grace_period_start_timestamp_ms,
                    secs_to_millis(membership.grace_period_duration_sec),
                    now_ms,
                ),
                EXIT_NOT_IN_GRACE_PERIOD,
                "CannotExtendNonGracePeriodMembership: membership is not in its grace period"
            );
            membership.grace_period_start_timestamp_ms = membership
                .grace_period_start_timestamp_ms
                .saturating_add(secs_to_millis(membership.grace_period_duration_sec))
                .saturating_add(secs_to_millis(membership.active_duration_sec));
            // The `Extended` event carries the claim; this is what makes it
            // the expiry the membership now has.
            ensure!(
                expiry_ms(
                    membership.grace_period_start_timestamp_ms,
                    secs_to_millis(membership.grace_period_duration_sec),
                ) == expiry_timestamp_ms,
                EXIT_STALE_EXPIRY,
                "expiry_timestamp_ms claim must match the extended membership"
            );
            Some(encode(&membership))
        }
        Effect::EraseMembership { now_ms, rate_limit } => {
            let membership =
                decode_membership(pre_data, "Membership account is empty - nothing to erase");
            ensure!(
                membership.rate_limit == rate_limit,
                EXIT_STALE_RATE_LIMIT,
                "rate_limit claim must match membership"
            );
            ensure!(
                is_expired(
                    membership.grace_period_start_timestamp_ms,
                    secs_to_millis(membership.grace_period_duration_sec),
                    now_ms,
                ),
                EXIT_NOT_EXPIRED,
                "CannotEraseUnexpiredMembership: membership has not expired yet"
            );
            Some(Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use nssa_core::program::ShardEffect;
    use rln_layouts::{CLOCK_50_ACCOUNT_ID_BYTES, events::RlnEvent};

    use super::*;

    const SELF_ID: [u8; 32] = [0xA1; 32];
    const TREE_ID: [u8; 32] = [0x07; 32];
    const TREASURY: [u8; 32] = [0x77; 32];
    const PAYER: [u8; 32] = [0x55; 32];
    const PRICE: u128 = 10;
    const ACTIVE_SEC: u32 = 100;
    const GRACE_SEC: u32 = 50;
    /// The config's `next_leaf_index` in [`config_state`].
    const LEAF: u64 = 5;
    const NOW_MS: u64 = 1_000_000;
    const RATE: u64 = 200;

    fn self_id() -> AccountId {
        AccountId::new(SELF_ID)
    }

    fn pda_of(seed: [u8; 32]) -> AccountId {
        AccountId::for_public_pda(&self_id(), &PdaSeed::new(seed))
    }

    fn commitment() -> [u8; 32] {
        hash_single(&secret())
    }

    fn secret() -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = 42;
        s
    }

    fn config_meta() -> AccountMeta {
        AccountMeta::new(pda_of(config_seed(&TREE_ID)), false, self_id())
    }

    fn membership_meta() -> AccountMeta {
        AccountMeta::new(
            pda_of(membership_seed(&TREE_ID, &commitment())),
            false,
            self_id(),
        )
    }

    fn payer_meta(is_authorized: bool) -> AccountMeta {
        AccountMeta::native_balance(AccountId::new(PAYER), is_authorized)
    }

    fn treasury_meta() -> AccountMeta {
        AccountMeta::native_balance(AccountId::new(TREASURY), false)
    }

    fn clock_meta() -> AccountMeta {
        AccountMeta::new(
            AccountId::new(CLOCK_50_ACCOUNT_ID_BYTES),
            false,
            clock_core::clock_account_id(),
        )
    }

    fn input(accounts: Vec<AccountMeta>) -> PlanInput {
        PlanInput {
            self_account_id: self_id(),
            caller_account_id: None,
            accounts,
            instruction_data: Vec::new(),
        }
    }

    fn config_state() -> ConfigState {
        ConfigState {
            tree_id: TREE_ID,
            price_per_unit: PRICE,
            treasury_account_id: TREASURY,
            total_registrations: 3,
            max_total_rate_limit: 1_000,
            current_total_rate_limit: 600,
            active_duration_for_new_memberships_sec: ACTIVE_SEC,
            grace_period_duration_for_new_memberships_sec: GRACE_SEC,
            next_leaf_index: LEAF,
        }
    }

    fn membership_state(grace_start_ms: u64) -> MembershipState {
        MembershipState {
            rate_limit: RATE,
            id_commitment: commitment(),
            grace_period_start_timestamp_ms: grace_start_ms,
            active_duration_sec: ACTIVE_SEC,
            grace_period_duration_sec: GRACE_SEC,
        }
    }

    fn register_ix() -> Instruction {
        Instruction::Register {
            tree_id: TREE_ID,
            id_commitment: commitment(),
            rate_limit: RATE,
            now_ms: NOW_MS,
            price_per_unit: PRICE,
            active_duration_sec: ACTIVE_SEC,
            grace_period_duration_sec: GRACE_SEC,
            leaf_index: LEAF,
        }
    }

    fn register_accounts() -> Vec<AccountMeta> {
        vec![
            config_meta(),
            payer_meta(true),
            treasury_meta(),
            clock_meta(),
            membership_meta(),
        ]
    }

    fn extend_accounts(payer_authorized: bool) -> Vec<AccountMeta> {
        vec![
            config_meta(),
            membership_meta(),
            payer_meta(payer_authorized),
            treasury_meta(),
            clock_meta(),
        ]
    }

    fn extend_ix(expiry_timestamp_ms: u64) -> Instruction {
        Instruction::Extend {
            tree_id: TREE_ID,
            id_commitment: commitment(),
            now_ms: NOW_MS,
            price_per_unit: PRICE,
            rate_limit: RATE,
            expiry_timestamp_ms,
        }
    }

    fn erase_ix() -> Instruction {
        Instruction::Erase {
            tree_id: TREE_ID,
            id_commitment: commitment(),
            rate_limit: RATE,
            now_ms: NOW_MS,
        }
    }

    fn slash_ix(identity_secret: [u8; 32]) -> Instruction {
        Instruction::Slash {
            tree_id: TREE_ID,
            id_commitment: commitment(),
            identity_secret,
            rate_limit: RATE,
        }
    }

    fn expected_payment(amount: u128) -> ChainedCall {
        ChainedCall::new(
            NATIVE_TOKEN_PROGRAM_ID,
            vec![
                ProgramShardSelector::native_balance(AccountId::new(PAYER)),
                ProgramShardSelector::native_balance(AccountId::new(TREASURY)),
            ],
            &native_token::Instruction::Transfer { amount },
        )
    }

    /// The plan's events, decoded. `ProgramEvent` has no `PartialEq`.
    fn events(plan: &Plan) -> Vec<RlnEvent> {
        plan.output()
            .events
            .iter()
            .map(|e| {
                RlnEvent::decode(e.selector, &e.data)
                    .expect("a selector this program emits")
                    .expect("well-formed event data")
            })
            .collect()
    }

    fn clock_bytes(timestamp: u64) -> Vec<u8> {
        clock_core::ClockAccountData {
            block_id: 1,
            timestamp,
        }
        .to_bytes()
    }

    // ─── seeds ─────────────────────────────────────────────────────────

    /// The host derives the same PDAs; these seeds must not drift.
    #[test]
    fn seeds_combine_label_and_args() {
        assert_eq!(
            config_seed(&TREE_ID),
            combine_seeds(&[&label_seed("config"), &TREE_ID])
        );
        assert_eq!(
            membership_seed(&TREE_ID, &[1; 32]),
            combine_seeds(&[&label_seed("membership"), &TREE_ID, &[1; 32]])
        );
    }

    // ─── plan ──────────────────────────────────────────────────────────

    fn initialize_ix() -> Instruction {
        Instruction::Initialize {
            tree_id: TREE_ID,
            price_per_unit: PRICE,
            treasury_account_id: TREASURY,
            max_total_rate_limit: 1_000,
            active_duration_for_new_memberships_sec: ACTIVE_SEC,
            grace_period_duration_for_new_memberships_sec: GRACE_SEC,
        }
    }

    #[test]
    fn plan_initialize_emits_init_config_and_no_event() {
        let plan = plan(&input(vec![config_meta()]), initialize_ix());
        let mut state = config_state();
        state.total_registrations = 0;
        state.current_total_rate_limit = 0;
        state.next_leaf_index = 0;
        assert_eq!(
            plan.output().effects,
            vec![ShardEffect::new(&config_meta(), &Effect::InitConfig(state))]
        );
        assert!(plan.output().chained_calls.is_empty());
        assert!(plan.output().events.is_empty());
    }

    #[test]
    #[should_panic(expected = "Wrong config PDA")]
    fn plan_initialize_rejects_foreign_config_pda() {
        let config = AccountMeta::new(AccountId::new([9; 32]), false, self_id());
        let _ = plan(&input(vec![config]), initialize_ix());
    }

    #[test]
    fn plan_register_emits_effects_payment_and_registered() {
        let plan = plan(&input(register_accounts()), register_ix());
        let out = plan.output();
        let grace_start = NOW_MS + secs_to_millis(ACTIVE_SEC);
        assert_eq!(
            out.effects,
            vec![
                ShardEffect::new(
                    &config_meta(),
                    &Effect::RegisterConfig {
                        tree_id: TREE_ID,
                        price_per_unit: PRICE,
                        treasury: TREASURY,
                        rate_limit: RATE,
                        active_duration_sec: ACTIVE_SEC,
                        grace_period_duration_sec: GRACE_SEC,
                        leaf_index: LEAF,
                    }
                ),
                ShardEffect::new(&clock_meta(), &Effect::ClockIs(NOW_MS)),
                ShardEffect::new(
                    &membership_meta(),
                    &Effect::InitMembership(membership_state(grace_start))
                ),
            ]
        );
        assert_eq!(
            out.chained_calls,
            vec![expected_payment(u128::from(RATE) * PRICE)]
        );
        assert_eq!(
            events(&plan),
            vec![RlnEvent::Registered(Registered {
                tree_id: TREE_ID,
                id_commitment: commitment(),
                rate_limit: RATE,
                expiry_timestamp_ms: grace_start + secs_to_millis(GRACE_SEC),
                leaf_index: LEAF,
            })]
        );
    }

    #[test]
    #[should_panic(expected = "id_commitment must not be zero")]
    fn plan_register_rejects_zero_commitment() {
        let Instruction::Register {
            tree_id,
            rate_limit,
            now_ms,
            price_per_unit,
            active_duration_sec,
            grace_period_duration_sec,
            ..
        } = register_ix()
        else {
            unreachable!()
        };
        let ix = Instruction::Register {
            tree_id,
            id_commitment: [0u8; 32],
            rate_limit,
            now_ms,
            price_per_unit,
            active_duration_sec,
            grace_period_duration_sec,
            leaf_index: LEAF,
        };
        let mut accounts = register_accounts();
        accounts[4] = AccountMeta::new(
            pda_of(membership_seed(&TREE_ID, &[0u8; 32])),
            false,
            self_id(),
        );
        let _ = plan(&input(accounts), ix);
    }

    /// Readers hash the commitment into a Poseidon leaf, so the program must
    /// refuse one that is not a BN254 field element even though it no longer
    /// hashes it itself.
    #[test]
    #[should_panic]
    fn plan_register_rejects_a_commitment_outside_the_field() {
        let commitment = [0xFF; 32];
        let ix = Instruction::Register {
            tree_id: TREE_ID,
            id_commitment: commitment,
            rate_limit: RATE,
            now_ms: NOW_MS,
            price_per_unit: PRICE,
            active_duration_sec: ACTIVE_SEC,
            grace_period_duration_sec: GRACE_SEC,
            leaf_index: LEAF,
        };
        let mut accounts = register_accounts();
        accounts[4] = AccountMeta::new(
            pda_of(membership_seed(&TREE_ID, &commitment)),
            false,
            self_id(),
        );
        let _ = plan(&input(accounts), ix);
    }

    #[test]
    #[should_panic(expected = "Payer must authorize payment")]
    fn plan_register_rejects_unauthorized_payer() {
        let mut accounts = register_accounts();
        accounts[1] = payer_meta(false);
        let _ = plan(&input(accounts), register_ix());
    }

    #[test]
    #[should_panic(expected = "Wrong clock account")]
    fn plan_register_rejects_wrong_clock() {
        let mut accounts = register_accounts();
        accounts[3] = AccountMeta::new(
            AccountId::new(*b"/LEZ/ClockProgramAccount/0000001"),
            false,
            clock_core::clock_account_id(),
        );
        let _ = plan(&input(accounts), register_ix());
    }

    #[test]
    #[should_panic(expected = "Wrong membership PDA")]
    fn plan_register_rejects_membership_of_other_commitment() {
        let mut accounts = register_accounts();
        accounts[4] = AccountMeta::new(
            pda_of(membership_seed(&TREE_ID, &[3; 32])),
            false,
            self_id(),
        );
        let _ = plan(&input(accounts), register_ix());
    }

    #[test]
    #[should_panic(expected = "membership must select this program's shard")]
    fn plan_register_rejects_foreign_membership_shard() {
        let mut accounts = register_accounts();
        accounts[4].program_account_id = AccountId::new([0xB2; 32]);
        let _ = plan(&input(accounts), register_ix());
    }

    #[test]
    #[should_panic(expected = "exactly 5 accounts")]
    fn plan_register_rejects_wrong_account_count() {
        let mut accounts = register_accounts();
        accounts.pop();
        let _ = plan(&input(accounts), register_ix());
    }

    #[test]
    fn plan_slash_releases_clears_and_emits_slashed() {
        let plan = plan(
            &input(vec![config_meta(), membership_meta()]),
            slash_ix(secret()),
        );
        assert_eq!(
            plan.output().effects,
            vec![
                ShardEffect::new(
                    &config_meta(),
                    &Effect::ReleaseConfig {
                        tree_id: TREE_ID,
                        rate_limit: RATE
                    }
                ),
                ShardEffect::new(
                    &membership_meta(),
                    &Effect::SlashMembership {
                        id_commitment: commitment(),
                        rate_limit: RATE
                    }
                ),
            ]
        );
        assert!(plan.output().chained_calls.is_empty());
        assert_eq!(
            events(&plan),
            vec![RlnEvent::Slashed(Slashed {
                tree_id: TREE_ID,
                id_commitment: commitment(),
            })]
        );
    }

    #[test]
    #[should_panic(expected = "must match hash(identity_secret)")]
    fn plan_slash_rejects_wrong_secret() {
        let mut wrong = secret();
        wrong[1] = 1;
        let _ = plan(
            &input(vec![config_meta(), membership_meta()]),
            slash_ix(wrong),
        );
    }

    #[test]
    fn plan_extend_charges_the_registration_price_and_emits_extended() {
        let plan = plan(&input(extend_accounts(true)), extend_ix(12_345));
        assert_eq!(
            plan.output().effects,
            vec![
                ShardEffect::new(
                    &config_meta(),
                    &Effect::ExtendConfig {
                        tree_id: TREE_ID,
                        price_per_unit: PRICE,
                        treasury: TREASURY
                    }
                ),
                ShardEffect::new(&clock_meta(), &Effect::ClockIs(NOW_MS)),
                ShardEffect::new(
                    &membership_meta(),
                    &Effect::ExtendMembership {
                        now_ms: NOW_MS,
                        rate_limit: RATE,
                        expiry_timestamp_ms: 12_345,
                    }
                ),
            ]
        );
        assert_eq!(
            plan.output().chained_calls,
            vec![expected_payment(u128::from(RATE) * PRICE)]
        );
        assert_eq!(
            events(&plan),
            vec![RlnEvent::Extended(Extended {
                tree_id: TREE_ID,
                id_commitment: commitment(),
                expiry_timestamp_ms: 12_345,
            })]
        );
    }

    #[test]
    #[should_panic(expected = "Payer must authorize payment")]
    fn plan_extend_rejects_unauthorized_payer() {
        let _ = plan(&input(extend_accounts(false)), extend_ix(0));
    }

    #[test]
    fn plan_erase_releases_clears_and_emits_erased() {
        let plan = plan(
            &input(vec![config_meta(), membership_meta(), clock_meta()]),
            erase_ix(),
        );
        assert_eq!(
            plan.output().effects,
            vec![
                ShardEffect::new(
                    &config_meta(),
                    &Effect::ReleaseConfig {
                        tree_id: TREE_ID,
                        rate_limit: RATE
                    }
                ),
                ShardEffect::new(&clock_meta(), &Effect::ClockIs(NOW_MS)),
                ShardEffect::new(
                    &membership_meta(),
                    &Effect::EraseMembership {
                        now_ms: NOW_MS,
                        rate_limit: RATE
                    }
                ),
            ]
        );
        assert!(plan.output().chained_calls.is_empty());
        assert_eq!(
            events(&plan),
            vec![RlnEvent::Erased(Erased {
                tree_id: TREE_ID,
                id_commitment: commitment(),
            })]
        );
    }

    #[test]
    #[should_panic(expected = "clock program's shard")]
    fn plan_erase_rejects_foreign_clock_shard() {
        let mut clock = clock_meta();
        clock.program_account_id = self_id();
        let _ = plan(
            &input(vec![config_meta(), membership_meta(), clock]),
            erase_ix(),
        );
    }

    // ─── apply ─────────────────────────────────────────────────────────

    fn config_bytes() -> Vec<u8> {
        encode(&config_state())
    }

    #[test]
    fn apply_init_config_writes_once() {
        let written = apply(Effect::InitConfig(config_state()), &[]).unwrap();
        assert_eq!(written, config_bytes());
    }

    #[test]
    #[should_panic(expected = "AccountAlreadyInitialized")]
    fn apply_init_config_refuses_live_config() {
        let _ = apply(Effect::InitConfig(config_state()), &config_bytes());
    }

    fn register_config(f: impl FnOnce(&mut u128, &mut [u8; 32], &mut u32, &mut u32)) -> Effect {
        let (mut price, mut treasury, mut active, mut grace) =
            (PRICE, TREASURY, ACTIVE_SEC, GRACE_SEC);
        f(&mut price, &mut treasury, &mut active, &mut grace);
        Effect::RegisterConfig {
            tree_id: TREE_ID,
            price_per_unit: price,
            treasury,
            rate_limit: RATE,
            active_duration_sec: active,
            grace_period_duration_sec: grace,
            leaf_index: LEAF,
        }
    }

    #[test]
    fn apply_register_config_counts_the_member() {
        let out = apply(register_config(|_, _, _, _| {}), &config_bytes()).unwrap();
        let mut expected = config_state();
        expected.total_registrations = 4;
        expected.current_total_rate_limit = 800;
        expected.next_leaf_index = LEAF + 1;
        assert_eq!(out, encode(&expected));
    }

    /// The `Registered` event carries the claimed index, so the apply must
    /// refuse one that is not the config's next.
    #[test]
    #[should_panic(expected = "leaf_index claim must match config")]
    fn apply_register_config_rejects_a_taken_leaf_index() {
        let mut effect = register_config(|_, _, _, _| {});
        if let Effect::RegisterConfig { leaf_index, .. } = &mut effect {
            *leaf_index = LEAF - 1;
        }
        let _ = apply(effect, &config_bytes());
    }

    /// A slash or erase uncounts the member but never rewinds the index, so
    /// a later registration cannot reuse a leaf.
    #[test]
    fn apply_release_config_keeps_the_next_leaf_index() {
        let out = apply(
            Effect::ReleaseConfig {
                tree_id: TREE_ID,
                rate_limit: RATE,
            },
            &config_bytes(),
        )
        .unwrap();
        assert_eq!(decode_config(&out).next_leaf_index, LEAF);
    }

    #[test]
    #[should_panic(expected = "tree_id arg must match config")]
    fn apply_register_config_rejects_other_tree() {
        let mut effect = register_config(|_, _, _, _| {});
        if let Effect::RegisterConfig { tree_id, .. } = &mut effect {
            *tree_id = [0; 32];
        }
        let _ = apply(effect, &config_bytes());
    }

    #[test]
    #[should_panic(expected = "price_per_unit claim")]
    fn apply_register_config_rejects_underpriced_claim() {
        let _ = apply(register_config(|p, _, _, _| *p = 0), &config_bytes());
    }

    #[test]
    #[should_panic(expected = "Wrong treasury")]
    fn apply_register_config_rejects_wrong_treasury() {
        let _ = apply(register_config(|_, t, _, _| *t = PAYER), &config_bytes());
    }

    #[test]
    #[should_panic(expected = "active_duration_sec claim")]
    fn apply_register_config_rejects_wrong_active_duration() {
        let _ = apply(register_config(|_, _, a, _| *a += 1), &config_bytes());
    }

    #[test]
    #[should_panic(expected = "grace_period_duration_sec claim")]
    fn apply_register_config_rejects_wrong_grace_duration() {
        let _ = apply(register_config(|_, _, _, g| *g += 1), &config_bytes());
    }

    #[test]
    #[should_panic(expected = "Would exceed max total rate limit")]
    fn apply_register_config_rejects_over_capacity() {
        let mut full = config_state();
        full.current_total_rate_limit = 900;
        let _ = apply(register_config(|_, _, _, _| {}), &encode(&full));
    }

    #[test]
    fn apply_init_membership_writes_once() {
        let state = membership_state(7);
        let out = apply(Effect::InitMembership(state.clone()), &[]).unwrap();
        assert_eq!(out, encode(&state));
    }

    #[test]
    #[should_panic(expected = "AccountAlreadyInitialized: membership already exists")]
    fn apply_init_membership_blocks_duplicate_registration() {
        let state = membership_state(7);
        let _ = apply(Effect::InitMembership(state.clone()), &encode(&state));
    }

    #[test]
    fn apply_clock_is_accepts_matching_timestamp() {
        assert!(apply(Effect::ClockIs(NOW_MS), &clock_bytes(NOW_MS)).is_none());
    }

    #[test]
    #[should_panic(expected = "is not within")]
    fn apply_clock_is_rejects_a_claim_ahead_of_the_clock() {
        let _ = apply(Effect::ClockIs(NOW_MS + 1), &clock_bytes(NOW_MS));
    }

    #[test]
    fn apply_clock_is_accepts_a_claim_one_step_behind() {
        assert!(apply(Effect::ClockIs(NOW_MS), &clock_bytes(NOW_MS + 750_000)).is_none());
    }

    #[test]
    fn apply_release_config_uncounts_the_member() {
        let out = apply(
            Effect::ReleaseConfig {
                tree_id: TREE_ID,
                rate_limit: RATE,
            },
            &config_bytes(),
        )
        .unwrap();
        let mut expected = config_state();
        expected.total_registrations = 2;
        expected.current_total_rate_limit = 400;
        assert_eq!(out, encode(&expected));
    }

    #[test]
    #[should_panic(expected = "tree_id arg must match config")]
    fn apply_release_config_rejects_other_tree() {
        let _ = apply(
            Effect::ReleaseConfig {
                tree_id: [0; 32],
                rate_limit: RATE,
            },
            &config_bytes(),
        );
    }

    #[test]
    fn apply_slash_membership_clears() {
        let out = apply(
            Effect::SlashMembership {
                id_commitment: commitment(),
                rate_limit: RATE,
            },
            &encode(&membership_state(7)),
        );
        assert_eq!(out, Some(Vec::new()));
    }

    #[test]
    #[should_panic(expected = "rate_limit claim must match membership")]
    fn apply_slash_membership_rejects_wrong_rate_claim() {
        let _ = apply(
            Effect::SlashMembership {
                id_commitment: commitment(),
                rate_limit: RATE - 1,
            },
            &encode(&membership_state(7)),
        );
    }

    #[test]
    #[should_panic(expected = "already slashed")]
    fn apply_slash_membership_rejects_empty() {
        let _ = apply(
            Effect::SlashMembership {
                id_commitment: commitment(),
                rate_limit: RATE,
            },
            &[],
        );
    }

    #[test]
    fn apply_extend_config_keeps() {
        let out = apply(
            Effect::ExtendConfig {
                tree_id: TREE_ID,
                price_per_unit: PRICE,
                treasury: TREASURY,
            },
            &config_bytes(),
        );
        assert!(out.is_none());
    }

    /// Renewal is priced: a claimed price below config's fails the tx.
    #[test]
    #[should_panic(expected = "price_per_unit claim")]
    fn apply_extend_config_rejects_free_renewal() {
        let _ = apply(
            Effect::ExtendConfig {
                tree_id: TREE_ID,
                price_per_unit: 0,
                treasury: TREASURY,
            },
            &config_bytes(),
        );
    }

    /// The expiry an honest client claims for extending a membership whose
    /// grace period started at `start`.
    fn extended_expiry(start: u64) -> u64 {
        start + secs_to_millis(GRACE_SEC) + secs_to_millis(ACTIVE_SEC) + secs_to_millis(GRACE_SEC)
    }

    fn extend_membership(expiry_timestamp_ms: u64) -> Effect {
        Effect::ExtendMembership {
            now_ms: NOW_MS,
            rate_limit: RATE,
            expiry_timestamp_ms,
        }
    }

    #[test]
    fn apply_extend_membership_advances_one_period() {
        let start = NOW_MS - 10;
        let out = apply(
            extend_membership(extended_expiry(start)),
            &encode(&membership_state(start)),
        )
        .unwrap();
        let expected =
            membership_state(start + secs_to_millis(GRACE_SEC) + secs_to_millis(ACTIVE_SEC));
        assert_eq!(out, encode(&expected));
    }

    /// The `Extended` event carries the claimed expiry, so the apply must
    /// refuse any claim but the one the extension produces.
    #[test]
    #[should_panic(expected = "expiry_timestamp_ms claim must match")]
    fn apply_extend_membership_rejects_an_overstated_expiry() {
        let start = NOW_MS - 10;
        let _ = apply(
            extend_membership(extended_expiry(start) + 1),
            &encode(&membership_state(start)),
        );
    }

    #[test]
    #[should_panic(expected = "expiry_timestamp_ms claim must match")]
    fn apply_extend_membership_rejects_the_pre_extension_expiry() {
        let start = NOW_MS - 10;
        let _ = apply(
            extend_membership(start + secs_to_millis(GRACE_SEC)),
            &encode(&membership_state(start)),
        );
    }

    #[test]
    #[should_panic(expected = "CannotExtendNonGracePeriodMembership")]
    fn apply_extend_membership_rejects_active_membership() {
        let _ = apply(
            extend_membership(extended_expiry(NOW_MS + 1)),
            &encode(&membership_state(NOW_MS + 1)),
        );
    }

    /// The rate limit prices the renewal, so an understated claim fails.
    #[test]
    #[should_panic(expected = "rate_limit claim must match membership")]
    fn apply_extend_membership_rejects_understated_rate() {
        let _ = apply(
            Effect::ExtendMembership {
                now_ms: NOW_MS,
                rate_limit: RATE - 1,
                expiry_timestamp_ms: extended_expiry(NOW_MS - 10),
            },
            &encode(&membership_state(NOW_MS - 10)),
        );
    }

    #[test]
    fn apply_erase_membership_clears_expired() {
        let start = NOW_MS - secs_to_millis(GRACE_SEC);
        let out = apply(
            Effect::EraseMembership {
                now_ms: NOW_MS,
                rate_limit: RATE,
            },
            &encode(&membership_state(start)),
        );
        assert_eq!(out, Some(Vec::new()));
    }

    #[test]
    #[should_panic(expected = "CannotEraseUnexpiredMembership")]
    fn apply_erase_membership_rejects_unexpired() {
        let _ = apply(
            Effect::EraseMembership {
                now_ms: NOW_MS,
                rate_limit: RATE,
            },
            &encode(&membership_state(NOW_MS - 10)),
        );
    }

    #[test]
    #[should_panic(expected = "rate_limit claim must match membership")]
    fn apply_erase_membership_rejects_wrong_rate_claim() {
        let start = NOW_MS - secs_to_millis(GRACE_SEC);
        let _ = apply(
            Effect::EraseMembership {
                now_ms: NOW_MS,
                rate_limit: RATE + 1,
            },
            &encode(&membership_state(start)),
        );
    }
}
