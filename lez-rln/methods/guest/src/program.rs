//! The RLN registration program: `plan` turns an instruction plus account
//! metadata into shard effects and chained calls; `apply` runs one effect
//! against one shard's bytes.
//!
//! Plan sees no account data, so every stored value an instruction depends on
//! travels in it as a claim (see `rln_layouts::instruction`). Each claim is
//! asserted by the apply of the shard that stores it; a wrong claim fails the
//! transaction, and with it every chained call the plan emitted.

use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::{
    account::{AccountId, ProgramShardSelector},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{AccountMeta, ChainedCall, PdaSeed, Plan, PlanInput},
};
use rln_layouts::{
    ConfigState, Instruction, MembershipState, MerkleInstruction, combine_seeds,
    exit::{
        EXIT_MEMBERSHIP_EXISTS, EXIT_MEMBERSHIP_MISSING, EXIT_NOT_EXPIRED,
        EXIT_NOT_IN_GRACE_PERIOD, EXIT_RATE_LIMIT_FULL, EXIT_STALE_CONFIG, EXIT_STALE_RATE_LIMIT,
    },
    is_expired, is_in_grace_period, label_seed, secs_to_millis,
};

use crate::{
    ensure,
    hash::{hash_single, validate_field_element},
    registration::{
        assert_clock_is, calculate_payment_amount, compute_registration_leaf,
        require_clock_account, validate_rate_limit,
    },
};

// ─── effects ───────────────────────────────────────────────────────────

/// One shard mutation or guard, planned by `plan` and executed by `apply`.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub enum Effect {
    /// Config shard: write the initial config. One-shot.
    InitConfig(ConfigState),
    /// Config shard: assert the claimed ids; keep.
    InitTreeGuard {
        tree_id: [u8; 32],
        merkle_program_id: [u8; 32],
    },
    /// Config shard: assert every claim a registration relies on, then count
    /// the new member.
    RegisterConfig {
        tree_id: [u8; 32],
        merkle_program_id: [u8; 32],
        price_per_unit: u128,
        treasury: [u8; 32],
        rate_limit: u64,
        active_duration_sec: u32,
        grace_period_duration_sec: u32,
    },
    /// Membership shard: write the new membership. One-shot.
    InitMembership(MembershipState),
    /// Clock shard (foreign, read-only): the claim is at most
    /// `CLOCK_CLAIM_TOLERANCE_MS` behind its timestamp, never ahead.
    ClockIs(u64),
    /// Config shard: assert the claimed ids, then uncount a member of
    /// `rate_limit` (slash, erase).
    ReleaseConfig {
        tree_id: [u8; 32],
        merkle_program_id: [u8; 32],
        rate_limit: u64,
    },
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
    /// Membership shard: assert the claim and the grace window, then renew.
    ExtendMembership { now_ms: u64, rate_limit: u64 },
    /// Membership shard: assert the claim and expiry, then clear.
    EraseMembership { now_ms: u64, rate_limit: u64 },
}

// ─── PDA seeds ─────────────────────────────────────────────────────────

pub fn config_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("config"), tree_id])
}

pub fn main_seed(tree_id: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("main"), tree_id])
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

/// `tree_main` is the merkle program's shard of this program's `main` PDA.
fn require_tree_main(
    input: &PlanInput,
    tree_main: &AccountMeta,
    tree_id: &[u8; 32],
    merkle_program_id: &[u8; 32],
) {
    assert!(
        tree_main.account_id == pda(input, main_seed(tree_id)),
        "Wrong tree_main PDA"
    );
    assert!(
        tree_main.program_account_id == AccountId::new(*merkle_program_id),
        "tree_main must select the merkle program's shard"
    );
}

// ─── chained calls ─────────────────────────────────────────────────────

/// Call the merkle program on `tree_main`, granting it this program's `main`
/// PDA.
///
/// `merkle_program_id` is a claim, and the seeds make its program the owner
/// of the tree. Every caller of this function also plans a config effect
/// that asserts the claim against the config's stored `merkle_program_id`,
/// so a caller-named program id fails the transaction instead of receiving
/// the grant. Never emit this call without that effect.
fn merkle_call(
    merkle_program_id: [u8; 32],
    tree_main: &AccountMeta,
    tree_id: &[u8; 32],
    instruction: &MerkleInstruction,
) -> ChainedCall {
    let merkle = AccountId::new(merkle_program_id);
    ChainedCall::new(
        merkle,
        vec![ProgramShardSelector::new(tree_main.account_id, merkle)],
        instruction,
    )
    .with_pda_seeds(vec![PdaSeed::new(main_seed(tree_id))])
}

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
/// - `InitializeMerkleTree`: `[config, tree_main]`
/// - `Register`: `[config, tree_main, payer, treasury, clock, membership]`
/// - `Slash`: `[config, tree_main, membership]`
/// - `Extend`: `[config, membership, payer, treasury, clock]`
/// - `Erase`: `[config, tree_main, membership, clock]`
///
/// `config` and `membership` select this program's shard of their PDAs,
/// `tree_main` the merkle program's shard of this program's `main` PDA,
/// `clock` the clock program's shard of `CLOCK_50`. `payer` must be
/// authorized; `payer` and `treasury` are paid through their native shards,
/// whatever shard their metadata selects.
pub fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    let mut plan = Plan::new(input);
    match instruction {
        Instruction::Initialize {
            merkle_program_id,
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
                    merkle_program_id,
                    tree_id,
                    price_per_unit,
                    treasury_account_id,
                    total_registrations: 0,
                    max_total_rate_limit,
                    current_total_rate_limit: 0,
                    active_duration_for_new_memberships_sec,
                    grace_period_duration_for_new_memberships_sec,
                }),
            );
        }
        Instruction::InitializeMerkleTree {
            tree_id,
            merkle_program_id,
        } => {
            let [config, tree_main] = accounts(input, "InitializeMerkleTree");
            require_own_pda(input, config, config_seed(&tree_id), "config");
            require_tree_main(input, tree_main, &tree_id, &merkle_program_id);
            plan.effect(
                config,
                &Effect::InitTreeGuard {
                    tree_id,
                    merkle_program_id,
                },
            );
            // One-shot: the merkle program's Initialize refuses a tree shard
            // that already holds data, so a replay cannot reset a live tree.
            plan.call(merkle_call(
                merkle_program_id,
                tree_main,
                &tree_id,
                &MerkleInstruction::Initialize,
            ));
        }
        Instruction::Register {
            tree_id,
            id_commitment,
            rate_limit,
            merkle_program_id,
            now_ms,
            price_per_unit,
            active_duration_sec,
            grace_period_duration_sec,
        } => {
            let [config, tree_main, payer, treasury, clock, membership] =
                accounts(input, "Register");
            validate_field_element(&id_commitment);
            // Zero is the empty-leaf value and no identity secret hashes to it.
            assert!(id_commitment != [0u8; 32], "id_commitment must not be zero");
            validate_rate_limit(rate_limit);
            require_own_pda(input, config, config_seed(&tree_id), "config");
            require_tree_main(input, tree_main, &tree_id, &merkle_program_id);
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
                &Effect::RegisterConfig {
                    tree_id,
                    merkle_program_id,
                    price_per_unit,
                    treasury: *treasury.account_id.value(),
                    rate_limit,
                    active_duration_sec,
                    grace_period_duration_sec,
                },
            );
            plan.inspect(clock, clock.program_account_id, &Effect::ClockIs(now_ms));
            plan.effect(
                membership,
                &Effect::InitMembership(MembershipState {
                    rate_limit,
                    id_commitment,
                    grace_period_start_timestamp_ms: now_ms
                        .saturating_add(secs_to_millis(active_duration_sec)),
                    active_duration_sec,
                    grace_period_duration_sec,
                }),
            );
            plan.call(native_payment(
                payer,
                treasury,
                calculate_payment_amount(rate_limit, price_per_unit),
            ));
            // The tree picks the index (its `next_index`) and refuses a full
            // tree; nothing here names one, so registrations planned against
            // the same tree state do not contend.
            plan.call(merkle_call(
                merkle_program_id,
                tree_main,
                &tree_id,
                &MerkleInstruction::Insert {
                    leaf: compute_registration_leaf(&id_commitment, rate_limit),
                },
            ));
        }
        Instruction::Slash {
            tree_id,
            id_commitment,
            identity_secret,
            merkle_program_id,
            leaf_index,
            rate_limit,
        } => {
            let [config, tree_main, membership] = accounts(input, "Slash");
            validate_field_element(&identity_secret);
            assert_eq!(
                hash_single(&identity_secret),
                id_commitment,
                "id_commitment arg must match hash(identity_secret)"
            );
            require_own_pda(input, config, config_seed(&tree_id), "config");
            require_tree_main(input, tree_main, &tree_id, &merkle_program_id);
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
                    merkle_program_id,
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
            // `leaf_index` is a hint; the merkle apply removes it only if it
            // holds this membership's leaf, whose `rate_limit` the membership
            // apply has just asserted.
            plan.call(merkle_call(
                merkle_program_id,
                tree_main,
                &tree_id,
                &MerkleInstruction::Remove {
                    index: leaf_index,
                    leaf: compute_registration_leaf(&id_commitment, rate_limit),
                },
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
            plan.effect(membership, &Effect::ExtendMembership { now_ms, rate_limit });
            plan.call(native_payment(
                payer,
                treasury,
                calculate_payment_amount(rate_limit, price_per_unit),
            ));
        }
        Instruction::Erase {
            tree_id,
            id_commitment,
            merkle_program_id,
            leaf_index,
            rate_limit,
            now_ms,
        } => {
            let [config, tree_main, membership, clock] = accounts(input, "Erase");
            require_own_pda(input, config, config_seed(&tree_id), "config");
            require_tree_main(input, tree_main, &tree_id, &merkle_program_id);
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
                    merkle_program_id,
                    rate_limit,
                },
            );
            plan.inspect(clock, clock.program_account_id, &Effect::ClockIs(now_ms));
            plan.effect(membership, &Effect::EraseMembership { now_ms, rate_limit });
            // As for Slash: the index is checked by content.
            plan.call(merkle_call(
                merkle_program_id,
                tree_main,
                &tree_id,
                &MerkleInstruction::Remove {
                    index: leaf_index,
                    leaf: compute_registration_leaf(&id_commitment, rate_limit),
                },
            ));
        }
    }
    plan
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

/// The config is the only source of the callee program id: the claimed
/// `merkle_program_id` that a chained call targets, with this program's
/// `main` PDA seed attached, must be the one stored at initialization.
fn assert_config_ids(config: &ConfigState, tree_id: &[u8; 32], merkle_program_id: &[u8; 32]) {
    assert!(config.tree_id == *tree_id, "tree_id arg must match config");
    assert!(
        config.merkle_program_id == *merkle_program_id,
        "merkle_program_id claim must match config"
    );
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
        Effect::InitTreeGuard {
            tree_id,
            merkle_program_id,
        } => {
            assert_config_ids(&decode_config(pre_data), &tree_id, &merkle_program_id);
            None
        }
        Effect::RegisterConfig {
            tree_id,
            merkle_program_id,
            price_per_unit,
            treasury,
            rate_limit,
            active_duration_sec,
            grace_period_duration_sec,
        } => {
            let mut config = decode_config(pre_data);
            assert_config_ids(&config, &tree_id, &merkle_program_id);
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
            config.total_registrations = config.total_registrations.saturating_add(1);
            config.current_total_rate_limit =
                config.current_total_rate_limit.saturating_add(rate_limit);
            Some(encode(&config))
        }
        // One-shot, and the only duplicate-registration guard: the membership
        // PDA is derived from the id_commitment, and neither the register plan
        // nor the merkle insert dedupes. Weaken this check and re-registering
        // a commitment silently overwrites its membership.
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
            merkle_program_id,
            rate_limit,
        } => {
            let mut config = decode_config(pre_data);
            assert_config_ids(&config, &tree_id, &merkle_program_id);
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
            assert!(config.tree_id == tree_id, "tree_id arg must match config");
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
        Effect::ExtendMembership { now_ms, rate_limit } => {
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
    use rln_layouts::CLOCK_50_ACCOUNT_ID_BYTES;

    use super::*;

    const SELF_ID: [u8; 32] = [0xA1; 32];
    const MERKLE: [u8; 32] = [0xB2; 32];
    const TREE_ID: [u8; 32] = [0x07; 32];
    const TREASURY: [u8; 32] = [0x77; 32];
    const PAYER: [u8; 32] = [0x55; 32];
    const PRICE: u128 = 10;
    const ACTIVE_SEC: u32 = 100;
    const GRACE_SEC: u32 = 50;
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

    fn tree_main_meta() -> AccountMeta {
        AccountMeta::new(pda_of(main_seed(&TREE_ID)), false, AccountId::new(MERKLE))
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
            merkle_program_id: MERKLE,
            tree_id: TREE_ID,
            price_per_unit: PRICE,
            treasury_account_id: TREASURY,
            total_registrations: 3,
            max_total_rate_limit: 1_000,
            current_total_rate_limit: 600,
            active_duration_for_new_memberships_sec: ACTIVE_SEC,
            grace_period_duration_for_new_memberships_sec: GRACE_SEC,
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
            merkle_program_id: MERKLE,
            now_ms: NOW_MS,
            price_per_unit: PRICE,
            active_duration_sec: ACTIVE_SEC,
            grace_period_duration_sec: GRACE_SEC,
        }
    }

    fn register_accounts() -> Vec<AccountMeta> {
        vec![
            config_meta(),
            tree_main_meta(),
            payer_meta(true),
            treasury_meta(),
            clock_meta(),
            membership_meta(),
        ]
    }

    fn expected_merkle(ix: &MerkleInstruction) -> ChainedCall {
        ChainedCall::new(
            AccountId::new(MERKLE),
            vec![ProgramShardSelector::new(
                tree_main_meta().account_id,
                AccountId::new(MERKLE),
            )],
            ix,
        )
        .with_pda_seeds(vec![PdaSeed::new(main_seed(&TREE_ID))])
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
            main_seed(&TREE_ID),
            combine_seeds(&[&label_seed("main"), &TREE_ID])
        );
        assert_eq!(
            membership_seed(&TREE_ID, &[1; 32]),
            combine_seeds(&[&label_seed("membership"), &TREE_ID, &[1; 32]])
        );
    }

    // ─── plan ──────────────────────────────────────────────────────────

    #[test]
    fn plan_initialize_emits_init_config() {
        let input = input(vec![config_meta()]);
        let plan = plan(
            &input,
            Instruction::Initialize {
                merkle_program_id: MERKLE,
                tree_id: TREE_ID,
                price_per_unit: PRICE,
                treasury_account_id: TREASURY,
                max_total_rate_limit: 1_000,
                active_duration_for_new_memberships_sec: ACTIVE_SEC,
                grace_period_duration_for_new_memberships_sec: GRACE_SEC,
            },
        );
        let mut state = config_state();
        state.total_registrations = 0;
        state.current_total_rate_limit = 0;
        assert_eq!(
            plan.output().effects,
            vec![ShardEffect::new(&config_meta(), &Effect::InitConfig(state))]
        );
        assert!(plan.output().chained_calls.is_empty());
    }

    #[test]
    #[should_panic(expected = "Wrong config PDA")]
    fn plan_initialize_rejects_foreign_config_pda() {
        let config = AccountMeta::new(AccountId::new([9; 32]), false, self_id());
        let _ = plan(
            &input(vec![config]),
            Instruction::Initialize {
                merkle_program_id: MERKLE,
                tree_id: TREE_ID,
                price_per_unit: PRICE,
                treasury_account_id: TREASURY,
                max_total_rate_limit: 1_000,
                active_duration_for_new_memberships_sec: ACTIVE_SEC,
                grace_period_duration_for_new_memberships_sec: GRACE_SEC,
            },
        );
    }

    #[test]
    fn plan_initialize_merkle_tree_guards_config_then_calls_merkle() {
        let plan = plan(
            &input(vec![config_meta(), tree_main_meta()]),
            Instruction::InitializeMerkleTree {
                tree_id: TREE_ID,
                merkle_program_id: MERKLE,
            },
        );
        assert_eq!(
            plan.output().effects,
            vec![ShardEffect::new(
                &config_meta(),
                &Effect::InitTreeGuard {
                    tree_id: TREE_ID,
                    merkle_program_id: MERKLE
                }
            )]
        );
        assert_eq!(
            plan.output().chained_calls,
            vec![expected_merkle(&MerkleInstruction::Initialize)]
        );
    }

    #[test]
    #[should_panic(expected = "tree_main must select the merkle program's shard")]
    fn plan_initialize_merkle_tree_rejects_tree_main_of_other_program() {
        let tree_main = AccountMeta::new(
            pda_of(main_seed(&TREE_ID)),
            false,
            AccountId::new([0xEE; 32]),
        );
        let _ = plan(
            &input(vec![config_meta(), tree_main]),
            Instruction::InitializeMerkleTree {
                tree_id: TREE_ID,
                merkle_program_id: MERKLE,
            },
        );
    }

    #[test]
    fn plan_register_emits_effects_payment_then_insert() {
        let plan = plan(&input(register_accounts()), register_ix());
        let out = plan.output();
        assert_eq!(
            out.effects,
            vec![
                ShardEffect::new(
                    &config_meta(),
                    &Effect::RegisterConfig {
                        tree_id: TREE_ID,
                        merkle_program_id: MERKLE,
                        price_per_unit: PRICE,
                        treasury: TREASURY,
                        rate_limit: RATE,
                        active_duration_sec: ACTIVE_SEC,
                        grace_period_duration_sec: GRACE_SEC,
                    }
                ),
                ShardEffect::new(&clock_meta(), &Effect::ClockIs(NOW_MS)),
                ShardEffect::new(
                    &membership_meta(),
                    &Effect::InitMembership(membership_state(NOW_MS + secs_to_millis(ACTIVE_SEC)))
                ),
            ]
        );
        assert_eq!(
            out.chained_calls,
            vec![
                expected_payment(u128::from(RATE) * PRICE),
                expected_merkle(&MerkleInstruction::Insert {
                    leaf: compute_registration_leaf(&commitment(), RATE),
                }),
            ]
        );
    }

    #[test]
    #[should_panic(expected = "id_commitment must not be zero")]
    fn plan_register_rejects_zero_commitment() {
        let Instruction::Register {
            tree_id,
            rate_limit,
            merkle_program_id,
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
            merkle_program_id,
            now_ms,
            price_per_unit,
            active_duration_sec,
            grace_period_duration_sec,
        };
        let mut accounts = register_accounts();
        accounts[5] = AccountMeta::new(
            pda_of(membership_seed(&TREE_ID, &[0u8; 32])),
            false,
            self_id(),
        );
        let _ = plan(&input(accounts), ix);
    }

    #[test]
    #[should_panic(expected = "Payer must authorize payment")]
    fn plan_register_rejects_unauthorized_payer() {
        let mut accounts = register_accounts();
        accounts[2] = payer_meta(false);
        let _ = plan(&input(accounts), register_ix());
    }

    #[test]
    #[should_panic(expected = "Wrong clock account")]
    fn plan_register_rejects_wrong_clock() {
        let mut accounts = register_accounts();
        accounts[4] = AccountMeta::new(
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
        accounts[5] = AccountMeta::new(
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
        accounts[5].program_account_id = AccountId::new(MERKLE);
        let _ = plan(&input(accounts), register_ix());
    }

    #[test]
    #[should_panic(expected = "exactly 6 accounts")]
    fn plan_register_rejects_wrong_account_count() {
        let mut accounts = register_accounts();
        accounts.pop();
        let _ = plan(&input(accounts), register_ix());
    }

    #[test]
    fn plan_slash_releases_and_removes() {
        let plan = plan(
            &input(vec![config_meta(), tree_main_meta(), membership_meta()]),
            Instruction::Slash {
                tree_id: TREE_ID,
                id_commitment: commitment(),
                identity_secret: secret(),
                merkle_program_id: MERKLE,
                leaf_index: 5,
                rate_limit: RATE,
            },
        );
        assert_eq!(
            plan.output().effects,
            vec![
                ShardEffect::new(
                    &config_meta(),
                    &Effect::ReleaseConfig {
                        tree_id: TREE_ID,
                        merkle_program_id: MERKLE,
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
        assert_eq!(
            plan.output().chained_calls,
            vec![expected_merkle(&MerkleInstruction::Remove {
                index: 5,
                leaf: compute_registration_leaf(&commitment(), RATE),
            })]
        );
    }

    #[test]
    #[should_panic(expected = "must match hash(identity_secret)")]
    fn plan_slash_rejects_wrong_secret() {
        let mut wrong = secret();
        wrong[1] = 1;
        let _ = plan(
            &input(vec![config_meta(), tree_main_meta(), membership_meta()]),
            Instruction::Slash {
                tree_id: TREE_ID,
                id_commitment: commitment(),
                identity_secret: wrong,
                merkle_program_id: MERKLE,
                leaf_index: 5,
                rate_limit: RATE,
            },
        );
    }

    #[test]
    fn plan_extend_charges_the_registration_price() {
        let plan = plan(
            &input(vec![
                config_meta(),
                membership_meta(),
                payer_meta(true),
                treasury_meta(),
                clock_meta(),
            ]),
            Instruction::Extend {
                tree_id: TREE_ID,
                id_commitment: commitment(),
                now_ms: NOW_MS,
                price_per_unit: PRICE,
                rate_limit: RATE,
            },
        );
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
                        rate_limit: RATE
                    }
                ),
            ]
        );
        assert_eq!(
            plan.output().chained_calls,
            vec![expected_payment(u128::from(RATE) * PRICE)]
        );
    }

    #[test]
    #[should_panic(expected = "Payer must authorize payment")]
    fn plan_extend_rejects_unauthorized_payer() {
        let _ = plan(
            &input(vec![
                config_meta(),
                membership_meta(),
                payer_meta(false),
                treasury_meta(),
                clock_meta(),
            ]),
            Instruction::Extend {
                tree_id: TREE_ID,
                id_commitment: commitment(),
                now_ms: NOW_MS,
                price_per_unit: PRICE,
                rate_limit: RATE,
            },
        );
    }

    #[test]
    fn plan_erase_releases_and_removes() {
        let plan = plan(
            &input(vec![
                config_meta(),
                tree_main_meta(),
                membership_meta(),
                clock_meta(),
            ]),
            Instruction::Erase {
                tree_id: TREE_ID,
                id_commitment: commitment(),
                merkle_program_id: MERKLE,
                leaf_index: 5,
                rate_limit: RATE,
                now_ms: NOW_MS,
            },
        );
        assert_eq!(
            plan.output().effects,
            vec![
                ShardEffect::new(
                    &config_meta(),
                    &Effect::ReleaseConfig {
                        tree_id: TREE_ID,
                        merkle_program_id: MERKLE,
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
        assert_eq!(
            plan.output().chained_calls,
            vec![expected_merkle(&MerkleInstruction::Remove {
                index: 5,
                leaf: compute_registration_leaf(&commitment(), RATE),
            })]
        );
    }

    #[test]
    #[should_panic(expected = "clock program's shard")]
    fn plan_erase_rejects_foreign_clock_shard() {
        let mut clock = clock_meta();
        clock.program_account_id = self_id();
        let _ = plan(
            &input(vec![
                config_meta(),
                tree_main_meta(),
                membership_meta(),
                clock,
            ]),
            Instruction::Erase {
                tree_id: TREE_ID,
                id_commitment: commitment(),
                merkle_program_id: MERKLE,
                leaf_index: 5,
                rate_limit: RATE,
                now_ms: NOW_MS,
            },
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

    #[test]
    fn apply_init_tree_guard_keeps_config() {
        let out = apply(
            Effect::InitTreeGuard {
                tree_id: TREE_ID,
                merkle_program_id: MERKLE,
            },
            &config_bytes(),
        );
        assert!(out.is_none());
    }

    /// The claimed callee id is checked against config before the merkle
    /// program ever holds the `main` seed.
    #[test]
    #[should_panic(expected = "merkle_program_id claim must match config")]
    fn apply_init_tree_guard_rejects_caller_named_program() {
        let _ = apply(
            Effect::InitTreeGuard {
                tree_id: TREE_ID,
                merkle_program_id: [0xEE; 32],
            },
            &config_bytes(),
        );
    }

    fn register_config(
        f: impl FnOnce(&mut [u8; 32], &mut u128, &mut [u8; 32], &mut u32, &mut u32),
    ) -> Effect {
        let (mut merkle, mut price, mut treasury, mut active, mut grace) =
            (MERKLE, PRICE, TREASURY, ACTIVE_SEC, GRACE_SEC);
        f(
            &mut merkle,
            &mut price,
            &mut treasury,
            &mut active,
            &mut grace,
        );
        Effect::RegisterConfig {
            tree_id: TREE_ID,
            merkle_program_id: merkle,
            price_per_unit: price,
            treasury,
            rate_limit: RATE,
            active_duration_sec: active,
            grace_period_duration_sec: grace,
        }
    }

    #[test]
    fn apply_register_config_counts_the_member() {
        let out = apply(register_config(|_, _, _, _, _| {}), &config_bytes()).unwrap();
        let mut expected = config_state();
        expected.total_registrations = 4;
        expected.current_total_rate_limit = 800;
        assert_eq!(out, encode(&expected));
    }

    #[test]
    #[should_panic(expected = "merkle_program_id claim")]
    fn apply_register_config_rejects_wrong_merkle_claim() {
        let _ = apply(
            register_config(|m, _, _, _, _| *m = [0; 32]),
            &config_bytes(),
        );
    }

    #[test]
    #[should_panic(expected = "price_per_unit claim")]
    fn apply_register_config_rejects_underpriced_claim() {
        let _ = apply(register_config(|_, p, _, _, _| *p = 0), &config_bytes());
    }

    #[test]
    #[should_panic(expected = "Wrong treasury")]
    fn apply_register_config_rejects_wrong_treasury() {
        let _ = apply(register_config(|_, _, t, _, _| *t = PAYER), &config_bytes());
    }

    #[test]
    #[should_panic(expected = "active_duration_sec claim")]
    fn apply_register_config_rejects_wrong_active_duration() {
        let _ = apply(register_config(|_, _, _, a, _| *a += 1), &config_bytes());
    }

    #[test]
    #[should_panic(expected = "grace_period_duration_sec claim")]
    fn apply_register_config_rejects_wrong_grace_duration() {
        let _ = apply(register_config(|_, _, _, _, g| *g += 1), &config_bytes());
    }

    #[test]
    #[should_panic(expected = "Would exceed max total rate limit")]
    fn apply_register_config_rejects_over_capacity() {
        let mut full = config_state();
        full.current_total_rate_limit = 900;
        let _ = apply(register_config(|_, _, _, _, _| {}), &encode(&full));
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
                merkle_program_id: MERKLE,
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
                merkle_program_id: MERKLE,
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

    #[test]
    fn apply_extend_membership_advances_one_period() {
        let start = NOW_MS - 10;
        let out = apply(
            Effect::ExtendMembership {
                now_ms: NOW_MS,
                rate_limit: RATE,
            },
            &encode(&membership_state(start)),
        )
        .unwrap();
        let expected =
            membership_state(start + secs_to_millis(GRACE_SEC) + secs_to_millis(ACTIVE_SEC));
        assert_eq!(out, encode(&expected));
    }

    #[test]
    #[should_panic(expected = "CannotExtendNonGracePeriodMembership")]
    fn apply_extend_membership_rejects_active_membership() {
        let _ = apply(
            Effect::ExtendMembership {
                now_ms: NOW_MS,
                rate_limit: RATE,
            },
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
