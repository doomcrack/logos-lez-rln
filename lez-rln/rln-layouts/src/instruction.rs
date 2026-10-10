//! Shared `Instruction` enums for the RLN registration and merkle programs.
//!
//! Defined once and consumed by both guests (decoded in their plan phase) and
//! the host when building transactions and chained-call payloads.
//!
//! Borsh encodes a variant as its DECLARATION INDEX, so removing or reordering
//! a variant re-numbers every variant after it. A host built against one
//! revision of this enum and a guest built against another agree on the bytes
//! and disagree on their meaning, silently. Move the two together.
//!
//! # Claimed values
//!
//! A program's plan phase sees account ids and authorization flags, never
//! account data. Every value a handler used to read from an account — the
//! clock's timestamp, the config's price and callee program id, a
//! membership's rate limit — therefore travels in the instruction as a CLAIM,
//! and the apply phase that does see the account asserts the claim against
//! the stored bytes. A wrong claim fails the transaction before any chained
//! call runs, so a caller gains nothing by lying: the merkle program id named
//! here is checked against the config account before the merkle program is
//! ever handed `pda_seeds`.
//!
//! The leaf index is NOT a claim. The tree assigns it on insert (its own
//! `next_index`), so registrations built from the same chain state do not
//! contend for one index. Slash and erase carry the index as a HINT that the
//! merkle apply checks by content: the leaf there must be
//! `H(id_commitment, rate_limit)`.
//!
//! A membership is paid for in the NATIVE asset by the account that signs the
//! transaction, which is also its fee payer. There is no payment token, no
//! credit token and no faucet: no program can mint native balance, so it
//! enters an account only at genesis, over the bridge, or by transfer.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug)]
pub enum Instruction {
    Initialize {
        /// Account id of the deployed merkle program: the header account the
        /// deployer created and signed, not a hash of its bytecode.
        merkle_program_id: [u8; 32],
        tree_id: [u8; 32],
        /// Native atomic units charged per unit of rate limit.
        price_per_unit: u128,
        /// Plain public account the price is credited to. Deliberately not a
        /// PDA: a PDA is spendable only through a chained call carrying its
        /// seeds, issued by its owning program, and this program has no
        /// instruction that would issue one.
        treasury_account_id: [u8; 32],
        max_total_rate_limit: u64,
        active_duration_for_new_memberships_sec: u32,
        grace_period_duration_for_new_memberships_sec: u32,
    },
    InitializeMerkleTree {
        tree_id: [u8; 32],
        /// Claim: asserted equal to the config's `merkle_program_id`.
        merkle_program_id: [u8; 32],
    },
    Register {
        tree_id: [u8; 32],
        /// A BN254 field element, non-zero.
        id_commitment: [u8; 32],
        rate_limit: u64,
        /// Claim: asserted equal to the config's `merkle_program_id`.
        merkle_program_id: [u8; 32],
        /// Claim: `CLOCK_50`'s timestamp, asserted against the clock shard.
        now_ms: u64,
        /// Claim: the config's `price_per_unit`, asserted by the config apply.
        price_per_unit: u128,
        /// Claim: the config's `active_duration_for_new_memberships_sec`,
        /// asserted by the config apply; snapshotted into the membership.
        active_duration_sec: u32,
        /// Claim: the config's `grace_period_duration_for_new_memberships_sec`,
        /// asserted by the config apply; snapshotted into the membership.
        grace_period_duration_sec: u32,
    },
    Slash {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        identity_secret: [u8; 32],
        /// Claim: asserted equal to the config's `merkle_program_id`.
        merkle_program_id: [u8; 32],
        /// Hint: the index of the membership's leaf, found by scanning the
        /// tree. The merkle `Remove` refuses it unless it holds this member's
        /// leaf.
        leaf_index: u64,
        /// Claim: the membership's `rate_limit`, asserted by the membership apply.
        rate_limit: u64,
    },
    Extend {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        /// Claim: `CLOCK_50`'s timestamp, asserted against the clock shard.
        now_ms: u64,
        /// Claim: the config's `price_per_unit`, asserted by the config apply.
        price_per_unit: u128,
        /// Claim: the membership's `rate_limit`, asserted by the membership apply.
        rate_limit: u64,
    },
    Erase {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        /// Claim: asserted equal to the config's `merkle_program_id`.
        merkle_program_id: [u8; 32],
        /// Hint: the index of the membership's leaf, found by scanning the
        /// tree. The merkle `Remove` refuses it unless it holds this member's
        /// leaf.
        leaf_index: u64,
        /// Claim: the membership's `rate_limit`, asserted by the membership apply.
        rate_limit: u64,
        /// Claim: `CLOCK_50`'s timestamp, asserted against the clock shard.
        now_ms: u64,
    },
}

/// Instruction of the incremental merkle tree program, carried as the
/// chained-call payload from the registration program (and, in tests, sent
/// directly). The tree declares exactly one account: its main PDA, whose
/// merkle shard holds the whole tree.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum MerkleInstruction {
    Initialize,
    /// Append `leaf` at the tree's `next_index`.
    Insert {
        leaf: [u8; 32],
    },
    /// Zero the leaf at `index`, which must hold `leaf`.
    Remove {
        index: u64,
        leaf: [u8; 32],
    },
    Set {
        index: u64,
        leaf: [u8; 32],
    },
}
