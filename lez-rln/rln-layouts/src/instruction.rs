//! Shared `Instruction` enum for the RLN registration program.
//!
//! Defined once and consumed by the guest (decoded in its plan phase) and the
//! host when building transactions.
//!
//! Borsh encodes a variant as its DECLARATION INDEX, so removing or reordering
//! a variant re-numbers every variant after it. A host built against one
//! revision of this enum and a guest built against another agree on the bytes
//! and disagree on their meaning, silently. Move the two together. The current
//! order is `Initialize = 0, Register = 1, Slash = 2, Extend = 3, Erase = 4`
//! (pinned by a test below).
//!
//! # Claimed values
//!
//! A program's plan phase sees account ids and authorization flags, never
//! account data. Every value a handler used to read from an account — the
//! clock's timestamp, the config's price, a membership's rate limit and
//! expiry — therefore travels in the instruction as a CLAIM, and the apply
//! phase that does see the account asserts the claim against the stored
//! bytes. A wrong claim fails the transaction, and a failed transaction emits
//! no events (`crate::events`), so every value an event carries is one some
//! apply has asserted.
//!
//! # Leaf index
//!
//! There is no on-chain tree, but the chain assigns leaf indices: the config
//! counts registrations in `next_leaf_index`, `Register` claims it, and the
//! `Registered` event carries it. Two registrations built from the same
//! config therefore claim the same index; the one that lands second fails
//! with `EXIT_STALE_LEAF_INDEX` and must be rebuilt from the new config.
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
    Register {
        tree_id: [u8; 32],
        /// A BN254 field element, non-zero.
        id_commitment: [u8; 32],
        rate_limit: u64,
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
        /// Claim: the config's `next_leaf_index`, asserted by the config
        /// apply. The `Registered` event carries it.
        leaf_index: u64,
    },
    Slash {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        identity_secret: [u8; 32],
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
        /// Claim: the membership's expiry AFTER this extension
        /// (`crate::expiry_ms` of the extended grace start), asserted by the
        /// membership apply. The `Extended` event carries it.
        expiry_timestamp_ms: u64,
    },
    Erase {
        tree_id: [u8; 32],
        id_commitment: [u8; 32],
        /// Claim: the membership's `rate_limit`, asserted by the membership apply.
        rate_limit: u64,
        /// Claim: `CLOCK_50`'s timestamp, asserted against the clock shard.
        now_ms: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins each variant's borsh tag: the host and the guest must agree on it.
    #[test]
    fn variant_tags_are_pinned() {
        let tag = |ix: Instruction| borsh::to_vec(&ix).unwrap()[0];
        let id = [0; 32];
        assert_eq!(
            tag(Instruction::Initialize {
                tree_id: id,
                price_per_unit: 0,
                treasury_account_id: id,
                max_total_rate_limit: 0,
                active_duration_for_new_memberships_sec: 0,
                grace_period_duration_for_new_memberships_sec: 0,
            }),
            0
        );
        assert_eq!(
            tag(Instruction::Register {
                tree_id: id,
                id_commitment: id,
                rate_limit: 0,
                now_ms: 0,
                price_per_unit: 0,
                active_duration_sec: 0,
                grace_period_duration_sec: 0,
                leaf_index: 0,
            }),
            1
        );
        assert_eq!(
            tag(Instruction::Slash {
                tree_id: id,
                id_commitment: id,
                identity_secret: id,
                rate_limit: 0,
            }),
            2
        );
        assert_eq!(
            tag(Instruction::Extend {
                tree_id: id,
                id_commitment: id,
                now_ms: 0,
                price_per_unit: 0,
                rate_limit: 0,
                expiry_timestamp_ms: 0,
            }),
            3
        );
        assert_eq!(
            tag(Instruction::Erase {
                tree_id: id,
                id_commitment: id,
                rate_limit: 0,
                now_ms: 0,
            }),
            4
        );
    }
}
