//! Shared Borsh-encoded state structs for the `rln_registration` program.
//!
//! The guest reads and writes these in its apply phase; the host can either
//! deserialize via `borsh::from_slice` or read individual fields by the
//! offset constants in `src/rln/constants.rs` (kept consistent with this
//! struct's field declaration order). Each lives in the registration
//! program's shard of its PDA.

use borsh::{BorshDeserialize, BorshSerialize};

/// Borsh layout for the registration program's config account.
///
/// Fixed size: 120 bytes. Field declaration order matches the byte layout
/// (Borsh encodes fixed-width primitives + fixed arrays in declaration order
/// with no length prefixes).
///
/// Offset-based readers (`src/rln/constants.rs`, and the module's own copy in
/// logos-rln-modules) resolve each field by byte position, and there is no
/// version discriminator to tell one layout from another. So a field removed
/// from the middle silently re-points every reader after it: an old config
/// read through new offsets decodes as plausible garbage — a wrong treasury,
/// a wrong price — rather than failing. Removing or reordering a field means
/// regenerating those tables in the same change, and readers should assert the
/// account's exact size before trusting any offset.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct ConfigState {
    pub tree_id: [u8; 32],
    /// Native atomic units charged per unit of rate limit.
    pub price_per_unit: u128,
    /// Plain public account the price is credited to.
    pub treasury_account_id: [u8; 32],
    pub total_registrations: u64,
    pub max_total_rate_limit: u64,
    pub current_total_rate_limit: u64,
    pub active_duration_for_new_memberships_sec: u32,
    pub grace_period_duration_for_new_memberships_sec: u32,
    /// The leaf index the next registration takes. Counts every registration
    /// ever made and never goes down (unlike `total_registrations`, which a
    /// slash or erase decrements), so an index is never reused.
    pub next_leaf_index: u64,
}

impl ConfigState {
    /// Whether `rate_limit` more units fit under `max_total_rate_limit`.
    pub fn can_register(&self, rate_limit: u64) -> bool {
        self.current_total_rate_limit.saturating_add(rate_limit) <= self.max_total_rate_limit
    }
}

/// Borsh layout for a per-member account in the registration program.
///
/// Fixed size: 56 bytes. It records no leaf index: the config assigns one at
/// registration (`ConfigState::next_leaf_index`) and the `Registered` event
/// carries it.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct MembershipState {
    pub rate_limit: u64,
    pub id_commitment: [u8; 32],
    /// Snapshotted from the config at registration.
    pub grace_period_start_timestamp_ms: u64,
    pub active_duration_sec: u32,
    pub grace_period_duration_sec: u32,
}

/// Serialized size of [`ConfigState`], in bytes.
///
/// Offset readers in the host and in `logos-lez-rln-module` assert an account
/// is exactly this long before trusting a byte offset into it. `ConfigState`
/// carries no version discriminator, so the length is the only thing that
/// distinguishes this layout from an older one.
pub const CONFIG_STATE_SIZE: usize = 120;

/// Serialized size of [`MembershipState`], in bytes.
pub const MEMBERSHIP_STATE_SIZE: usize = 56;

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the byte layout both offset tables are derived from. A field added
    /// or removed changes this number, and a reader that was not regenerated
    /// decodes the wrong bytes without erroring — so this failing is the
    /// signal to go regenerate them.
    #[test]
    fn config_state_is_the_size_its_readers_assume() {
        let config = ConfigState {
            tree_id: [2; 32],
            price_per_unit: 3,
            treasury_account_id: [4; 32],
            total_registrations: 5,
            max_total_rate_limit: 6,
            current_total_rate_limit: 7,
            active_duration_for_new_memberships_sec: 8,
            grace_period_duration_for_new_memberships_sec: 9,
            next_leaf_index: 10,
        };
        let bytes = borsh::to_vec(&config).expect("ConfigState serializes");
        assert_eq!(bytes.len(), CONFIG_STATE_SIZE);
    }

    /// Each field is recoverable at the offset its readers use. Size alone
    /// cannot catch a reorder that keeps the total the same.
    #[test]
    fn config_state_fields_sit_where_the_offset_readers_look() {
        let config = ConfigState {
            tree_id: [0xBB; 32],
            price_per_unit: 0x1122_3344_5566_7788,
            treasury_account_id: [0xCC; 32],
            total_registrations: 0x0102_0304,
            max_total_rate_limit: 0x0506_0708,
            current_total_rate_limit: 0x090A_0B0C,
            active_duration_for_new_memberships_sec: 0x0D0E,
            grace_period_duration_for_new_memberships_sec: 0x0F10,
            next_leaf_index: 0x1112_1314,
        };
        let b = borsh::to_vec(&config).expect("ConfigState serializes");
        assert_eq!(&b[0..32], &[0xBB; 32], "tree_id @0");
        assert_eq!(
            u128::from_le_bytes(b[32..48].try_into().unwrap()),
            0x1122_3344_5566_7788,
            "price_per_unit @32",
        );
        assert_eq!(&b[48..80], &[0xCC; 32], "treasury_account_id @48");
        assert_eq!(
            u64::from_le_bytes(b[80..88].try_into().unwrap()),
            0x0102_0304,
            "total_registrations @80",
        );
        assert_eq!(
            u64::from_le_bytes(b[88..96].try_into().unwrap()),
            0x0506_0708,
            "max_total_rate_limit @88",
        );
        assert_eq!(
            u64::from_le_bytes(b[96..104].try_into().unwrap()),
            0x090A_0B0C,
            "current_total_rate_limit @96",
        );
        assert_eq!(
            u32::from_le_bytes(b[104..108].try_into().unwrap()),
            0x0D0E,
            "active_duration_sec @104",
        );
        assert_eq!(
            u32::from_le_bytes(b[108..112].try_into().unwrap()),
            0x0F10,
            "grace_period_duration_sec @108",
        );
        assert_eq!(
            u64::from_le_bytes(b[112..120].try_into().unwrap()),
            0x1112_1314,
            "next_leaf_index @112",
        );
    }

    #[test]
    fn membership_state_is_the_size_its_readers_assume() {
        let membership = MembershipState {
            rate_limit: 2,
            id_commitment: [3; 32],
            grace_period_start_timestamp_ms: 4,
            active_duration_sec: 5,
            grace_period_duration_sec: 6,
        };
        let bytes = borsh::to_vec(&membership).expect("MembershipState serializes");
        assert_eq!(bytes.len(), MEMBERSHIP_STATE_SIZE);
    }
}
