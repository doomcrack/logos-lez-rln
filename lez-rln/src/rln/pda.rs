//! Program-Derived Account derivations for the RLN registration program.
//!
//! Every PDA address is `compute_pda(SHA-256(seed_1 || seed_2 || ...))` where
//! each seed is a 32-byte value: string labels are zero-padded, `u32` args are
//! little-endian in the first 4 bytes, 32-byte args pass through.

use nssa::AccountId;

pub use crate::spel_seeds::{combine_seeds, derive_pda, label_seed};

/// Config account: `seeds = [literal("config"), arg("tree_id")]`.
pub fn derive_config_account(program_id: &AccountId, tree_id: &[u8; 32]) -> AccountId {
    derive_pda(program_id, &[&label_seed("config"), tree_id])
}

/// Membership account: `seeds = [literal("membership"), arg("tree_id"), arg("id_commitment")]`.
pub fn derive_membership_account(
    program_id: &AccountId,
    tree_id: &[u8; 32],
    id_commitment: &[u8; 32],
) -> AccountId {
    derive_pda(
        program_id,
        &[&label_seed("membership"), tree_id, id_commitment],
    )
}

/// Raw seed bytes for the membership PDA (used as `pda_seeds` in chained calls).
pub fn membership_pda_seed(tree_id: &[u8; 32], id_commitment: &[u8; 32]) -> [u8; 32] {
    combine_seeds(&[&label_seed("membership"), tree_id, id_commitment])
}

#[cfg(test)]
mod tests {
    use nssa_core::program::PdaSeed;

    use super::*;

    fn mock_program_id() -> AccountId {
        AccountId::new([1u8; 32])
    }

    fn tree_id_a() -> [u8; 32] {
        let mut t = [0u8; 32];
        t[0] = 7;
        t
    }

    #[test]
    fn pda_derivation_is_deterministic() {
        let p = mock_program_id();
        let t = tree_id_a();
        assert_eq!(derive_config_account(&p, &t), derive_config_account(&p, &t));
        assert_eq!(
            derive_membership_account(&p, &t, &[2u8; 32]),
            derive_membership_account(&p, &t, &[2u8; 32]),
        );
    }

    #[test]
    fn different_tree_ids_produce_different_pdas() {
        let p = mock_program_id();
        let mut t2 = tree_id_a();
        t2[1] = 9;
        assert_ne!(
            derive_config_account(&p, &tree_id_a()),
            derive_config_account(&p, &t2)
        );
    }

    #[test]
    fn all_pda_types_are_distinct() {
        let p = mock_program_id();
        let t = tree_id_a();
        assert_ne!(
            derive_config_account(&p, &t),
            derive_membership_account(&p, &t, &[3u8; 32]),
            "PDA types must be distinct"
        );
    }

    #[test]
    fn membership_pdas_differ_by_commitment() {
        let p = mock_program_id();
        let t = tree_id_a();
        assert_ne!(
            derive_membership_account(&p, &t, &[1u8; 32]),
            derive_membership_account(&p, &t, &[2u8; 32]),
        );
    }

    #[test]
    fn membership_pdas_differ_by_tree() {
        let p = mock_program_id();
        let mut t2 = tree_id_a();
        t2[1] = 9;
        assert_ne!(
            derive_membership_account(&p, &tree_id_a(), &[5u8; 32]),
            derive_membership_account(&p, &t2, &[5u8; 32]),
        );
    }

    #[test]
    fn membership_seed_matches_derive() {
        let p = mock_program_id();
        let t = tree_id_a();
        let id = [4u8; 32];
        let seed = membership_pda_seed(&t, &id);
        let from_seed = AccountId::for_public_pda(&p, &PdaSeed::new(seed));
        assert_eq!(from_seed, derive_membership_account(&p, &t, &id));
    }
}
