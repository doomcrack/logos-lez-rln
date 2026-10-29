//! SPEL-style PDA seed primitives shared across modules.
//!
//! Leaf module with no internal dependencies. `rln::pda` builds its
//! derivations on these helpers. The seed primitives live in `rln-layouts` so
//! the guest shares them; this module re-exports them and adds the host-only
//! `derive_pda`.

use nssa::AccountId;
use nssa_core::program::PdaSeed;
pub use rln_layouts::{combine_seeds, label_seed, u32_seed};

/// Derive a PDA account ID from a program's account id and a list of 32-byte
/// seeds.
pub fn derive_pda(program_id: &AccountId, seeds: &[&[u8; 32]]) -> AccountId {
    AccountId::for_public_pda(program_id, &PdaSeed::new(combine_seeds(seeds)))
}
