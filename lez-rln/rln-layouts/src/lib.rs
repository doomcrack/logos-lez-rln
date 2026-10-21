//! Shared layouts for RLN registration.
//!
//! This crate provides the registration program's Borsh `Instruction` enum,
//! its account state, and the events it emits — everything the host, the
//! guest and event readers must agree on byte for byte.
//!
//! # no_std Support
//!
//! This crate is `no_std` compatible. Disable the default `std` feature for
//! embedded or zkVM guest environments:
//!
//! ```toml
//! rln-layouts = { path = "../rln-layouts", default-features = false }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use bytemuck::{Pod, Zeroable};

pub mod spel_pda;
pub use spel_pda::{combine_seeds, label_seed, u32_seed};

pub mod state;
pub use state::{ConfigState, MembershipState};

pub mod instruction;
pub use instruction::Instruction;

pub mod events;

pub mod exit;

// ============================================================================
// Rate Limit Constraints
// ============================================================================

/// Minimum allowed rate limit for registration.
pub const MIN_RATE_LIMIT: u64 = 100;

/// Maximum allowed rate limit for registration.
pub const MAX_RATE_LIMIT: u64 = 600;

// ============================================================================
// Clock Account
// ============================================================================

/// Raw bytes of the CLOCK_50 system account ID, updated by the sequencer every
/// 50 blocks. This crate mirrors the constant instead of depending on
/// `clock_core` to stay `no_std`-friendly for the host side.
pub const CLOCK_50_ACCOUNT_ID_BYTES: [u8; 32] = *b"/LEZ/ClockProgramAccount/0000050";

/// Prefix `lee_core::AccountId::from_builtin_program_name` hashes ahead of a
/// builtin program's name. Mirrored here so the host tooling and the guests
/// can name a builtin's shard without depending on `lee_core`.
pub const BUILTIN_PROGRAM_NAME_PREFIX: [u8; 32] = *b"/LEE-BuiltinProgram/v1/AccountId";

/// Account id of a builtin program addressed by name:
/// `SHA-256(BUILTIN_PROGRAM_NAME_PREFIX || name)`.
pub fn builtin_program_account_id(name: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(BUILTIN_PROGRAM_NAME_PREFIX);
    h.update(name);
    h.finalize().into()
}

/// The clock program's account id — the shard on `CLOCK_50` that holds
/// `ClockAccountData`.
pub fn clock_program_account_id() -> [u8; 32] {
    builtin_program_account_id(b"clock")
}

/// How far BEHIND `CLOCK_50`'s timestamp a claimed `now_ms` may be.
///
/// `CLOCK_50` moves in steps, once per 50 blocks: 750 s at testnet's 15 s
/// blocks. A client reads it, builds a transaction, and the step may land
/// before inclusion; an equality claim then reverts a perfectly honest
/// register. 900 s covers one step plus 20% for block-time jitter; a claim
/// two steps stale is refused (`EXIT_STALE_CLOCK`) and the client re-reads.
///
/// The claim, not the chain's clock, is what a membership is dated by, so
/// the tolerance is how much EARLIER than the chain's time a membership may
/// be dated: the member's active window starts (and ends) up to 15 minutes
/// early, which only shortens their own membership. A claim AHEAD of the
/// clock — the one direction that would lengthen it — is refused outright.
/// Erase judges expiry at the claim, so an older claim only makes erasing
/// harder; extend may land up to the tolerance after a grace period closed.
pub const CLOCK_CLAIM_TOLERANCE_MS: u64 = 900_000;

pub const MILLIS_PER_SECOND: u64 = 1_000;

#[inline]
pub const fn secs_to_millis(secs: u32) -> u64 {
    secs as u64 * MILLIS_PER_SECOND
}

// ============================================================================
// Expiration helpers
// ============================================================================

/// Returns true iff `now_ms` falls inside
/// `[grace_start_ms, grace_start_ms + grace_duration_ms)`.
#[inline]
pub fn is_in_grace_period(grace_start_ms: u64, grace_duration_ms: u64, now_ms: u64) -> bool {
    grace_start_ms <= now_ms && now_ms < grace_start_ms.saturating_add(grace_duration_ms)
}

/// Returns true iff `now_ms >= grace_start_ms + grace_duration_ms`.
#[inline]
pub fn is_expired(grace_start_ms: u64, grace_duration_ms: u64, now_ms: u64) -> bool {
    now_ms >= expiry_ms(grace_start_ms, grace_duration_ms)
}

/// A membership's expiry: the end of its grace period, the instant from which
/// [`is_expired`] holds. The `expiry_timestamp_ms` the events carry.
#[inline]
pub const fn expiry_ms(grace_start_ms: u64, grace_duration_ms: u64) -> u64 {
    grace_start_ms.saturating_add(grace_duration_ms)
}

// ============================================================================
// Helper Types for Unaligned Integer Access
// ============================================================================

macro_rules! le_int {
    ($name:ident, $int:ty, $n:expr) => {
        #[repr(C, packed)]
        #[derive(Clone, Copy, Pod, Zeroable, Debug, Default)]
        pub struct $name(pub [u8; $n]);

        impl $name {
            #[inline]
            pub fn get(&self) -> $int {
                <$int>::from_le_bytes(self.0)
            }
        }
    };
}

le_int!(U32Le, u32, 4);
le_int!(U64Le, u64, 8);
le_int!(U128Le, u128, 16);

/// `lee_core`'s per-shard data cap (`DATA_MAX_LENGTH`).
pub const SHARD_MAX_BYTES: usize = 100 * 1024;
