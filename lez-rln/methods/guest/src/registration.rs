//! Helpers shared by the `rln_registration` program's plan and apply phases.

use nssa_core::program::AccountMeta;
use rln_layouts::exit::{EXIT_CLOCK_NOT_INITIALIZED, EXIT_STALE_CLOCK};

// Re-export rate limit and expiration constants / helpers from shared crate
use crate::ensure;
pub use crate::layouts::{
    CLOCK_50_ACCOUNT_ID_BYTES, CLOCK_CLAIM_TOLERANCE_MS, MAX_RATE_LIMIT, MIN_RATE_LIMIT,
    is_expired, is_in_grace_period,
};

// ============================================================================
// Validation
// ============================================================================

/// Validate rate limit is within allowed range.
///
/// # Panics
/// If rate_limit is below MIN_RATE_LIMIT or above MAX_RATE_LIMIT.
pub fn validate_rate_limit(rate_limit: u64) {
    assert!(
        rate_limit >= MIN_RATE_LIMIT,
        "Rate limit {} below minimum {}",
        rate_limit,
        MIN_RATE_LIMIT
    );
    assert!(
        rate_limit <= MAX_RATE_LIMIT,
        "Rate limit {} above maximum {}",
        rate_limit,
        MAX_RATE_LIMIT
    );
}

/// Price of a membership at `rate_limit`, in native atomic units.
///
/// Saturating rather than wrapping: a wrapped product would price a debit
/// against a real balance at an amount nobody asked for, while a saturated
/// one is unaffordable and the native transfer refuses it.
pub fn calculate_payment_amount(rate_limit: u64, price_per_unit: u128) -> u128 {
    price_per_unit.saturating_mul(rate_limit as u128)
}

// ============================================================================
// Clock Helpers
// ============================================================================

/// Plan side of the clock guard: `clock` must name `CLOCK_50`'s clock-program
/// shard, the only shard of that account holding `ClockAccountData`.
pub fn require_clock_account(clock: &AccountMeta) {
    assert!(
        *clock.account_id.value() == CLOCK_50_ACCOUNT_ID_BYTES,
        "Wrong clock account provided"
    );
    assert!(
        clock.program_account_id == clock_core::clock_account_id(),
        "Clock account must select the clock program's shard"
    );
}

/// Apply side of the clock guard: the claimed `now_ms` must be at most
/// `CLOCK_CLAIM_TOLERANCE_MS` behind the clock shard's timestamp, and never
/// ahead of it. An equality claim would revert any transaction that straddles
/// a `CLOCK_50` step; see the constant for why an older claim is safe.
///
/// A zero timestamp is refused: CLOCK_50 carries the genesis zero until the
/// sequencer's first refresh of it (every 50 blocks), and a membership stamped
/// from that dates its whole lifetime to 1970 and expires the instant the
/// clock is first written. No live chain reports zero, so every
/// time-dependent instruction refuses to run until the clock exists.
pub fn assert_clock_is(clock_pre_data: &[u8], now_ms: u64) {
    let timestamp = clock_core::ClockAccountData::from_bytes(clock_pre_data).timestamp;
    ensure!(
        timestamp > 0,
        EXIT_CLOCK_NOT_INITIALIZED,
        "ClockNotInitialized: CLOCK_50 has not been written yet"
    );
    ensure!(
        now_ms <= timestamp && timestamp - now_ms <= CLOCK_CLAIM_TOLERANCE_MS,
        EXIT_STALE_CLOCK,
        "Claimed now_ms {now_ms} is not within {CLOCK_CLAIM_TOLERANCE_MS} ms before \
         CLOCK_50's timestamp {timestamp}"
    );
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_rate_limit_valid() {
        validate_rate_limit(MIN_RATE_LIMIT);
        validate_rate_limit(MAX_RATE_LIMIT);
        validate_rate_limit(300);
    }

    #[test]
    #[should_panic(expected = "below minimum")]
    fn test_validate_rate_limit_too_low() {
        validate_rate_limit(MIN_RATE_LIMIT - 1);
    }

    #[test]
    #[should_panic(expected = "above maximum")]
    fn test_validate_rate_limit_too_high() {
        validate_rate_limit(MAX_RATE_LIMIT + 1);
    }

    #[test]
    fn test_calculate_payment_amount() {
        let price_per_unit = 10u128;
        let rate_limit = 100u64;
        assert_eq!(calculate_payment_amount(rate_limit, price_per_unit), 1000);

        assert_eq!(calculate_payment_amount(600, 5), 3000);
    }

    /// A price that cannot be paid is better than a price that wrapped into
    /// one that can.
    #[test]
    fn calculate_payment_amount_saturates_instead_of_wrapping() {
        assert_eq!(calculate_payment_amount(2, u128::MAX), u128::MAX);
    }

    #[test]
    fn test_is_in_grace_period_boundaries() {
        let start_ms = 1_000u64;
        let duration_ms = 100u64;
        assert!(!is_in_grace_period(start_ms, duration_ms, 999));
        assert!(is_in_grace_period(start_ms, duration_ms, 1000));
        assert!(is_in_grace_period(start_ms, duration_ms, 1099));
        assert!(!is_in_grace_period(start_ms, duration_ms, 1100));
        assert!(!is_in_grace_period(start_ms, duration_ms, 5000));
    }

    #[test]
    fn test_is_expired_boundaries() {
        let start_ms = 1_000u64;
        let duration_ms = 100u64;
        assert!(!is_expired(start_ms, duration_ms, 999));
        assert!(!is_expired(start_ms, duration_ms, 1099));
        assert!(is_expired(start_ms, duration_ms, 1100));
        assert!(is_expired(start_ms, duration_ms, 5000));
    }

    #[test]
    fn test_grace_period_zero_duration_transitions_directly_to_expired() {
        let start_ms = 1_000u64;
        assert!(!is_in_grace_period(start_ms, 0, 1_000));
        assert!(is_expired(start_ms, 0, 1_000));
    }

    fn clock_bytes(timestamp: u64) -> Vec<u8> {
        clock_core::ClockAccountData {
            block_id: 7,
            timestamp,
        }
        .to_bytes()
    }

    fn clock_meta(
        account_id: [u8; 32],
        program_account_id: nssa_core::account::AccountId,
    ) -> AccountMeta {
        AccountMeta::new(
            nssa_core::account::AccountId::new(account_id),
            false,
            program_account_id,
        )
    }

    #[test]
    fn require_clock_account_accepts_clock50_clock_shard() {
        require_clock_account(&clock_meta(
            CLOCK_50_ACCOUNT_ID_BYTES,
            clock_core::clock_account_id(),
        ));
    }

    #[test]
    #[should_panic(expected = "Wrong clock account")]
    fn require_clock_account_rejects_other_account() {
        require_clock_account(&clock_meta([9u8; 32], clock_core::clock_account_id()));
    }

    #[test]
    #[should_panic(expected = "clock program's shard")]
    fn require_clock_account_rejects_foreign_shard() {
        require_clock_account(&clock_meta(
            CLOCK_50_ACCOUNT_ID_BYTES,
            nssa_core::account::AccountId::new([3u8; 32]),
        ));
    }

    /// The host names the clock shard by `rln_layouts`' mirror of the id.
    #[test]
    fn clock_program_id_mirror_matches_clock_core() {
        assert_eq!(
            rln_layouts::clock_program_account_id(),
            *clock_core::clock_account_id().value()
        );
    }

    const T: u64 = 10_000_000;

    #[test]
    fn assert_clock_is_accepts_matching_timestamp() {
        assert_clock_is(&clock_bytes(T), T);
    }

    /// The clock stepped after the claim was read: still accepted.
    #[test]
    fn assert_clock_is_accepts_a_claim_up_to_the_tolerance_behind() {
        assert_clock_is(&clock_bytes(T), T - 1);
        assert_clock_is(&clock_bytes(T), T - CLOCK_CLAIM_TOLERANCE_MS);
    }

    #[test]
    #[should_panic(expected = "exit 10: Claimed now_ms")]
    fn assert_clock_is_rejects_a_claim_ahead_of_the_clock() {
        assert_clock_is(&clock_bytes(T), T + 1);
    }

    #[test]
    #[should_panic(expected = "exit 10: Claimed now_ms")]
    fn assert_clock_is_rejects_a_claim_older_than_the_tolerance() {
        assert_clock_is(&clock_bytes(T), T - CLOCK_CLAIM_TOLERANCE_MS - 1);
    }

    #[test]
    #[should_panic(expected = "ClockNotInitialized")]
    fn assert_clock_is_rejects_genesis_zero() {
        assert_clock_is(&clock_bytes(0), 0);
    }
}
