//! Exit codes the guests halt with when a check fails because the CHAIN MOVED
//! between the moment a client read it and the moment its transaction ran.
//!
//! A guest panic is charged the transaction's full declared gas; a guest that
//! halts with a non-zero exit code is charged the cycles it actually ran
//! (`LeeError::ProgramExitedWithCode { code, cycles }`). A client that built
//! an honest transaction from a slightly stale view — the clock ticked, a
//! concurrent registration took the next leaf index or the last unit of
//! capacity, someone slashed the member first — therefore pays for the work
//! done, not for the ceiling.
//!
//! Checks that only a malformed or hostile transaction can fail — wrong PDA,
//! wrong account count or shard, a non-field element, a tree id that is not
//! the stored one, an init replay — still panic: nothing about the
//! chain can make an honest client trip them, and the full charge is the
//! deterrent.
//!
//! Codes are `u8` because that is what `risc0_zkvm::guest::env::exit` takes;
//! the host sees them widened to `u32`.

/// `CLOCK_50`'s timestamp is not the claimed `now_ms`: the clock ticked.
pub const EXIT_STALE_CLOCK: u8 = 10;
/// `CLOCK_50` still carries its genesis zero.
pub const EXIT_CLOCK_NOT_INITIALIZED: u8 = 11;
/// The claimed price, treasury or membership durations are not the config's.
pub const EXIT_STALE_CONFIG: u8 = 12;
/// `rate_limit` more units no longer fit under `max_total_rate_limit`.
pub const EXIT_RATE_LIMIT_FULL: u8 = 13;
/// A membership for this `id_commitment` already exists.
pub const EXIT_MEMBERSHIP_EXISTS: u8 = 14;
/// No membership for this `id_commitment` (slashed or erased meanwhile).
pub const EXIT_MEMBERSHIP_MISSING: u8 = 15;
/// The claimed `rate_limit` is not the membership's.
pub const EXIT_STALE_RATE_LIMIT: u8 = 16;
/// Extend outside the membership's grace period.
pub const EXIT_NOT_IN_GRACE_PERIOD: u8 = 17;
/// Erase of a membership that has not expired.
pub const EXIT_NOT_EXPIRED: u8 = 18;
// 19 (LeafMismatch) and 20 (TreeFull) belonged to the on-chain merkle tree,
// which this program no longer has. Left unused rather than renumbered so a
// code in an old log keeps its meaning.
/// The claimed post-extension expiry is not the one the membership apply
/// computes (the membership was extended meanwhile).
pub const EXIT_STALE_EXPIRY: u8 = 21;
/// The claimed `leaf_index` is not the config's `next_leaf_index`: another
/// registration took it first.
pub const EXIT_STALE_LEAF_INDEX: u8 = 22;

/// The name of an exit code, for logs and error messages.
pub fn exit_code_name(code: u32) -> Option<&'static str> {
    let code = u8::try_from(code).ok()?;
    Some(match code {
        EXIT_STALE_CLOCK => "StaleClock",
        EXIT_CLOCK_NOT_INITIALIZED => "ClockNotInitialized",
        EXIT_STALE_CONFIG => "StaleConfig",
        EXIT_RATE_LIMIT_FULL => "RateLimitFull",
        EXIT_MEMBERSHIP_EXISTS => "MembershipExists",
        EXIT_MEMBERSHIP_MISSING => "MembershipMissing",
        EXIT_STALE_RATE_LIMIT => "StaleRateLimit",
        EXIT_NOT_IN_GRACE_PERIOD => "NotInGracePeriod",
        EXIT_NOT_EXPIRED => "NotExpired",
        EXIT_STALE_EXPIRY => "StaleExpiry",
        EXIT_STALE_LEAF_INDEX => "StaleLeafIndex",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_is_named_and_distinct() {
        let codes = [
            EXIT_STALE_CLOCK,
            EXIT_CLOCK_NOT_INITIALIZED,
            EXIT_STALE_CONFIG,
            EXIT_RATE_LIMIT_FULL,
            EXIT_MEMBERSHIP_EXISTS,
            EXIT_MEMBERSHIP_MISSING,
            EXIT_STALE_RATE_LIMIT,
            EXIT_NOT_IN_GRACE_PERIOD,
            EXIT_NOT_EXPIRED,
            EXIT_STALE_EXPIRY,
            EXIT_STALE_LEAF_INDEX,
        ];
        for (i, a) in codes.iter().enumerate() {
            let name = exit_code_name(u32::from(*a)).expect("every code is named");
            for b in &codes[i + 1..] {
                assert_ne!(a, b, "codes are distinct");
                assert_ne!(
                    Some(name),
                    exit_code_name(u32::from(*b)),
                    "names are distinct"
                );
            }
        }
        assert_eq!(exit_code_name(0), None);
        assert_eq!(exit_code_name(256 + u32::from(EXIT_STALE_CLOCK)), None);
    }
}
