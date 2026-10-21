//! Events the registration program emits, one per successful action.
//!
//! There is no on-chain membership tree. A Zone service (or any reader)
//! rebuilds it from these events, applied in LEZ block order, whatever the
//! call depth they were emitted at:
//!
//! - `Registered` → insert `poseidon(id_commitment, rate_limit)` at `leaf_index`. The index is the
//!   config's `next_leaf_index`, claimed by the instruction and asserted on chain, so a registry's
//!   `Registered` events carry 0, 1, 2… in block order.
//! - `Slashed` → remove the member's leaf, if it is still live.
//! - `Extended` → no tree change; the reader keeps the new expiry.
//! - `Erased` → no tree change (an erased membership has already expired). A reader that still
//!   holds the leaf as live removes it defensively.
//!
//! One deployed program can serve several registries, each keyed by its
//! `tree_id` (the seed of its config and membership PDAs), so every event
//! names its registry first and a reader keeps one tree per `tree_id`. Only
//! `Registered` carries `rate_limit`; the later events name the membership by
//! `id_commitment`, and a reader takes its rate limit from the registration.
//!
//! LEZ emits events from a program's PLAN phase only, and the plan never sees
//! account data, so every field here is a value the instruction claimed and an
//! apply asserted. A transaction whose apply refuses a claim is reverted and
//! emits nothing.
//!
//! Format, as with LEZ's `bridge::Deposit`: `selector` is the first 8 bytes of
//! `sha256(SELECTOR_NAME)`, pinned as a literal so the guest never hashes;
//! `data` is the borsh encoding of the struct (fixed-width little-endian
//! fields in declaration order, no length prefixes).

use borsh::{BorshDeserialize, BorshSerialize};

/// A membership was registered.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Registered {
    /// The registry: asserted against the config the transaction wrote.
    pub tree_id: [u8; 32],
    pub id_commitment: [u8; 32],
    pub rate_limit: u64,
    /// `crate::expiry_ms` of the new membership: the end of its grace period.
    pub expiry_timestamp_ms: u64,
    /// The membership's leaf: the config's `next_leaf_index` when it
    /// registered, asserted by the config apply.
    pub leaf_index: u64,
}

/// A membership was extended by one active plus grace period.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Extended {
    /// The registry: asserted against the config the transaction wrote.
    pub tree_id: [u8; 32],
    pub id_commitment: [u8; 32],
    /// The membership's expiry after the extension.
    pub expiry_timestamp_ms: u64,
}

/// A membership was slashed: its identity secret was revealed.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Slashed {
    /// The registry: asserted against the config the transaction wrote.
    pub tree_id: [u8; 32],
    pub id_commitment: [u8; 32],
}

/// An expired membership was erased and its rate limit released.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Erased {
    /// The registry: asserted against the config the transaction wrote.
    pub tree_id: [u8; 32],
    pub id_commitment: [u8; 32],
}

macro_rules! event {
    ($name:ident, $selector_name:literal, $selector:expr) => {
        impl $name {
            pub const SELECTOR: [u8; 8] = $selector;
            pub const SELECTOR_NAME: &'static str = $selector_name;

            pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
                borsh::to_vec(self).expect(concat!(stringify!($name), " serializes"))
            }

            pub fn from_bytes(bytes: &[u8]) -> borsh::io::Result<Self> {
                borsh::from_slice(bytes)
            }
        }
    };
}

event!(
    Registered,
    "rln_registration::Registered",
    [0xb7, 0xab, 0x5a, 0xde, 0x17, 0x03, 0xcd, 0xe8]
);
event!(
    Extended,
    "rln_registration::Extended",
    [0x63, 0x1f, 0xfa, 0x56, 0x86, 0x62, 0x31, 0xd2]
);
event!(
    Slashed,
    "rln_registration::Slashed",
    [0x19, 0xe9, 0xa7, 0x83, 0xdd, 0x52, 0x1a, 0x1b]
);
event!(
    Erased,
    "rln_registration::Erased",
    [0x88, 0xaf, 0x4b, 0x20, 0xb9, 0xdc, 0xb6, 0xaa]
);

/// Any of the registration program's events, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RlnEvent {
    Registered(Registered),
    Extended(Extended),
    Slashed(Slashed),
    Erased(Erased),
}

impl RlnEvent {
    /// Decode an event by its selector. `None` for a selector this program
    /// does not emit; `Some(Err)` for a known selector with malformed data.
    pub fn decode(selector: [u8; 8], data: &[u8]) -> Option<borsh::io::Result<Self>> {
        Some(match selector {
            Registered::SELECTOR => Registered::from_bytes(data).map(Self::Registered),
            Extended::SELECTOR => Extended::from_bytes(data).map(Self::Extended),
            Slashed::SELECTOR => Slashed::from_bytes(data).map(Self::Slashed),
            Erased::SELECTOR => Erased::from_bytes(data).map(Self::Erased),
            _ => return None,
        })
    }

    /// The `(selector, data)` pair the program emits for this event.
    pub fn encode(&self) -> ([u8; 8], alloc::vec::Vec<u8>) {
        match self {
            Self::Registered(e) => (Registered::SELECTOR, e.to_bytes()),
            Self::Extended(e) => (Extended::SELECTOR, e.to_bytes()),
            Self::Slashed(e) => (Slashed::SELECTOR, e.to_bytes()),
            Self::Erased(e) => (Erased::SELECTOR, e.to_bytes()),
        }
    }

    pub fn tree_id(&self) -> [u8; 32] {
        match self {
            Self::Registered(e) => e.tree_id,
            Self::Extended(e) => e.tree_id,
            Self::Slashed(e) => e.tree_id,
            Self::Erased(e) => e.tree_id,
        }
    }

    pub fn id_commitment(&self) -> [u8; 32] {
        match self {
            Self::Registered(e) => e.id_commitment,
            Self::Extended(e) => e.id_commitment,
            Self::Slashed(e) => e.id_commitment,
            Self::Erased(e) => e.id_commitment,
        }
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    fn selector_of(name: &str) -> [u8; 8] {
        Sha256::digest(name.as_bytes())[..8].try_into().unwrap()
    }

    #[test]
    fn selectors_are_the_sha256_prefix_of_their_names() {
        assert_eq!(Registered::SELECTOR, selector_of(Registered::SELECTOR_NAME));
        assert_eq!(Extended::SELECTOR, selector_of(Extended::SELECTOR_NAME));
        assert_eq!(Slashed::SELECTOR, selector_of(Slashed::SELECTOR_NAME));
        assert_eq!(Erased::SELECTOR, selector_of(Erased::SELECTOR_NAME));
    }

    /// Readers in other languages decode these bytes by position.
    #[test]
    fn wire_formats_are_pinned() {
        let tree = [0x77; 32];
        let id = [0xAA; 32];
        let mut registered_bytes = [tree, id].concat();
        registered_bytes.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        registered_bytes.extend_from_slice(&0x1112_1314_1516_1718u64.to_le_bytes());
        registered_bytes.extend_from_slice(&0x2122_2324_2526_2728u64.to_le_bytes());
        let mut with_expiry = [tree, id].concat();
        with_expiry.extend_from_slice(&0x1112_1314_1516_1718u64.to_le_bytes());
        let without = [tree, id].concat();

        let registered = Registered {
            tree_id: tree,
            id_commitment: id,
            rate_limit: 0x0102_0304_0506_0708,
            expiry_timestamp_ms: 0x1112_1314_1516_1718,
            leaf_index: 0x2122_2324_2526_2728,
        };
        assert_eq!(registered.to_bytes(), registered_bytes);
        let extended = Extended {
            tree_id: tree,
            id_commitment: id,
            expiry_timestamp_ms: 0x1112_1314_1516_1718,
        };
        assert_eq!(extended.to_bytes(), with_expiry);
        let slashed = Slashed {
            tree_id: tree,
            id_commitment: id,
        };
        assert_eq!(slashed.to_bytes(), without);
        let erased = Erased {
            tree_id: tree,
            id_commitment: id,
        };
        assert_eq!(erased.to_bytes(), without);
    }

    #[test]
    fn decode_round_trips_and_rejects_unknown_selectors() {
        let events = [
            RlnEvent::Registered(Registered {
                tree_id: [9; 32],
                id_commitment: [1; 32],
                rate_limit: 100,
                expiry_timestamp_ms: 5,
                leaf_index: 7,
            }),
            RlnEvent::Extended(Extended {
                tree_id: [9; 32],
                id_commitment: [2; 32],
                expiry_timestamp_ms: 6,
            }),
            RlnEvent::Slashed(Slashed {
                tree_id: [9; 32],
                id_commitment: [3; 32],
            }),
            RlnEvent::Erased(Erased {
                tree_id: [9; 32],
                id_commitment: [4; 32],
            }),
        ];
        for event in events {
            let (selector, data) = event.encode();
            assert_eq!(RlnEvent::decode(selector, &data).unwrap().unwrap(), event);
        }
        assert!(RlnEvent::decode([0; 8], &[]).is_none());
        assert!(
            RlnEvent::decode(Registered::SELECTOR, &[0; 3])
                .unwrap()
                .is_err()
        );
    }
}
