//! The membership tree, rebuilt off-chain from the registration program's
//! events.
//!
//! The program keeps no tree. Every successful `Register`, `Extend`, `Slash`
//! and `Erase` emits one `rln_layouts::events` event, and a reader applies
//! them in LEZ block order (block, then transaction index, then emission
//! order) to a [`MembershipSet`]:
//!
//! - **events** — decode the program's events from a transaction's ([`decode_transaction_events`])
//!   or from the indexer ([`indexer`]).
//! - **reader** — the derivation rules: insert on `Registered` at its leaf index, remove on
//!   `Slashed` (if live) and on expiry, re-insert on an `Extended` that lands after the reader
//!   expired the leaf, and a defensive remove on `Erased`.
//!
//! Leaf indices are assigned on chain (the config's `next_leaf_index`, which
//! `Register` claims) and carried in `Registered`; the reader checks they run
//! 0, 1, 2… per registry, which catches a missed or misordered event. Any two
//! readers that apply the same events in block order agree on every root.

mod events;
pub mod indexer;
mod reader;

pub use events::*;
pub use reader::*;
