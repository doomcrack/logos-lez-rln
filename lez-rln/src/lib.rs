//! Host-side library for the RLN (Rate Limiting Nullifier) zkVM program.
//!
//! Companion code lives in two other places:
//! - `methods/guest/src/bin/` — the `rln_registration` zkVM guest program, compiled to RISC-V. It
//!   keeps no membership tree; it emits one event per successful action.
//! - `src/bin/` — host CLIs (`run_setup`, `register_member`, `run_rln_proof`) that drive a live
//!   sequencer using the helpers in this library.
//!
//! [`zone`] rebuilds the membership tree from the program's events.

pub mod fr_bytes;
pub mod proof_circuit;
pub mod rln;
pub mod spel_seeds;
pub mod zone;

#[cfg(all(test, feature = "rc5-state-tests"))]
mod cycle_harness;
#[cfg(all(test, feature = "rc5-state-tests"))]
mod state_tests;
