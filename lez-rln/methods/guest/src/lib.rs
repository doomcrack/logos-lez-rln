//! Guest crate for the RLN registration zkVM program.
//!
//! [`program`] holds the program's plan and apply; the binary in `src/bin/`
//! wires them into `run_program`.

pub mod fail;
pub mod hash;
pub mod layouts;
pub mod program;
pub mod registration;
