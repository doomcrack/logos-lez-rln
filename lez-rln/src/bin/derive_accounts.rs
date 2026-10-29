//! Derive-only dump of the program id + tree-scoped PDAs for a tree id, as
//! JSON. Reuses the real derivation (no reimplemented PDA math) so a
//! deployment descriptor's `config_account` stays an honest cache of
//! `tree_id`.
//!
//! The program id is deployment state, not a function of the guest binary: it
//! comes from `LEZ_RLN_REGISTRATION_PROGRAM_ID` or the tree's
//! `programs_<tree>.json` record.
//!
//! ```bash
//! LEZ_RLN_TREE_ID_HEX=<64hex> cargo run --bin derive_accounts   # run from lez-rln/
//! ```

use logos_lez_rln::rln::{
    client::tree_id_from_env, derive_config_account, program_ids::hex_id, program_ids_or_exit,
};

fn main() {
    let tree_id = tree_id_from_env();
    let programs = program_ids_or_exit(&tree_id);
    println!(
        "{{\"registration_program_id\":\"{}\",\"config_account\":\"{}\"}}",
        hex_id(&programs.registration),
        derive_config_account(&programs.registration, &tree_id),
    );
}
