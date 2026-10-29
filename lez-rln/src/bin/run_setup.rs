//! Deploy (or reuse) the registration program, record its id, and initialize
//! the RLN registry for `LEZ_RLN_TREE_ID_HEX`.
//!
//! A program named by `LEZ_RLN_REGISTRATION_PROGRAM_ID` or by the tree's
//! `programs_<tree>.json` record is reused when its header carries the local
//! binary's image id; otherwise it is deployed. Re-running against an
//! initialized registry changes nothing.
//!
//! ```bash
//! source dev/env.sh && cargo run --bin run_setup
//! ```

use logos_lez_rln::rln::{
    client::{
        init_wallet, load_program, resolve_payer, run_setup, save_payment_account, tree_id_from_env,
    },
    derive_config_account,
    program_ids::hex_id,
};

#[tokio::main]
async fn main() {
    let payer = resolve_payer();
    let mut wallet_core = init_wallet().await;
    let tree_id = tree_id_from_env();
    let registration_program = load_program();

    println!("=== RLN Setup ===\n");
    let programs = run_setup(&mut wallet_core, &registration_program, &tree_id).await;

    save_payment_account(&tree_id, &payer);
    println!("Payment account saved: {payer}");
    println!("Registration program: {}", hex_id(&programs.registration));
    println!(
        "Config account:       {}",
        derive_config_account(&programs.registration, &tree_id)
    );
}
