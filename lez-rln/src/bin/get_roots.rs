//! Rebuild the membership tree from the registration program's events and
//! print its root.
//!
//! The tree is not on chain: this replays every event the indexer at
//! `LEZ_RLN_INDEXER_URL` holds for the program, in block order, then applies
//! the expiry step at `CLOCK_50`'s current timestamp.
//!
//! ```bash
//! source dev/env.sh && cargo run --bin get_roots
//! ```

use logos_lez_rln::{
    rln::{
        client::{init_wallet, read_clock_ms, tree_id_from_env},
        program_ids_or_exit,
    },
    zone::indexer::{indexer_url_from_env, membership_set},
};

#[tokio::main]
async fn main() {
    let tree_id = tree_id_from_env();
    let programs = program_ids_or_exit(&tree_id);
    let url = indexer_url_from_env().unwrap_or_else(|| {
        eprintln!("LEZ_RLN_INDEXER_URL must name the LEZ indexer serving the program's events");
        std::process::exit(2);
    });
    let wallet_core = init_wallet().await;

    let now_ms = read_clock_ms(&wallet_core).await;
    let set = membership_set(&url, &programs.registration, &tree_id, Some(now_ms))
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    println!("Leaves used:    {}", set.next_index());
    println!(
        "Live members:   {}",
        set.members().iter().filter(|m| m.live).count()
    );
    println!("Membership root (LE hex): {}", hex::encode(set.root()));
}
