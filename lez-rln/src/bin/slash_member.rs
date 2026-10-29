//! Slash one RLN membership by revealing its identity secret, then wait until
//! the membership account is gone. The deposit is forfeited and the program
//! emits `Slashed`.
//!
//! ```bash
//! LEZ_RLN_ID_COMMITMENT=<64 hex> LEZ_RLN_IDENTITY_SECRET=<64 hex> \
//!     cargo run --release --bin slash_member
//! ```
//!
//! Both values are 32-byte little-endian field elements, as `register_member`
//! prints them (`ID_COMMITMENT`, `IDENTITY_SECRET_HASH`).

use logos_lez_rln::rln::{
    client::{init_wallet, read_membership, resolve_payer, slash_membership, tree_id_from_env},
    program_ids_or_exit,
};

fn hex32_from_env(name: &str) -> [u8; 32] {
    let raw = std::env::var(name).unwrap_or_else(|_| {
        eprintln!("{name} must be set (64 hex chars)");
        std::process::exit(2);
    });
    let bytes = hex::decode(raw.trim().trim_start_matches("0x")).unwrap_or_else(|e| {
        eprintln!("{name} is not hex: {e}");
        std::process::exit(2);
    });
    bytes.try_into().unwrap_or_else(|_| {
        eprintln!("{name} must be 32 bytes (64 hex chars)");
        std::process::exit(2);
    })
}

#[tokio::main]
async fn main() {
    let id_commitment = hex32_from_env("LEZ_RLN_ID_COMMITMENT");
    let identity_secret = hex32_from_env("LEZ_RLN_IDENTITY_SECRET");

    let tree_id = tree_id_from_env();
    let programs = program_ids_or_exit(&tree_id);
    let wallet_core = init_wallet().await;
    let payer = resolve_payer();

    if read_membership(&wallet_core, &programs, &tree_id, &id_commitment)
        .await
        .is_none()
    {
        eprintln!("No membership for 0x{}", hex::encode(id_commitment));
        std::process::exit(1);
    }

    slash_membership(
        &wallet_core,
        &programs,
        &tree_id,
        &identity_secret,
        &id_commitment,
        &payer,
    )
    .await;

    for _ in 0..60 {
        if read_membership(&wallet_core, &programs, &tree_id, &id_commitment)
            .await
            .is_none()
        {
            println!("SLASHED={}", hex::encode(id_commitment));
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    panic!(
        "Timeout waiting for the membership of 0x{} to disappear",
        hex::encode(id_commitment)
    );
}
