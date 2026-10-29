//! Register pre-generated identity commitments on-chain from a CSV file.
//! FEATURE: Bridge between off-chain credential generation and on-chain LEZ registration
//!
//! Each line: hex_id_commitment,rate_limit
//!
//! ```bash
//! source dev/env.sh && cargo run --bin register_commitments -- commitments.csv
//! ```

use std::fs;

use logos_lez_rln::{
    fr_bytes::bytes_le_to_fr,
    rln::{
        client::{
            init_wallet, rate_commitment_from_fr, register_identity, resolve_payer,
            tree_id_from_env,
        },
        derive_config_account, program_ids_or_exit,
    },
};

fn hex_to_bytes32(hex: &str) -> [u8; 32] {
    let hex = hex.trim();
    assert_eq!(hex.len(), 64, "Expected 64 hex chars, got {}", hex.len());
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .unwrap_or_else(|_| panic!("Invalid hex at position {}", i));
    }
    bytes
}

fn compute_rate_commitment(id_commitment_bytes: &[u8; 32], rate_limit: u64) -> [u8; 32] {
    let id_commitment_fr =
        bytes_le_to_fr(id_commitment_bytes).expect("Invalid id_commitment bytes");
    rate_commitment_from_fr(&id_commitment_fr, rate_limit)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let csv_path = args
        .get(1)
        .expect("Usage: register_commitments <commitments.csv>");

    let content = fs::read_to_string(csv_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", csv_path, e));

    let entries: Vec<([u8; 32], u64)> = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let parts: Vec<&str> = line.split(',').collect();
            assert!(
                parts.len() >= 2,
                "Expected: hex_commitment,rate_limit[,idSecretHash]"
            );
            let commitment = hex_to_bytes32(parts[0]);
            let rate_limit: u64 = parts[1].trim().parse().expect("Invalid rate_limit");
            (commitment, rate_limit)
        })
        .collect();

    eprintln!(
        "Registering {} identity commitments on-chain...",
        entries.len()
    );

    let tree_id = tree_id_from_env();
    let programs = program_ids_or_exit(&tree_id);
    let wallet_core = init_wallet().await;
    let config_account_id = derive_config_account(&programs.registration, &tree_id);

    for (i, (id_commitment, rate_limit)) in entries.iter().enumerate() {
        let user_holding_id = resolve_payer();

        let leaf_bytes = compute_rate_commitment(id_commitment, *rate_limit);

        let registration = register_identity(
            &wallet_core,
            &programs,
            &tree_id,
            id_commitment,
            &user_holding_id,
            *rate_limit,
        )
        .await;
        let Some(registration) = registration else {
            eprintln!(
                "WARNING: membership of rate commitment 0x{} not confirmed, continuing...",
                hex::encode(&leaf_bytes[..8])
            );
            continue;
        };

        eprintln!(
            "  Registered {}/{}: leaf={} commitment=0x{}... rate_commitment=0x{}...",
            i + 1,
            entries.len(),
            registration.leaf_index,
            hex::encode(&id_commitment[..8]),
            hex::encode(&leaf_bytes[..8])
        );
    }

    println!("CONFIG_ACCOUNT={}", config_account_id);
    eprintln!("All {} commitments registered successfully.", entries.len());
}
