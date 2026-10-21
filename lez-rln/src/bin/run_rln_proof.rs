//! End-to-end RLN proof demo. Requires `run_setup` to have been run first,
//! and `LEZ_RLN_INDEXER_URL` to name an indexer serving the program's events:
//! the membership tree is rebuilt from them, not read from chain.

use logos_lez_rln::{
    fr_bytes::fr_to_bytes_le,
    rln::{
        client::{
            RlnIdentity, create_identity, init_wallet, register_identity, resolve_payer,
            tree_id_from_env, wait_account_attempts,
        },
        program_ids_or_exit,
    },
    zone::{
        indexer::{indexer_url_from_env, wait_for_member},
        proof_to_circuit,
    },
};
use rln::prelude::{Fr, Hasher, PoseidonHash, RLNWitnessInput, hash_to_field_le};

// RLN proof constants
const USER_MESSAGE_LIMIT: u64 = 100;
const MESSAGE_ID: u64 = 0;
const MESSAGE: &str = "Hello, RLN!";
const EPOCH: &str = "1231028105";
const RLN_IDENTIFIER: &str = "rln/logos-rln-relay/v2.0.0";

#[tokio::main]
async fn main() {
    let tree_id = tree_id_from_env();
    let programs = program_ids_or_exit(&tree_id);
    let indexer_url = indexer_url_from_env().unwrap_or_else(|| {
        eprintln!("LEZ_RLN_INDEXER_URL must name the LEZ indexer serving the program's events");
        std::process::exit(2);
    });
    let mut wallet_core = init_wallet().await;

    println!("=== RLN Proof Demo ===\n");

    let user_holding_id = resolve_payer();

    // Step 1: Create identity using zerokit
    println!("Step 1: Creating identity...");
    let RlnIdentity {
        identity_secret,
        id_commitment_bytes,
        leaf_bytes,
        ..
    } = create_identity(&mut wallet_core, USER_MESSAGE_LIMIT).await;
    println!(
        "  Identity commitment: {}",
        hex::encode(id_commitment_bytes)
    );

    // Step 2: Register via the registration program
    println!("\nStep 2: Registering...");
    let registration = register_identity(
        &wallet_core,
        &programs,
        &tree_id,
        &id_commitment_bytes,
        &user_holding_id,
        USER_MESSAGE_LIMIT,
    )
    .await
    .expect("Timeout waiting for the membership to appear on-chain");
    println!("  Registered at leaf index {}", registration.leaf_index);

    // Step 3: Rebuild the tree from the program's events and prove membership
    println!("\nStep 3: Rebuilding the membership tree from events...");
    let set = wait_for_member(
        &indexer_url,
        &programs.registration,
        &tree_id,
        &id_commitment_bytes,
        wait_account_attempts(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let leaf_index = set
        .leaf_index_of(&id_commitment_bytes)
        .expect("the member was just found");
    assert_eq!(
        leaf_index, registration.leaf_index,
        "the reader placed the member at another leaf than the chain assigned"
    );
    let proof = set.proof(leaf_index);
    let (merkle_proof, root) = proof_to_circuit(&proof);

    assert_eq!(
        leaf_bytes, proof.leaf,
        "Leaf mismatch - the reader's leaf is not this identity's rate commitment"
    );

    // Step 4: Generate RLN proof
    println!("\nStep 4: Generating RLN proof...");
    let user_message_limit_fr = Fr::from(USER_MESSAGE_LIMIT);
    let message_id_fr = Fr::from(MESSAGE_ID);

    let epoch_fr = hash_to_field_le(EPOCH.as_bytes());
    let rln_identifier_fr = hash_to_field_le(RLN_IDENTIFIER.as_bytes());
    let external_nullifier = Hasher::<PoseidonHash>::hash_pair(epoch_fr, rln_identifier_fr);

    let x = hash_to_field_le(MESSAGE.as_bytes());

    let witness = RLNWitnessInput::new_single()
        .identity_secret(identity_secret)
        .user_message_limit(user_message_limit_fr)
        .merkle_proof(merkle_proof)
        .x(x)
        .external_nullifier(external_nullifier)
        .message_id(message_id_fr)
        .build()
        .expect("Failed to create RLN witness");

    let rln = logos_lez_rln::proof_circuit::engine();

    let (rln_proof, proof_values) = rln
        .generate_proof(&witness)
        .expect("Failed to generate RLN proof");

    println!("  Proof generated successfully!");
    println!(
        "  Nullifier: {}",
        hex::encode(fr_to_bytes_le(
            &proof_values.nullifier().expect("single-mode proof")
        ))
    );
    println!(
        "  Root in proof: {}",
        hex::encode(fr_to_bytes_le(&proof_values.root()))
    );

    // Step 5: Verify the RLN proof
    println!("\nStep 5: Verifying RLN proof...");

    let is_valid = rln
        .verify_with_roots(&rln_proof, &proof_values, &x, &[root])
        .expect("Failed to verify proof");

    if is_valid {
        println!("  Proof verified successfully!");
    } else {
        println!("  Proof verification FAILED!");
    }

    println!("\n=== Summary ===");
    println!("Identity at leaf index: {}", leaf_index);
    println!("Membership root: {}", hex::encode(fr_to_bytes_le(&root)));
    println!("Proof valid: {}", is_valid);

    if !is_valid {
        panic!("RLN proof verification failed!");
    }
}
