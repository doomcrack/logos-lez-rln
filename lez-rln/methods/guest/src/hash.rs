//! The one Poseidon the program still computes: Slash checks that the
//! revealed identity secret hashes to the member's commitment. Registration
//! leaves (`poseidon(id_commitment, rate_limit)`) are hashed by readers.

use rust_poseidon_bn254_pure::{bn254::field::Felt, poseidon::permutation::compress_1};

pub fn validate_field_element(bytes: &[u8; 32]) {
    let felt = Felt::unsafe_from_le_bytes(bytes);
    assert!(
        Felt::is_valid(&felt),
        "Input is not a valid BN254 field element (must be < prime)"
    );
}

pub fn hash_single(input: &[u8; 32]) -> [u8; 32] {
    validate_field_element(input);
    let hash_felt = compress_1(Felt::unsafe_from_le_bytes(input));
    Felt::to_le_bytes(&hash_felt)
}
