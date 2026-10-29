//! The registry's whole lifecycle against a LIVE sequencer: deploy, init,
//! register, prove, a refused duplicate, slash, extend, erase — with the
//! membership tree rebuilt from the program's events, as a Zone reader would.
//!
//! Skipped unless `LEZ_RLN_LOCAL_SEQUENCER` is set. `tools/e2e-local.sh`
//! boots a sequencer and an indexer with `dev.sh`, funds a payer at genesis
//! and runs this with the environment it needs:
//!
//! - `LEE_WALLET_HOME_DIR`: a wallet whose config names the local sequencer;
//! - `LEZ_RLN_PAYER`: the genesis-funded account (deploys, pays, signs);
//! - `LEZ_RLN_INDEXER_URL`: the local indexer, which serves the events;
//! - `LEZ_RLN_ACTIVE_DURATION_SECS` / `LEZ_RLN_GRACE_PERIOD_DURATION_SECS`: seconds, so extend and
//!   erase become legal within a few clock ticks.
//!
//! `CLOCK_50` moves every 50 blocks, so the two time-gated steps each wait
//! for the clock to pass a threshold rather than sleeping a fixed time. The
//! indexer trails the sequencer, so every reader check polls until the
//! events it needs have been indexed.

use std::time::Duration;

use logos_lez_rln::{
    fr_bytes::fr_to_bytes_le,
    proof_circuit::CIRCUIT_DEPTH,
    rln::{
        ProgramIds,
        client::{
            RlnIdentity, create_identity, erase_membership, extend_membership, init_wallet,
            load_program, membership_durations, membership_expiry_ms, read_clock_ms, read_config,
            read_membership, register_identity, resolve_payer, run_setup, slash_membership,
        },
    },
    zone::{
        MembershipSet, RlnEvent,
        indexer::{fetch_all_events, indexer_url_from_env, membership_set},
        proof_to_circuit,
    },
};
use nssa::AccountId;
use rln::prelude::{Fr, Hasher, PoseidonHash, RLNWitnessInput, hash_to_field_le};
use rln_layouts::secs_to_millis;
use wallet::WalletCore;

const RATE_LIMIT: u64 = 100;
const ZERO_LEAF: [u8; 32] = [0u8; 32];

/// Poll the clock until it reads at least `threshold_ms`.
async fn wait_for_clock(wallet: &WalletCore, threshold_ms: u64, what: &str) -> u64 {
    for _ in 0..600 {
        let now = read_clock_ms(wallet).await;
        if now >= threshold_ms {
            return now;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("{what}: CLOCK_50 never reached {threshold_ms}");
}

/// Poll until the membership for `id_commitment` is absent.
async fn wait_for_membership_gone(
    wallet: &WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
    id_commitment: &[u8; 32],
    what: &str,
) {
    for _ in 0..120 {
        if read_membership(wallet, programs, tree_id, id_commitment)
            .await
            .is_none()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("{what}: membership was never cleared");
}

/// Poll the indexer until it holds `count` of the registry's events, and
/// return them.
async fn wait_for_events(
    url: &str,
    program: &AccountId,
    tree_id: &[u8; 32],
    count: usize,
    what: &str,
) -> Vec<RlnEvent> {
    for _ in 0..240 {
        let events = fetch_all_events(url, program, tree_id)
            .await
            .unwrap_or_else(|e| panic!("{what}: {e}"));
        if events.len() >= count {
            assert_eq!(events.len(), count, "{what}: more events than actions");
            return events.into_iter().map(|at| at.event).collect();
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("{what}: the indexer never held {count} events");
}

async fn register(
    wallet: &mut WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
    payer: &AccountId,
) -> RlnIdentity {
    let identity = create_identity(wallet, RATE_LIMIT).await;
    register_identity(
        wallet,
        programs,
        tree_id,
        &identity.id_commitment_bytes,
        payer,
        RATE_LIMIT,
    )
    .await
    .expect("the membership never appeared on-chain");
    identity
}

async fn native_balance(wallet: &WalletCore, id: &AccountId) -> u128 {
    wallet.get_account_balance(*id).await.expect("balance read")
}

#[tokio::test]
async fn registry_lifecycle_on_a_live_sequencer() {
    if std::env::var_os("LEZ_RLN_LOCAL_SEQUENCER").is_none() {
        eprintln!("LEZ_RLN_LOCAL_SEQUENCER not set; skipping (run tools/e2e-local.sh)");
        return;
    }
    let indexer = indexer_url_from_env().expect("LEZ_RLN_INDEXER_URL names the local indexer");
    let (active_sec, grace_sec) = membership_durations();
    assert!(
        active_sec <= 60 && grace_sec <= 300,
        "set LEZ_RLN_ACTIVE_DURATION_SECS / LEZ_RLN_GRACE_PERIOD_DURATION_SECS to seconds, \
         or extend and erase cannot be exercised in one run"
    );

    let mut tree_id = [0u8; 32];
    tree_id.copy_from_slice(&rand_bytes());
    let mut wallet = init_wallet().await;
    let registration_program = load_program();
    let payer = resolve_payer();

    // ── deploy + init ─────────────────────────────────────────────────
    // A fresh tree id, so this run's registry starts empty even when the
    // program is reused: every event names its tree id, and the reader keeps
    // only this one's.
    let programs = run_setup(&mut wallet, &registration_program, &tree_id).await;
    let config = read_config(&wallet, &programs, &tree_id).await;
    assert_eq!(config.tree_id, tree_id);
    assert_eq!(config.active_duration_for_new_memberships_sec, active_sec);
    assert_eq!(config.total_registrations, 0);
    let treasury = AccountId::new(config.treasury_account_id);
    let price = config.price_per_unit * u128::from(RATE_LIMIT);

    // ── register three members ────────────────────────────────────────
    let treasury_before = native_balance(&wallet, &treasury).await;
    let member_a = register(&mut wallet, &programs, &tree_id, &payer).await;
    let member_b = register(&mut wallet, &programs, &tree_id, &payer).await;
    let member_c = register(&mut wallet, &programs, &tree_id, &payer).await;
    let config = read_config(&wallet, &programs, &tree_id).await;
    assert_eq!(config.total_registrations, 3);
    assert_eq!(config.current_total_rate_limit, 3 * RATE_LIMIT);
    assert_eq!(
        native_balance(&wallet, &treasury).await,
        treasury_before + 3 * price,
        "the treasury is credited the price of every registration"
    );
    let membership_a = read_membership(&wallet, &programs, &tree_id, &member_a.id_commitment_bytes)
        .await
        .expect("member A is registered");
    assert_eq!(membership_a.rate_limit, RATE_LIMIT);

    let events = wait_for_events(
        &indexer,
        &programs.registration,
        &tree_id,
        3,
        "three registrations",
    )
    .await;
    let set = MembershipSet::from_events(CIRCUIT_DEPTH, &events).expect("events apply");
    let (leaf_a, leaf_b, leaf_c) = (
        set.leaf_index_of(&member_a.id_commitment_bytes).unwrap(),
        set.leaf_index_of(&member_b.id_commitment_bytes).unwrap(),
        set.leaf_index_of(&member_c.id_commitment_bytes).unwrap(),
    );
    assert_eq!(
        (leaf_b, leaf_c),
        (leaf_a + 1, leaf_a + 2),
        "the chain numbers registrations in block order"
    );
    assert_eq!(
        set.member(&member_a.id_commitment_bytes)
            .unwrap()
            .expiry_timestamp_ms,
        membership_expiry_ms(&membership_a),
        "Registered carries the expiry the chain stored"
    );

    // ── an RLN proof against the reader's root verifies ───────────────
    let proof = set.proof(leaf_a);
    assert_eq!(proof.leaf, member_a.leaf_bytes);
    let (merkle_proof, root) = proof_to_circuit(&proof);
    let epoch = hash_to_field_le(b"local-sequencer-epoch");
    let rln_identifier = hash_to_field_le(b"local-sequencer");
    let external_nullifier = Hasher::<PoseidonHash>::hash_pair(epoch, rln_identifier);
    let x = hash_to_field_le(b"hello");
    let witness = RLNWitnessInput::new_single()
        .identity_secret(member_a.identity_secret)
        .user_message_limit(Fr::from(RATE_LIMIT))
        .merkle_proof(merkle_proof)
        .x(x)
        .external_nullifier(external_nullifier)
        .message_id(Fr::from(0u64))
        .build()
        .expect("witness");
    let engine = logos_lez_rln::proof_circuit::engine();
    let (rln_proof, values) = engine.generate_proof(&witness).expect("proof generation");
    assert!(
        engine
            .verify_with_roots(&rln_proof, &values, &x, &[root])
            .expect("verification runs"),
        "proof must verify against the reader's root"
    );

    // ── a duplicate registration is refused ───────────────────────────
    assert!(
        register_identity(
            &wallet,
            &programs,
            &tree_id,
            &member_a.id_commitment_bytes,
            &payer,
            RATE_LIMIT,
        )
        .await
        .is_none(),
        "re-registering an existing commitment must not create a membership"
    );
    let config = read_config(&wallet, &programs, &tree_id).await;
    assert_eq!(config.total_registrations, 3);
    assert!(
        read_membership(&wallet, &programs, &tree_id, &member_a.id_commitment_bytes)
            .await
            .is_some(),
        "still registered"
    );

    // ── slash C by revealing its secret; C may then register again ────
    let secret_c = fr_to_bytes_le(&member_c.identity_secret);
    slash_membership(
        &wallet,
        &programs,
        &tree_id,
        &secret_c,
        &member_c.id_commitment_bytes,
        &payer,
    )
    .await;
    wait_for_membership_gone(
        &wallet,
        &programs,
        &tree_id,
        &member_c.id_commitment_bytes,
        "slash",
    )
    .await;
    let config = read_config(&wallet, &programs, &tree_id).await;
    assert_eq!(config.total_registrations, 2);
    assert_eq!(config.current_total_rate_limit, 2 * RATE_LIMIT);
    register_identity(
        &wallet,
        &programs,
        &tree_id,
        &member_c.id_commitment_bytes,
        &payer,
        RATE_LIMIT,
    )
    .await
    .expect("C's second membership never appeared on-chain");

    // The refused duplicate emitted nothing: Registered ×3, Slashed, Registered.
    let events = wait_for_events(
        &indexer,
        &programs.registration,
        &tree_id,
        5,
        "slash and re-register",
    )
    .await;
    let set = MembershipSet::from_events(CIRCUIT_DEPTH, &events).expect("events apply");
    assert_eq!(
        set.proof(leaf_c).leaf,
        ZERO_LEAF,
        "a slashed leaf is zeroed"
    );
    assert_eq!(
        set.leaf_index_of(&member_c.id_commitment_bytes),
        Some(leaf_c + 1),
        "a slashed commitment registers at a new leaf"
    );

    // ── extend A once its grace period opens ──────────────────────────
    let start_a = membership_a.grace_period_start_timestamp_ms;
    wait_for_clock(&wallet, start_a, "extend").await;
    let treasury_before = native_balance(&wallet, &treasury).await;
    extend_membership(
        &wallet,
        &programs,
        &tree_id,
        &member_a.id_commitment_bytes,
        &payer,
    )
    .await;
    let renewed_start = start_a + secs_to_millis(grace_sec) + secs_to_millis(active_sec);
    for _ in 0..120 {
        let membership =
            read_membership(&wallet, &programs, &tree_id, &member_a.id_commitment_bytes)
                .await
                .expect("A stays registered");
        if membership.grace_period_start_timestamp_ms == renewed_start {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let renewed_a = read_membership(&wallet, &programs, &tree_id, &member_a.id_commitment_bytes)
        .await
        .expect("A stays registered");
    assert_eq!(
        renewed_a.grace_period_start_timestamp_ms, renewed_start,
        "extend pushes the grace window out by one grace + one active period"
    );
    assert_eq!(
        native_balance(&wallet, &treasury).await,
        treasury_before + price,
        "renewal is priced like a registration"
    );
    let events = wait_for_events(&indexer, &programs.registration, &tree_id, 6, "extend").await;
    let set = MembershipSet::from_events(CIRCUIT_DEPTH, &events).expect("events apply");
    assert_eq!(
        set.member(&member_a.id_commitment_bytes)
            .unwrap()
            .expiry_timestamp_ms,
        membership_expiry_ms(&renewed_a),
        "Extended carries the expiry the chain stored"
    );

    // ── erase B once it has expired ───────────────────────────────────
    let membership_b = read_membership(&wallet, &programs, &tree_id, &member_b.id_commitment_bytes)
        .await
        .expect("B is registered");
    let expiry_b = membership_expiry_ms(&membership_b);
    wait_for_clock(&wallet, expiry_b, "erase").await;
    erase_membership(
        &wallet,
        &programs,
        &tree_id,
        &member_b.id_commitment_bytes,
        &payer,
    )
    .await;
    wait_for_membership_gone(
        &wallet,
        &programs,
        &tree_id,
        &member_b.id_commitment_bytes,
        "erase",
    )
    .await;
    let config = read_config(&wallet, &programs, &tree_id).await;
    assert_eq!(config.total_registrations, 2);
    assert_eq!(config.current_total_rate_limit, 2 * RATE_LIMIT);

    wait_for_events(&indexer, &programs.registration, &tree_id, 7, "erase").await;
    let set = membership_set(&indexer, &programs.registration, &tree_id, Some(expiry_b))
        .await
        .expect("events apply");
    assert_eq!(
        set.proof(leaf_b).leaf,
        ZERO_LEAF,
        "an erased leaf is zeroed"
    );
    assert_eq!(
        set.proof(leaf_a).leaf,
        member_a.leaf_bytes,
        "erasing B leaves A's leaf alone"
    );
}

fn rand_bytes() -> [u8; 32] {
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    let mut seed = [0u8; 32];
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos()
        .to_le_bytes();
    seed[..16].copy_from_slice(&nanos);
    seed[16..24].copy_from_slice(&std::process::id().to_le_bytes()[..4].repeat(2));
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    let mut out = [0u8; 32];
    rng.fill_bytes(&mut out);
    out
}
