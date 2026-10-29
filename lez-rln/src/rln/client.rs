//! Client helpers for the RLN registration program (shared by `run_setup`,
//! `register_member`, `run_rln_proof` and `register_commitments`).
//!
//! Every read and every transaction names a SHARD: the registration program's
//! shard of `config` and `membership`, the clock program's shard of
//! `CLOCK_50`, and the native shard of `payer` and `treasury`. There is no
//! tree to read here: the program emits events and `crate::zone` rebuilds the
//! tree from them. The order and selection of each instruction's
//! accounts is the guest's `plan` contract (`methods/guest/src/program.rs`).

use std::{path::PathBuf, time::Duration};

use nssa::{AccountId, ProgramShardSelector, program::Program};
use nssa_core::program::{MAX_PROGRAM_SEGMENTS, PROGRAM_LOADER_ACCOUNT_ID, ProgramId};
use program_loader_core::{MAX_SEGMENT_DATA_LEN, ProgramHeader};
use rand_chacha::ChaCha20Rng;
use rln::prelude::{Fr, Hasher, IdentityKeys, PoseidonHash, SecretFr};
use rln_layouts::{ConfigState, MembershipState, expiry_ms, secs_to_millis};
use sequencer_service_protocol::FeeStateQuote;
use wallet::{
    AccountIdentity, AccountMention, WalletCore, program_facades::program_loader::ProgramLoader,
};

use crate::{
    fr_bytes::{bytes_le_to_fr, fr_to_bytes_le},
    rln::{
        CONFIG_SIZE, Instruction, MEMBERSHIP_SIZE, ProgramIds, derive_config_account,
        derive_membership_account,
        program_ids::{hex_id, known_program_ids, save_program_ids},
    },
};

/// Native atomic units charged per unit of rate limit. At rate_limit 100 a
/// membership costs 1,000,000, which is the anti-grief price `Extend` needs to
/// stay non-zero.
pub const PRICE_PER_UNIT: u128 = 10_000;
pub const MAX_TOTAL_RATE_LIMIT: u64 = 1_000_000;

/// 30 days, in seconds.
pub const DEFAULT_ACTIVE_DURATION_SECS: u32 = 30 * 24 * 60 * 60;

/// 7 days, in seconds.
pub const DEFAULT_GRACE_PERIOD_DURATION_SECS: u32 = 7 * 24 * 60 * 60;

/// The `(active, grace)` durations a new registry stamps on its memberships:
/// the defaults above, or `LEZ_RLN_ACTIVE_DURATION_SECS` /
/// `LEZ_RLN_GRACE_PERIOD_DURATION_SECS`. The guest refuses a zero active
/// duration, so a live-chain test that wants to extend and erase within
/// minutes sets these to seconds, never zero.
pub fn membership_durations() -> (u32, u32) {
    let read = |name: &str, default: u32| {
        std::env::var(name).ok().map_or(default, |raw| {
            raw.parse()
                .unwrap_or_else(|_| panic!("{name} must be a u32 number of seconds, got {raw:?}"))
        })
    };
    (
        read("LEZ_RLN_ACTIVE_DURATION_SECS", DEFAULT_ACTIVE_DURATION_SECS),
        read(
            "LEZ_RLN_GRACE_PERIOD_DURATION_SECS",
            DEFAULT_GRACE_PERIOD_DURATION_SECS,
        ),
    )
}

/// CLOCK_50 system account id.
pub fn clock_account_id() -> AccountId {
    AccountId::new(crate::rln::CLOCK_50_ACCOUNT_ID_BYTES)
}

/// The clock program's shard of `CLOCK_50`, which holds `ClockAccountData`.
pub fn clock_selector() -> ProgramShardSelector {
    ProgramShardSelector::new(clock_account_id(), clock_core::clock_account_id())
}

pub const REGISTRATION_BINARY: &str =
    "methods/guest/target/riscv32im-risc0-zkvm-elf/docker/rln_registration.bin";
pub const DATA_DIR: &str = ".logos-lez-rln";

/// Initialize a WalletCore, creating storage if missing.
///
/// An existing `wallet_config.json` is preserved (lets callers point the
/// wallet at a non-default sequencer, e.g. the public LEZ testnet); with
/// none present, a fresh local-dev default is written.
pub async fn init_wallet() -> WalletCore {
    let config_path = wallet::helperfunctions::fetch_config_path().unwrap();
    let storage_path = wallet::helperfunctions::fetch_persistent_storage_path().unwrap();
    if storage_path.exists() {
        WalletCore::new_update_chain(config_path, storage_path, None).unwrap()
    } else {
        println!("First run: initializing wallet storage at {storage_path:?}");
        WalletCore::new_init_storage(config_path, storage_path, None, "")
            .unwrap()
            .0
    }
}

/// Load the registration guest binary from its default path. Its image id is
/// what a deployed header must carry; its account id is deployment state
/// (`program_ids`).
pub fn load_program() -> Program {
    let registration_bytecode =
        std::fs::read(REGISTRATION_BINARY).expect("Failed to read registration program binary");
    Program::new(registration_bytecode.into()).expect("Failed to parse registration program")
}

/// Read one shard, panicking with `label` on a transport error. An account
/// or shard that was never written reads as empty.
async fn read_shard(
    wallet_core: &WalletCore,
    selector: ProgramShardSelector,
    label: &str,
) -> Vec<u8> {
    wallet_core
        .get_account_view(selector)
        .await
        .unwrap_or_else(|e| panic!("{label}: cannot read {}: {e:?}", selector.account_id))
        .data
        .shard(selector.program_account_id)
        .to_vec()
}

fn config_selector(programs: &ProgramIds, tree_id: &[u8; 32]) -> ProgramShardSelector {
    ProgramShardSelector::new(
        derive_config_account(&programs.registration, tree_id),
        programs.registration,
    )
}

fn membership_selector(
    programs: &ProgramIds,
    tree_id: &[u8; 32],
    id_commitment: &[u8; 32],
) -> ProgramShardSelector {
    ProgramShardSelector::new(
        derive_membership_account(&programs.registration, tree_id, id_commitment),
        programs.registration,
    )
}

/// Check if the registry for `tree_id` is initialized on-chain.
pub async fn is_initialized(
    wallet_core: &WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
) -> bool {
    !read_shard(wallet_core, config_selector(programs, tree_id), "config")
        .await
        .is_empty()
}

/// The registry config. `ConfigState` has no version discriminator, so its
/// exact size is asserted before decoding.
pub async fn read_config(
    wallet_core: &WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
) -> ConfigState {
    let bytes = read_shard(wallet_core, config_selector(programs, tree_id), "config").await;
    assert!(
        !bytes.is_empty(),
        "config for tree {} is empty: the registry is not initialized",
        hex::encode(tree_id)
    );
    assert_eq!(
        bytes.len(),
        CONFIG_SIZE,
        "config shard is {} bytes, the layout this host reads is {CONFIG_SIZE}",
        bytes.len()
    );
    borsh::from_slice(&bytes).expect("config shard decodes as ConfigState")
}

/// A membership, or `None` if it does not exist.
pub async fn read_membership(
    wallet_core: &WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
    id_commitment: &[u8; 32],
) -> Option<MembershipState> {
    let bytes = read_shard(
        wallet_core,
        membership_selector(programs, tree_id, id_commitment),
        "membership",
    )
    .await;
    if bytes.is_empty() {
        return None;
    }
    assert_eq!(
        bytes.len(),
        MEMBERSHIP_SIZE,
        "membership shard is {} bytes, the layout this host reads is {MEMBERSHIP_SIZE}",
        bytes.len()
    );
    Some(borsh::from_slice(&bytes).expect("membership shard decodes as MembershipState"))
}

/// `CLOCK_50`'s timestamp, the `now_ms` claim a time-dependent instruction
/// carries. The guest refuses a zero clock, so this does too.
pub async fn read_clock_ms(wallet_core: &WalletCore) -> u64 {
    let bytes = read_shard(wallet_core, clock_selector(), "clock").await;
    let timestamp = borsh::from_slice::<clock_core::ClockAccountData>(&bytes)
        .map(|clock| clock.timestamp)
        .unwrap_or(0);
    assert!(
        timestamp > 0,
        "CLOCK_50 has not been written yet; the sequencer writes it every 50 blocks"
    );
    timestamp
}

/// Default `max_attempts` for effect confirmation. Each attempt sleeps
/// 500 ms, so 360 → 180 s — covers a testnet block cycle plus margin.
/// Override via `LEZ_RLN_ACCOUNT_WAIT_ATTEMPTS`.
pub fn wait_account_attempts() -> u32 {
    std::env::var("LEZ_RLN_ACCOUNT_WAIT_ATTEMPTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(360)
}

/// RLN tree id, read from `LEZ_RLN_TREE_ID_HEX` (32 bytes, 64 hex chars).
/// Strict: aborts with an actionable error if unset or malformed. Kept out of
/// source because shell scripts key persistent caches off the hex form, and a
/// bump here would silently desync them.
pub fn tree_id_from_env() -> [u8; 32] {
    let hex = std::env::var("LEZ_RLN_TREE_ID_HEX").unwrap_or_else(|_| {
        eprintln!(
            "LEZ_RLN_TREE_ID_HEX not set (expected 64 hex chars).\n\
             Example: LEZ_RLN_TREE_ID_HEX=000102030405060708090a0b0c0d0e0f\
             1011121314151617a0cba6e85ca1e26e cargo run --bin run_setup"
        );
        std::process::exit(2);
    });
    let bytes = hex::decode(&hex).unwrap_or_else(|e| {
        eprintln!("LEZ_RLN_TREE_ID_HEX is not valid hex: {e}");
        std::process::exit(2);
    });
    bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
        eprintln!(
            "LEZ_RLN_TREE_ID_HEX must decode to exactly 32 bytes, got {}",
            v.len()
        );
        std::process::exit(2);
    })
}

/// Path to a per-tree account file, named `<prefix>_<tree_id>.txt`.
fn account_file_path(tree_id: &[u8; 32], prefix: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(DATA_DIR)
        .join(format!("{}_{}.txt", prefix, hex::encode(tree_id)))
}

/// Save the payment account ID for later reuse.
pub fn save_payment_account(tree_id: &[u8; 32], account_id: &AccountId) {
    let path = account_file_path(tree_id, "payment_account");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, account_id.to_string()).expect("Failed to save payment_account ID");
}

/// Load a previously saved payment account ID.
pub fn load_payment_account(tree_id: &[u8; 32]) -> Option<AccountId> {
    std::fs::read_to_string(account_file_path(tree_id, "payment_account"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Compute the membership leaf: rate_commitment = poseidon(id_commitment, rate_limit).
/// Single source of truth for the leaf value shared by identity creation and
/// CSV-driven bulk registration.
pub fn rate_commitment_from_fr(id_commitment_fr: &Fr, rate_limit: u64) -> [u8; 32] {
    let rate_commitment =
        Hasher::<PoseidonHash>::hash_pair(*id_commitment_fr, Fr::from(rate_limit));
    fr_to_bytes_le(&rate_commitment)
}

/// The leaf a membership occupies, from its byte-encoded `id_commitment`.
pub fn registration_leaf(id_commitment: &[u8; 32], rate_limit: u64) -> [u8; 32] {
    let id_commitment_fr =
        bytes_le_to_fr(id_commitment).expect("id_commitment is not a valid BN254 field element");
    rate_commitment_from_fr(&id_commitment_fr, rate_limit)
}

/// A membership's expiry: the end of its grace period, what the events carry
/// as `expiry_timestamp_ms`.
pub fn membership_expiry_ms(membership: &MembershipState) -> u64 {
    expiry_ms(
        membership.grace_period_start_timestamp_ms,
        secs_to_millis(membership.grace_period_duration_sec),
    )
}

/// The expiry `membership` has once extended: its grace start moves on by one
/// grace plus one active period. `Extend` claims it, and the guest asserts it.
pub fn extended_expiry_ms(membership: &MembershipState) -> u64 {
    let grace_start = membership
        .grace_period_start_timestamp_ms
        .saturating_add(secs_to_millis(membership.grace_period_duration_sec))
        .saturating_add(secs_to_millis(membership.active_duration_sec));
    expiry_ms(
        grace_start,
        secs_to_millis(membership.grace_period_duration_sec),
    )
}

/// Outputs of `create_identity`: the RLN identity plus its leaf (rate commitment).
pub struct RlnIdentity {
    pub identity_secret: SecretFr,
    pub id_commitment_fr: Fr,
    pub id_commitment_bytes: [u8; 32],
    pub leaf_bytes: [u8; 32],
    pub id_secret_hash_hex: String,
}

/// Create a new wallet account, derive an RLN identity from its signing key, and
/// compute the rate commitment (leaf value = poseidon(id_commitment, rate_limit)).
pub async fn create_identity(wallet_core: &mut WalletCore, user_message_limit: u64) -> RlnIdentity {
    let (account_id, _chain_index) = wallet_core.create_new_account_public(None);
    wallet_core
        .store_persistent_data()
        .expect("Failed to store wallet");

    let signing_key = wallet_core
        .get_account_public_signing_key(account_id)
        .expect("Account should be self-owned public");

    let seed = signing_key.value();
    let identity_keys = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(seed);
    let identity_secret = identity_keys.identity_secret();
    let id_commitment_fr = identity_keys.id_commitment();

    // Deliberate secret leak: this hex is the IDENTITY_SECRET_HASH recovery path.
    let id_secret_hash_hex = hex::encode(fr_to_bytes_le(&identity_secret));

    let id_commitment_bytes = fr_to_bytes_le(&id_commitment_fr);

    let leaf_bytes = rate_commitment_from_fr(&id_commitment_fr, user_message_limit);

    RlnIdentity {
        identity_secret,
        id_commitment_fr,
        id_commitment_bytes,
        leaf_bytes,
        id_secret_hash_hex,
    }
}

// ============================================================================
// Deployment
// ============================================================================

/// The funded account that pays for deployment and initialization.
///
/// Every account a deploy touches is freshly created and holds nothing, so
/// self-pay has nothing to draw on, and no program can mint native: this has
/// to name an account funded at genesis, over the bridge, or by a transfer
/// from something already funded.
fn fee_payer() -> Option<AccountId> {
    std::env::var("LEZ_RLN_PAYER")
        .ok()
        .map(|raw| parse_account_id(&raw).unwrap_or_else(|e| panic!("LEZ_RLN_PAYER is {e}")))
}

/// How many loader segments `bytecode` uploads as, refusing a binary the
/// loader would refuse.
///
/// The loader re-attaches the protocol's default kernel to the uploaded user
/// ELF, so a `.bin` built around any other kernel deploys under an image id
/// that is not its own. Checked before any deploy account is created.
pub fn deploy_segment_count(bytecode: &[u8]) -> Result<usize, String> {
    let binary = risc0_binfmt::ProgramBinary::decode(bytecode)
        .map_err(|e| format!("not a risc0 program binary: {e}"))?;
    if binary.kernel_elf != risc0_zkos_v1compat::V1COMPAT_ELF {
        return Err(
            "its kernel ELF is not risc0_zkos_v1compat::V1COMPAT_ELF, the only kernel \
                    the program loader accepts — rebuild the guest without stripping the kernel"
                .to_string(),
        );
    }
    let segments = binary.user_elf.len().div_ceil(MAX_SEGMENT_DATA_LEN);
    if segments == 0 || segments > MAX_PROGRAM_SEGMENTS {
        return Err(format!(
            "its user ELF uploads as {segments} segments; the loader takes 1 to \
             {MAX_PROGRAM_SEGMENTS}"
        ));
    }
    Ok(segments)
}

/// Whether a header account's loader shard holds a header for `image_id`.
///
/// Empty means nothing was deployed there. A header for another image, or
/// bytes that are not a header, mean the account belongs to something else.
pub fn header_deployed(loader_shard: &[u8], image_id: &ProgramId) -> Result<bool, String> {
    if loader_shard.is_empty() {
        return Ok(false);
    }
    match ProgramHeader::from_bytes(loader_shard) {
        Some(header) if header.image_id == *image_id => Ok(true),
        Some(header) => Err(format!("holds a header for image {:?}", header.image_id)),
        None => Err("holds something other than a program header".to_string()),
    }
}

/// Read `header`'s loader shard and judge it against `image_id`.
async fn program_deployed_at(
    wallet_core: &WalletCore,
    header: AccountId,
    image_id: &ProgramId,
    label: &str,
) -> Result<bool, String> {
    let shard = read_shard(
        wallet_core,
        ProgramShardSelector::new(header, PROGRAM_LOADER_ACCOUNT_ID),
        label,
    )
    .await;
    header_deployed(&shard, image_id)
}

/// How many consecutive already-written key-chain accounts a deploy skips
/// before giving up on the wallet.
const FRESH_ACCOUNT_ATTEMPTS: usize = 64;

/// The next account on the wallet's key chain whose loader shard is empty
/// on chain.
///
/// The key chain is derived from the wallet seed, so a wallet restored or
/// copied from the same seed re-derives the accounts an earlier deploy
/// already claimed; `CreateHeader` and `WriteSegment` both fail on a
/// written loader shard and are charged in full. Accounts that are already
/// written are skipped, which also steps past the leftovers of an
/// interrupted upload.
async fn fresh_loader_account(wallet_core: &mut WalletCore, label: &str) -> AccountId {
    for _ in 0..FRESH_ACCOUNT_ATTEMPTS {
        let (account, _) = wallet_core.create_new_account_public(None);
        let shard = read_shard(
            wallet_core,
            ProgramShardSelector::new(account, PROGRAM_LOADER_ACCOUNT_ID),
            label,
        )
        .await;
        if shard.is_empty() {
            return account;
        }
        println!("  {label}: skipping {account}, its loader shard is already written");
    }
    panic!(
        "{label}: the next {FRESH_ACCOUNT_ATTEMPTS} wallet accounts all hold loader data; use a \
         wallet with an unused key chain"
    );
}

/// Deploy `program` to a fresh keyed header account, uploading its user ELF
/// to fresh keyed segment accounts. Returns the header, which is the
/// program's account id.
///
/// The wallet's loader cannot resume a partial upload, and segments are
/// write-once, so every call uploads to accounts that are empty on chain; a
/// deploy interrupted midway leaves its accounts behind and a re-run steps
/// past them.
pub async fn deploy_program(
    wallet_core: &mut WalletCore,
    program: &Program,
    bytecode_path: &str,
    program_name: &str,
) -> AccountId {
    let bytecode = std::fs::read(bytecode_path)
        .unwrap_or_else(|e| panic!("Failed to read {program_name} binary {bytecode_path}: {e}"));
    let loaded = Program::new(bytecode.clone().into())
        .unwrap_or_else(|e| panic!("Failed to parse {program_name} binary: {e:?}"));
    assert_eq!(
        loaded.id(),
        program.id(),
        "{program_name}: {bytecode_path} changed since it was loaded"
    );
    let segment_count = deploy_segment_count(&bytecode)
        .unwrap_or_else(|what| panic!("{program_name}: refusing {bytecode_path}: {what}"));
    let payer = fee_payer().unwrap_or_else(|| {
        panic!("{program_name}: deploying needs a funded payer — set LEZ_RLN_PAYER")
    });

    let header = fresh_loader_account(wallet_core, program_name).await;
    let mut segments = Vec::with_capacity(segment_count);
    for _ in 0..segment_count {
        segments.push(fresh_loader_account(wallet_core, program_name).await);
    }
    // The header and segment keys have to outlive a failed deploy: the header
    // key is what `UpdateHeader` would sign with.
    wallet_core
        .store_persistent_data()
        .expect("Failed to store wallet");
    println!("  {program_name}: header {header}, {segment_count} segment(s)");

    ProgramLoader(wallet_core)
        .deploy(header, &segments, bytecode, true, Some(payer))
        .await
        .unwrap_or_else(|e| panic!("{program_name}: deploy failed: {e:?}"));

    match program_deployed_at(wallet_core, header, &program.id(), program_name).await {
        Ok(true) => {}
        Ok(false) => panic!("{program_name}: deploy finalized but header {header} is empty"),
        Err(what) => panic!("{program_name}: header {header} {what}"),
    }
    println!(
        "  {program_name} deployed at {header} ({})",
        hex_id(&header)
    );
    header
}

/// The program at `known`, if its header carries `program`'s image id, else
/// a fresh deploy.
async fn ensure_program(
    wallet_core: &mut WalletCore,
    known: Option<AccountId>,
    program: &Program,
    bytecode_path: &str,
    program_name: &str,
) -> AccountId {
    let Some(header) = known else {
        return deploy_program(wallet_core, program, bytecode_path, program_name).await;
    };
    match program_deployed_at(wallet_core, header, &program.id(), program_name).await {
        Ok(true) => {
            println!("  {program_name} already deployed at {header}");
            header
        }
        Ok(false) => panic!(
            "{program_name}: the recorded program id {header} holds no header. Unset its \
             environment override or remove the programs_<tree>.json record to deploy anew."
        ),
        Err(what) => panic!(
            "{program_name}: the recorded program id {header} {what} — {bytecode_path} is not \
             the deployed program. Rebuild the matching guest, or remove the record to deploy \
             anew."
        ),
    }
}

// ============================================================================
// Transactions
// ============================================================================

/// A public account the transaction does not sign for, selecting `program`'s
/// shard.
fn no_sign(account_id: AccountId, program: AccountId) -> AccountMention {
    AccountIdentity::PublicNoSign(account_id).select_program_shard(program)
}

/// Wait for tx `hash` to take effect on the shard `selector` names, and fail
/// loudly if it never does.
///
/// A send returning `Ok` means only that the sequencer admitted the
/// transaction; one that fails on-chain is left out of the block, so the only
/// client-side sign is that its target never changes.
async fn confirm_effect(
    wallet_core: &WalletCore,
    hash: common::HashType,
    selector: ProgramShardSelector,
    landed: impl Fn(&[u8]) -> bool,
    label: &str,
) {
    let attempts = wait_account_attempts();
    for _ in 0..attempts {
        if landed(&read_shard(wallet_core, selector, label).await) {
            return;
        }
        if let Ok(Some((_, block))) = wallet_core.get_transaction(hash).await {
            // Re-read: the shard may have been read before the block landed.
            if landed(&read_shard(wallet_core, selector, label).await) {
                return;
            }
            panic!(
                "{label}: tx {hash} is in block {block} but had no effect on {}",
                selector.account_id
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!(
        "{label}: tx {hash} was accepted but after {} s is neither in a block nor has any \
         effect on {} — a failed transaction is left out of the block; the sequencer's log \
         names the error",
        attempts / 2,
        selector.account_id
    );
}

/// Build, submit, and confirm one registration-program init transaction:
/// no signers, paid by `LEZ_RLN_PAYER`. Blocks until `wait_on` is non-empty.
async fn send_init_tx(
    wallet_core: &WalletCore,
    programs: &ProgramIds,
    accounts: Vec<AccountMention>,
    instruction: Instruction,
    label: &str,
    wait_on: ProgramShardSelector,
) {
    let instruction_data =
        Program::serialize_instruction(instruction).expect("instruction serializes");
    let hash = wallet_core
        .send_pub_tx_paid_by(
            accounts,
            instruction_data,
            programs.registration,
            fee_payer(),
        )
        .await
        .unwrap_or_else(|e| panic!("Failed to send {label}: {e:?}"));
    println!("  {label} tx hash: {hash}");
    confirm_effect(wallet_core, hash, wait_on, |shard| !shard.is_empty(), label).await;
}

/// Deploy (or reuse) the registration program, record its id, create the
/// treasury, and initialize the registry for `tree_id`. Returns the program id.
///
/// The program is reused from `LEZ_RLN_REGISTRATION_PROGRAM_ID` or the tree's
/// record when its header carries the local binary's image id, and deployed
/// otherwise. The record is written as soon as the id is known, before
/// initialization.
pub async fn run_setup(
    wallet_core: &mut WalletCore,
    registration_program: &Program,
    tree_id: &[u8; 32],
) -> ProgramIds {
    let known = known_program_ids(tree_id).unwrap_or_else(|e| panic!("{e}"));

    println!("Setup Step 1: Checking/deploying the program...");
    let registration = ensure_program(
        wallet_core,
        known.map(|ids| ids.registration),
        registration_program,
        REGISTRATION_BINARY,
        "Registration program",
    )
    .await;
    let programs = ProgramIds { registration };
    save_program_ids(tree_id, &programs);
    println!(
        "  Program id recorded in {}",
        crate::rln::program_ids::record_path(tree_id).display()
    );

    if is_initialized(wallet_core, &programs, tree_id).await {
        println!("Registry already initialized for this tree");
        return programs;
    }

    // The treasury is a plain public account, deliberately not a PDA: a PDA is
    // spendable only through a chained call carrying its seeds, issued by its
    // owning program, and this program has no instruction that would issue
    // one. A native credit needs no prior initialization of the target.
    println!("Setup Step 2: Creating the treasury account...");
    let (treasury_id, _) = wallet_core.create_new_account_public(None);
    wallet_core
        .store_persistent_data()
        .expect("Failed to store wallet");
    println!("  Treasury: {treasury_id}");

    println!("Setup Step 3: Initializing registration program...");
    let (active_duration_sec, grace_period_duration_sec) = membership_durations();
    let config = config_selector(&programs, tree_id);
    send_init_tx(
        wallet_core,
        &programs,
        vec![no_sign(config.account_id, programs.registration)],
        Instruction::Initialize {
            tree_id: *tree_id,
            price_per_unit: PRICE_PER_UNIT,
            treasury_account_id: *treasury_id.value(),
            max_total_rate_limit: MAX_TOTAL_RATE_LIMIT,
            active_duration_for_new_memberships_sec: active_duration_sec,
            grace_period_duration_for_new_memberships_sec: grace_period_duration_sec,
        },
        "InitializeConfig",
        config,
    )
    .await;
    println!("  Registration initialized");
    programs
}

/// An account id as either 64 hex chars or base58.
///
/// `AccountId`'s own FromStr is base58 only, but the registry module publishes
/// its payer as hex — `wallet_status` answers `{"payer":"<64 hex>"}` because
/// that is what every other id on its wire is. Hex is tried only at exactly
/// 64 characters, so a base58 id is never silently reinterpreted as bytes.
pub fn parse_account_id(raw: &str) -> Result<AccountId, String> {
    let raw = raw.trim();
    if raw.len() == 64
        && let Ok(bytes) = hex::decode(raw)
        && let Ok(id) = <[u8; 32]>::try_from(bytes.as_slice())
    {
        return Ok(AccountId::new(id));
    }
    raw.parse()
        .map_err(|e| format!("neither 64-hex nor base58: {e}"))
}

/// The account that signs a registration and pays for it.
///
/// It signs the `Register` transaction, pays the registry price out of its
/// native balance, and pays the transaction fee. No program can mint native
/// balance, so this account must already have been funded at genesis
/// (`dev.sh`'s `LEZ_RLN_GENESIS_FUND`), over the bridge, or by a transfer.
pub fn resolve_payer() -> AccountId {
    fee_payer().unwrap_or_else(|| {
        eprintln!(
            "LEZ_RLN_PAYER must name a funded account: a registration pays its \
             price and its fee from one native balance, and no program can mint native."
        );
        std::process::exit(2);
    })
}

/// The execution gas a transaction declares.
///
/// The wallet's own send path declares its configured `gas_limit` (2,000,000
/// by default). Gas is cycles, summed over every plan and apply session, and
/// a slash hashes the identity secret (one Poseidon compression, about 900,000
/// cycles) on top of its sessions; every membership transaction declares its
/// own limit, so it builds the transaction itself.
///
/// Defaults to the protocol's ceiling. The sequencer refuses a transaction
/// declaring more than `MAX_GAS_EXEC`, so this is a ceiling rather than a
/// preference.
fn declared_gas_limit() -> u64 {
    const MAX_GAS_EXEC: u64 = 10_000_000;
    let limit = std::env::var("LEZ_RLN_GAS_LIMIT")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(MAX_GAS_EXEC);
    assert!(
        limit <= MAX_GAS_EXEC,
        "LEZ_RLN_GAS_LIMIT {limit} exceeds MAX_GAS_EXEC {MAX_GAS_EXEC}; \
         a transaction declaring more can never be included in a block"
    );
    limit
}

/// Send a public transaction that declares its own gas limit, signed by
/// `signer` and paid for by the configured payer.
///
/// Only accounts that sign carry a nonce: the signer's, then the payer's when
/// it is a separate co-signer outside `shard_selectors`.
///
/// `max_fee` is the declared cap, normally the `fee_reserve` the caller
/// checked the payer against: the chain refuses a cap below its reserve, so
/// the two must come from the same quote.
async fn send_metered_tx(
    wallet_core: &WalletCore,
    program_account: AccountId,
    shard_selectors: Vec<ProgramShardSelector>,
    signer: &AccountId,
    instruction_data: nssa_core::program::InstructionData,
    max_fee: u128,
    label: &str,
) -> common::HashType {
    let payer =
        fee_payer().unwrap_or_else(|| panic!("{label} needs a funded payer — set LEZ_RLN_PAYER"));

    let signer_key = wallet_core
        .get_account_public_signing_key(*signer)
        .unwrap_or_else(|| panic!("{label}: signer {signer:?} not in wallet"));

    // Registration pays its price and its fee from ONE native balance, so
    // signer == payer is the normal case. Listing that account twice would
    // take two nonces and two signatures for it and advance its nonce by two,
    // failing the NEXT transaction's nonce check.
    let payer_is_signer = payer == *signer;
    let payer_key = (!payer_is_signer).then(|| {
        wallet_core
            .get_account_public_signing_key(payer)
            .unwrap_or_else(|| panic!("{label}: payer {payer:?} not in wallet"))
    });

    let nonce_accounts: Vec<AccountId> = if payer_is_signer {
        vec![*signer]
    } else {
        vec![*signer, payer]
    };
    let nonces = wallet_core
        .get_accounts_nonces(&nonce_accounts)
        .await
        .unwrap_or_else(|e| panic!("{label}: failed to read nonces: {e:?}"));

    let fee = nssa::FeeDeclaration::new(payer, declared_gas_limit(), 0, max_fee);
    let message = nssa::public_transaction::Message::new_preserialized(
        program_account,
        shard_selectors,
        nonces,
        instruction_data,
        Some(fee),
    );

    let hash = message.hash();
    let mut witnesses = vec![(
        nssa::Signature::new(signer_key, &hash),
        nssa::PublicKey::new_from_private_key(signer_key),
    )];
    if let Some(payer_key) = payer_key.as_ref() {
        witnesses.push((
            nssa::Signature::new(payer_key, &hash),
            nssa::PublicKey::new_from_private_key(payer_key),
        ));
    }
    let witness = nssa::public_transaction::WitnessSet::from_raw_parts(witnesses);

    use sequencer_service_rpc::RpcClient as _;
    wallet_core
        .client()
        .send_transaction(common::transaction::LeeTransaction::Public(
            nssa::PublicTransaction::new(message, witness),
        ))
        .await
        .unwrap_or_else(|e| panic!("Failed to send {label}: {e:?}"))
}

/// The serialized-size allowance the wallet sizes its `max_fee` against
/// (`ASSUMED_DATA_BYTES` in the LEZ wallet). A Register tx is a few hundred
/// bytes, so this over-reserves storage gas — by ~1% of the whole reserve.
const ASSUMED_DATA_BYTES: u128 = 100_000;

/// Headroom over the quoted ceiling for the base fee rising between the
/// balance check and the block the transaction lands in.
///
/// The quote's `next_*_ceiling` already bounds the NEXT block (a full one
/// raises the base fee by at most one step, 8 -> 9 on devnet). x2 is six more
/// full-block steps of +12.5% (1.125^6 ~ 2.03), the same margin
/// logos-rln-module's `ensure.rs` reserves. Over-reserving costs nothing but a
/// larger funding target — the reserve is refunded down to the actual fee —
/// while under-reserving gets the transaction refused at admission.
const BASE_FEE_HEADROOM: u128 = 2;

/// The fee cap declared, and the reserve required, when no fee quote can be
/// had: the wallet's own sizing, `(gas_limit + ASSUMED_DATA_BYTES) x
/// ASSUMED_BASE_FEE (64)`, at the protocol's gas ceiling — ~646M.
const DECLARED_MAX_FEE: u128 = (10_000_000 + ASSUMED_DATA_BYTES) * 64;

/// Where a reserve came from, so a refusal can say what it was sized against.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ReserveBasis {
    /// Computed from the sequencer's quote at this height.
    Quote(u64),
    Fallback,
}

impl std::fmt::Display for ReserveBasis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReserveBasis::Quote(height) => write!(f, "getFeeState at height {height}"),
            ReserveBasis::Fallback => write!(f, "fixed fallback, no fee quote"),
        }
    }
}

/// The fee a metered tx reserves, over and above anything it pays a program.
///
/// A tx's `max_fee` is only a cap: the chain checks `max_fee >= reserve` and
/// `balance >= reserve`, then debits `gas_limit x base_fee_exec + data_bytes x
/// base_fee_stor + tip` at the including block's fee state, refunded down to
/// the actual fee. So the payer has to hold that reserve, not the cap, and
/// the same figure serves as the cap, since it clears the reserve by
/// construction.
fn fee_reserve_from(quote: &FeeStateQuote, gas_limit: u64) -> u128 {
    u128::from(gas_limit)
        .saturating_mul(u128::from(quote.next_base_fee_exec_ceiling))
        .saturating_add(
            ASSUMED_DATA_BYTES.saturating_mul(u128::from(quote.next_base_fee_stor_ceiling)),
        )
        .saturating_mul(BASE_FEE_HEADROOM)
}

/// The reserve from the sequencer's live quote, or `DECLARED_MAX_FEE`.
fn fee_reserve<E>(quote: Result<FeeStateQuote, E>, gas_limit: u64) -> (u128, ReserveBasis) {
    match quote {
        Ok(quote) => (
            fee_reserve_from(&quote, gas_limit),
            ReserveBasis::Quote(quote.height),
        ),
        Err(_) => (DECLARED_MAX_FEE, ReserveBasis::Fallback),
    }
}

/// Quote the reserve for one transaction. The caller uses the one figure for
/// both the affordability check and the declared `max_fee`, so the two cannot
/// disagree about the fee state they were sized against.
async fn quoted_fee_reserve(wallet_core: &WalletCore, label: &str) -> (u128, ReserveBasis) {
    use sequencer_service_rpc::RpcClient as _;
    let quote = wallet_core.client().get_fee_state().await;
    if let Err(e) = &quote {
        eprintln!("{label}: getFeeState failed ({e}); reserving the fixed {DECLARED_MAX_FEE}");
    }
    fee_reserve(quote, declared_gas_limit())
}

/// Refuse a payer that cannot cover the registry price AND the fee reserve,
/// and return that reserve for the transaction to declare as its `max_fee`.
///
/// The reserve is moved out of the payer before the guest runs, so an account
/// that clears the price but not the reserve never reaches the program at
/// all: the sequencer refuses it with a bare "Incorrect fee" that names
/// neither number.
async fn assert_can_afford(
    wallet_core: &WalletCore,
    payer: &AccountId,
    price: u128,
    label: &str,
) -> u128 {
    let balance = wallet_core
        .get_account_balance(*payer)
        .await
        .unwrap_or_else(|e| panic!("{label}: cannot read {payer}'s balance: {e:?}"));
    let (reserve, basis) = quoted_fee_reserve(wallet_core, label).await;
    let required = price.saturating_add(reserve);
    assert!(
        balance >= required,
        "{label}: payer {payer} holds {balance} native, needs {required} \
         ({price} price + {reserve} fee reserve, sized from {basis})",
    );
    reserve
}

/// A membership `register_identity` created, and the leaf it was assigned.
#[derive(Debug, Clone)]
pub struct Registration {
    pub membership: MembershipState,
    /// The config's `next_leaf_index` the transaction claimed; the chain
    /// accepted it, and the `Registered` event carries it.
    pub leaf_index: u64,
}

/// Register `id_commitment` at `rate_limit`, paid by `payer_id`, wait for the
/// transaction's fate, and return the membership it created — `None` when the
/// transaction was included without creating it (a refused duplicate, a stale
/// claim) or has not landed after `wait_account_attempts()` polls (it was
/// sent and may still land: check the chain before re-registering).
///
/// Every claim is read from the chain just before sending: `CLOCK_50`'s
/// timestamp and the config's price, durations and `next_leaf_index`. A
/// registration that lands between that read and this one takes the index
/// first, and this one is refused (`EXIT_STALE_LEAF_INDEX`, charged only the
/// cycles it ran): concurrent registrations against one registry contend.
pub async fn register_identity(
    wallet_core: &WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
    id_commitment: &[u8; 32],
    payer_id: &AccountId,
    rate_limit: u64,
) -> Option<Registration> {
    let config = read_config(wallet_core, programs, tree_id).await;
    let now_ms = read_clock_ms(wallet_core).await;
    let existed = read_membership(wallet_core, programs, tree_id, id_commitment)
        .await
        .is_some();

    let shard_selectors = vec![
        config_selector(programs, tree_id),
        ProgramShardSelector::native_balance(*payer_id),
        ProgramShardSelector::native_balance(AccountId::new(config.treasury_account_id)),
        clock_selector(),
        membership_selector(programs, tree_id, id_commitment),
    ];

    let max_fee = assert_can_afford(
        wallet_core,
        payer_id,
        config.price_per_unit.saturating_mul(u128::from(rate_limit)),
        "register",
    )
    .await;

    let instruction = Instruction::Register {
        tree_id: *tree_id,
        id_commitment: *id_commitment,
        rate_limit,
        now_ms,
        price_per_unit: config.price_per_unit,
        active_duration_sec: config.active_duration_for_new_memberships_sec,
        grace_period_duration_sec: config.grace_period_duration_for_new_memberships_sec,
        leaf_index: config.next_leaf_index,
    };
    let instruction_data =
        Program::serialize_instruction(instruction).expect("instruction serializes");
    let hash = send_metered_tx(
        wallet_core,
        programs.registration,
        shard_selectors,
        payer_id,
        instruction_data,
        max_fee,
        "Failed to register identity",
    )
    .await;

    // A failed registration is still included (a charged revert with no
    // effect), so the block is the signal: once the transaction is in one,
    // the membership is either there or never will be. A membership that
    // existed before the send is never this transaction's: the guest refuses
    // a duplicate.
    let landed = || async {
        if existed {
            return None;
        }
        read_membership(wallet_core, programs, tree_id, id_commitment)
            .await
            .filter(|m| m.rate_limit == rate_limit)
            .map(|membership| Registration {
                membership,
                leaf_index: config.next_leaf_index,
            })
    };
    for _ in 0..wait_account_attempts() {
        if let Some(membership) = landed().await {
            return Some(membership);
        }
        if let Ok(Some(_)) = wallet_core.get_transaction(hash).await {
            return landed().await;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    None
}

/// Renew a membership that is currently inside its grace period.
///
/// Renewal costs the same as registering the membership's rate limit, so
/// `payer_id` must hold that much NATIVE balance on top of the fee reserve; it
/// signs and is debited, and the config's treasury is credited. Anyone may pay
/// for anyone's renewal.
pub async fn extend_membership(
    wallet_core: &WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
    id_commitment: &[u8; 32],
    payer_id: &AccountId,
) {
    crate::fr_bytes::bytes_le_to_fr(id_commitment)
        .expect("id_commitment is not a valid BN254 field element");

    let config = read_config(wallet_core, programs, tree_id).await;
    let membership = read_membership(wallet_core, programs, tree_id, id_commitment)
        .await
        .expect("extend: no membership for this id_commitment");
    let now_ms = read_clock_ms(wallet_core).await;

    let shard_selectors = vec![
        config_selector(programs, tree_id),
        membership_selector(programs, tree_id, id_commitment),
        ProgramShardSelector::native_balance(*payer_id),
        ProgramShardSelector::native_balance(AccountId::new(config.treasury_account_id)),
        clock_selector(),
    ];

    let max_fee = assert_can_afford(
        wallet_core,
        payer_id,
        config
            .price_per_unit
            .saturating_mul(u128::from(membership.rate_limit)),
        "extend",
    )
    .await;

    let instruction = Instruction::Extend {
        tree_id: *tree_id,
        id_commitment: *id_commitment,
        now_ms,
        price_per_unit: config.price_per_unit,
        rate_limit: membership.rate_limit,
        expiry_timestamp_ms: extended_expiry_ms(&membership),
    };
    let instruction_data =
        Program::serialize_instruction(instruction).expect("instruction serializes");
    send_metered_tx(
        wallet_core,
        programs.registration,
        shard_selectors,
        payer_id,
        instruction_data,
        max_fee,
        "Failed to extend membership",
    )
    .await;
}

/// Erase an expired membership, releasing its rate limit. Any funded account
/// can call this; a membership not yet expired is refused by the guest.
pub async fn erase_membership(
    wallet_core: &WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
    id_commitment: &[u8; 32],
    fee_payer_id: &AccountId,
) {
    crate::fr_bytes::bytes_le_to_fr(id_commitment)
        .expect("id_commitment is not a valid BN254 field element");

    let membership = read_membership(wallet_core, programs, tree_id, id_commitment)
        .await
        .expect("erase: no membership for this id_commitment");
    let now_ms = read_clock_ms(wallet_core).await;

    let shard_selectors = vec![
        config_selector(programs, tree_id),
        membership_selector(programs, tree_id, id_commitment),
        clock_selector(),
    ];

    // Erase pays no price, only the fee.
    let (max_fee, _) = quoted_fee_reserve(wallet_core, "erase").await;
    let instruction = Instruction::Erase {
        tree_id: *tree_id,
        id_commitment: *id_commitment,
        rate_limit: membership.rate_limit,
        now_ms,
    };
    let instruction_data =
        Program::serialize_instruction(instruction).expect("instruction serializes");
    send_metered_tx(
        wallet_core,
        programs.registration,
        shard_selectors,
        fee_payer_id,
        instruction_data,
        max_fee,
        "Failed to erase membership",
    )
    .await;
}

/// Slash a member by revealing their `identity_secret`, ending the membership
/// and returning the rate limit to the pool. Any funded account can call this;
/// the guest checks `id_commitment == Poseidon(identity_secret)`.
pub async fn slash_membership(
    wallet_core: &WalletCore,
    programs: &ProgramIds,
    tree_id: &[u8; 32],
    identity_secret: &[u8; 32],
    id_commitment: &[u8; 32],
    fee_payer_id: &AccountId,
) {
    crate::fr_bytes::bytes_le_to_fr(identity_secret)
        .expect("identity_secret is not a valid BN254 field element");

    let membership = read_membership(wallet_core, programs, tree_id, id_commitment)
        .await
        .expect("slash: no membership for this id_commitment");

    let shard_selectors = vec![
        config_selector(programs, tree_id),
        membership_selector(programs, tree_id, id_commitment),
    ];

    let (max_fee, _) = quoted_fee_reserve(wallet_core, "slash").await;
    let instruction = Instruction::Slash {
        tree_id: *tree_id,
        id_commitment: *id_commitment,
        identity_secret: *identity_secret,
        rate_limit: membership.rate_limit,
    };
    let instruction_data =
        Program::serialize_instruction(instruction).expect("instruction serializes");
    send_metered_tx(
        wallet_core,
        programs.registration,
        shard_selectors,
        fee_payer_id,
        instruction_data,
        max_fee,
        "Failed to slash membership",
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    const GAS: u64 = 10_000_000;

    /// devnet's quote on 2026-09-30: base fee 8, next-block ceiling 9.
    fn devnet_quote() -> FeeStateQuote {
        FeeStateQuote {
            height: 15_448,
            base_fee_exec: 8,
            base_fee_stor: 8,
            next_base_fee_exec_floor: 8,
            next_base_fee_exec_ceiling: 9,
            next_base_fee_stor_floor: 8,
            next_base_fee_stor_ceiling: 9,
            max_gas_exec: 10_000_000,
            max_gas_stor: 1_000_000,
        }
    }

    #[test]
    fn the_reserve_is_sized_from_the_quoted_ceiling() {
        // (10M x 9 + 100k x 9) x 2
        assert_eq!(fee_reserve_from(&devnet_quote(), GAS), 181_800_000);
    }

    #[test]
    fn the_headroom_multiplies_the_quoted_reserve() {
        let quote = devnet_quote();
        let unscaled = u128::from(GAS) * u128::from(quote.next_base_fee_exec_ceiling)
            + ASSUMED_DATA_BYTES * u128::from(quote.next_base_fee_stor_ceiling);
        assert_eq!(fee_reserve_from(&quote, GAS), unscaled * BASE_FEE_HEADROOM);
    }

    #[test]
    fn the_reserve_follows_the_declared_gas_limit() {
        assert_eq!(
            fee_reserve_from(&devnet_quote(), 2_000_000),
            (2_000_000 * 9 + 100_000 * 9) * 2
        );
    }

    #[test]
    fn a_quote_reports_its_height() {
        assert_eq!(
            fee_reserve(Ok::<_, ()>(devnet_quote()), GAS),
            (181_800_000, ReserveBasis::Quote(15_448))
        );
    }

    #[test]
    fn no_quote_falls_back_to_the_fixed_reserve() {
        assert_eq!(
            fee_reserve(Err::<FeeStateQuote, _>("connection refused"), GAS),
            (DECLARED_MAX_FEE, ReserveBasis::Fallback)
        );
        assert_eq!(DECLARED_MAX_FEE, 646_400_000);
    }

    #[test]
    fn the_declared_cap_clears_the_chains_reserve() {
        let quote = devnet_quote();
        let at_ceiling = u128::from(GAS) * u128::from(quote.next_base_fee_exec_ceiling)
            + ASSUMED_DATA_BYTES * u128::from(quote.next_base_fee_stor_ceiling);
        assert!(fee_reserve_from(&quote, GAS) >= at_ceiling);
        assert!(fee_reserve_from(&quote, GAS) < DECLARED_MAX_FEE);
    }

    #[test]
    fn the_reserve_saturates_instead_of_overflowing() {
        let quote = FeeStateQuote {
            next_base_fee_exec_ceiling: u64::MAX,
            next_base_fee_stor_ceiling: u64::MAX,
            ..devnet_quote()
        };
        assert_eq!(fee_reserve_from(&quote, u64::MAX), u128::MAX);
    }

    fn image_id() -> ProgramId {
        [7; 8]
    }

    fn header_for(image_id: ProgramId) -> Vec<u8> {
        ProgramHeader {
            image_id,
            program_first_segment: AccountId::new([1; 32]),
            immutable: true,
        }
        .to_bytes()
    }

    #[test]
    fn an_empty_loader_shard_is_not_deployed() {
        assert_eq!(header_deployed(&[], &image_id()), Ok(false));
    }

    #[test]
    fn a_header_for_this_image_is_deployed() {
        assert_eq!(
            header_deployed(&header_for(image_id()), &image_id()),
            Ok(true)
        );
    }

    #[test]
    fn a_header_for_another_image_is_refused() {
        assert!(header_deployed(&header_for([9; 8]), &image_id()).is_err());
    }

    #[test]
    fn a_loader_shard_that_is_not_a_header_is_refused() {
        assert!(header_deployed(&[1, 2, 3], &image_id()).is_err());
    }

    fn binary(user_elf: &[u8], kernel_elf: &[u8]) -> Vec<u8> {
        risc0_binfmt::ProgramBinary::new(user_elf, kernel_elf).encode()
    }

    #[test]
    fn a_default_kernel_binary_uploads_one_segment_per_chunk() {
        let user = vec![0u8; MAX_SEGMENT_DATA_LEN + 1];
        assert_eq!(
            deploy_segment_count(&binary(&user, risc0_zkos_v1compat::V1COMPAT_ELF)),
            Ok(2)
        );
    }

    #[test]
    fn a_binary_with_another_kernel_is_refused() {
        let err = deploy_segment_count(&binary(&[1, 2, 3], b"not the kernel")).unwrap_err();
        assert!(err.contains("V1COMPAT_ELF"), "{err}");
    }

    #[test]
    fn a_binary_over_the_segment_cap_is_refused() {
        let user = vec![0u8; MAX_SEGMENT_DATA_LEN * MAX_PROGRAM_SEGMENTS + 1];
        assert!(deploy_segment_count(&binary(&user, risc0_zkos_v1compat::V1COMPAT_ELF)).is_err());
    }

    #[test]
    fn bytes_that_are_not_a_program_binary_are_refused() {
        assert!(deploy_segment_count(b"garbage").is_err());
    }

    #[test]
    fn the_clock_selector_names_the_clock_programs_shard_of_clock_50() {
        let selector = clock_selector();
        assert_eq!(
            *selector.account_id.value(),
            rln_layouts::CLOCK_50_ACCOUNT_ID_BYTES
        );
        assert_eq!(
            *selector.program_account_id.value(),
            rln_layouts::clock_program_account_id()
        );
    }
}
