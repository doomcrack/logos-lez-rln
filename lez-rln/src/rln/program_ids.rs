//! Where the deployed registration program lives.
//!
//! A program's account id is the header account its deployer created and
//! signed, so it cannot be derived from the `.bin`: it is deployment state.
//! `run_setup` records it per tree in `~/.logos-lez-rln/programs_<tree_hex>.json`
//! as `{"registration_program_id":"<64hex>"}`, and every tool reads it back
//! from there. `LEZ_RLN_REGISTRATION_PROGRAM_ID` (64 hex) overrides the record,
//! which is also how a new tree reuses a program deployed for another.
//!
//! There is no merkle program: the registration program emits events and
//! readers keep the tree. A record written before that change also carries a
//! `merkle_program_id`; it is ignored.

use std::path::PathBuf;

use nssa::AccountId;

use super::client::DATA_DIR;

pub const REGISTRATION_PROGRAM_ID_ENV: &str = "LEZ_RLN_REGISTRATION_PROGRAM_ID";

const REGISTRATION_KEY: &str = "registration_program_id";

/// The account id of the deployed registration program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramIds {
    pub registration: AccountId,
}

pub fn hex_id(id: &AccountId) -> String {
    hex::encode(id.value())
}

fn parse_hex_id(raw: &str, what: &str) -> Result<AccountId, String> {
    let bytes = hex::decode(raw.trim()).map_err(|e| format!("{what} is not hex: {e}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("{what} must be 32 bytes, got {}", v.len()))?;
    Ok(AccountId::new(bytes))
}

pub fn record_path(tree_id: &[u8; 32]) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(DATA_DIR)
        .join(format!("programs_{}.json", hex::encode(tree_id)))
}

pub fn encode_record(ids: &ProgramIds) -> String {
    serde_json::json!({
        REGISTRATION_KEY: hex_id(&ids.registration),
    })
    .to_string()
}

pub fn decode_record(json: &str) -> Result<ProgramIds, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("not JSON: {e}"))?;
    let registration = value
        .get(REGISTRATION_KEY)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("missing string field `{REGISTRATION_KEY}`"))
        .and_then(|raw| parse_hex_id(raw, REGISTRATION_KEY))?;
    Ok(ProgramIds { registration })
}

pub fn save_program_ids(tree_id: &[u8; 32], ids: &ProgramIds) {
    let path = record_path(tree_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, encode_record(ids))
        .unwrap_or_else(|e| panic!("Failed to write {}: {e}", path.display()));
}

/// The program id known for `tree_id`: environment first, then the record.
pub fn known_program_ids(tree_id: &[u8; 32]) -> Result<Option<ProgramIds>, String> {
    if let Ok(raw) = std::env::var(REGISTRATION_PROGRAM_ID_ENV) {
        return parse_hex_id(&raw, REGISTRATION_PROGRAM_ID_ENV)
            .map(|registration| Some(ProgramIds { registration }));
    }
    let path = record_path(tree_id);
    match std::fs::read_to_string(&path) {
        Ok(json) => decode_record(&json)
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display())),
        Err(_) => Ok(None),
    }
}

/// The program id for `tree_id`, or exit with what to set.
pub fn program_ids_or_exit(tree_id: &[u8; 32]) -> ProgramIds {
    let known = known_program_ids(tree_id).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2);
    });
    known.unwrap_or_else(|| {
        eprintln!(
            "No program id for tree {}: run `run_setup`, or set {REGISTRATION_PROGRAM_ID_ENV} \
             (64 hex), or write {}",
            hex::encode(tree_id),
            record_path(tree_id).display()
        );
        std::process::exit(2);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_round_trips() {
        let ids = ProgramIds {
            registration: AccountId::new([0xA1; 32]),
        };
        assert_eq!(decode_record(&encode_record(&ids)), Ok(ids));
    }

    #[test]
    fn the_record_spells_ids_as_hex() {
        let ids = ProgramIds {
            registration: AccountId::new([0x01; 32]),
        };
        let value: serde_json::Value = serde_json::from_str(&encode_record(&ids)).unwrap();
        assert_eq!(value[REGISTRATION_KEY], "01".repeat(32));
    }

    /// A record from the merkle-tree era still names the registration program.
    #[test]
    fn a_legacy_record_with_a_merkle_id_is_read() {
        let json = format!(
            "{{\"{REGISTRATION_KEY}\":\"{}\",\"merkle_program_id\":\"{}\"}}",
            "01".repeat(32),
            "02".repeat(32)
        );
        assert_eq!(
            decode_record(&json),
            Ok(ProgramIds {
                registration: AccountId::new([0x01; 32])
            })
        );
    }

    #[test]
    fn a_record_missing_the_id_is_refused() {
        assert!(decode_record("{}").is_err());
    }

    #[test]
    fn a_short_id_is_refused() {
        let json = format!("{{\"{REGISTRATION_KEY}\":\"0102\"}}");
        assert!(decode_record(&json).is_err());
    }
}
