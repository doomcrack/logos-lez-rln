//! Decoding the registration program's events.

use nssa::AccountId;
use nssa_core::program::TransactionEvent;
pub use rln_layouts::events::{Erased, Extended, Registered, RlnEvent, Slashed};

/// Decode one event `program` emitted.
///
/// The program emits only the four `rln_layouts::events` selectors, so an
/// unknown selector or undecodable data from it means the reader and the
/// deployed program disagree on the event format: an error, not something to
/// skip, since a reader that skipped one would miss a tree change.
pub fn decode_event(selector: [u8; 8], data: &[u8]) -> Result<RlnEvent, String> {
    match RlnEvent::decode(selector, data) {
        Some(Ok(event)) => Ok(event),
        Some(Err(e)) => Err(format!(
            "event {} does not decode: {e}",
            hex::encode(selector)
        )),
        None => Err(format!(
            "selector {} is not one the registration program emits",
            hex::encode(selector)
        )),
    }
}

/// The events of registry `tree_id`, in their order.
pub fn for_registry<'a>(
    tree_id: &'a [u8; 32],
    events: impl IntoIterator<Item = &'a RlnEvent>,
) -> impl Iterator<Item = &'a RlnEvent> {
    events.into_iter().filter(move |e| e.tree_id() == *tree_id)
}

/// The events `program` emitted in one transaction, in emission order. Events
/// of every other program (the native transfer, say) are skipped.
pub fn decode_transaction_events(
    program: &AccountId,
    events: &[TransactionEvent],
) -> Result<Vec<RlnEvent>, String> {
    events
        .iter()
        .filter(|event| event.account_id == *program)
        .map(|event| decode_event(event.event.selector, &event.event.data))
        .collect()
}

#[cfg(test)]
mod tests {
    use nssa_core::program::ProgramEvent;

    use super::*;

    fn transaction_event(program: [u8; 32], event: &RlnEvent) -> TransactionEvent {
        let (selector, data) = event.encode();
        TransactionEvent {
            account_id: AccountId::new(program),
            event: ProgramEvent { selector, data },
        }
    }

    fn registered(n: u8) -> RlnEvent {
        RlnEvent::Registered(Registered {
            tree_id: [7; 32],
            id_commitment: [n; 32],
            rate_limit: 100,
            expiry_timestamp_ms: 1,
            leaf_index: u64::from(n),
        })
    }

    #[test]
    fn only_the_programs_events_are_decoded_in_order() {
        let ours = [0xA1; 32];
        let events = [
            transaction_event(ours, &registered(1)),
            transaction_event([0xEE; 32], &registered(2)),
            transaction_event(ours, &registered(3)),
        ];
        assert_eq!(
            decode_transaction_events(&AccountId::new(ours), &events),
            Ok(vec![registered(1), registered(3)])
        );
    }

    #[test]
    fn an_unknown_selector_from_the_program_is_an_error() {
        let ours = [0xA1; 32];
        let event = TransactionEvent {
            account_id: AccountId::new(ours),
            event: ProgramEvent {
                selector: [0; 8],
                data: vec![],
            },
        };
        assert!(decode_transaction_events(&AccountId::new(ours), &[event]).is_err());
    }
}
