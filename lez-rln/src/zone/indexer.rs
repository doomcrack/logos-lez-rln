//! Reading the registration program's events from a LEZ indexer.
//!
//! The sequencer's RPC serves no events; the indexer does, over `getEvents`,
//! for at most `MAX_EVENT_QUERY_BLOCK_SPAN` blocks per call. Its
//! `event_filter` must cover the program (`"archival"`, or a source naming the
//! program id), or a query answers `UncoveredEventQuery` instead of events.
//!
//! The RPC trait also carries subscriptions, so its client is a WebSocket one:
//! an `http(s)://` URL is dialed as `ws(s)://` on the same port, which the
//! indexer's jsonrpsee server answers.

use indexer_service_protocol::{
    AccountId as IndexerAccountId, BlockId, GetEventsFilter, MAX_EVENT_QUERY_BLOCK_SPAN,
};
use indexer_service_rpc::RpcClient as _;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use nssa::AccountId;

use super::{MembershipSet, RlnEvent, decode_event};

// One program can serve several registries, so the helpers below that build
// a set take the registry's `tree_id` and keep only its events.

/// The indexer URL, from `LEZ_RLN_INDEXER_URL`.
pub fn indexer_url_from_env() -> Option<String> {
    std::env::var("LEZ_RLN_INDEXER_URL").ok()
}

/// One of the program's events, where it landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventAt {
    pub block_id: BlockId,
    pub tx_index: u32,
    pub event: RlnEvent,
}

fn ws_url(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if let Some(rest) = url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else {
        url.to_string()
    }
}

pub async fn connect(url: &str) -> Result<WsClient, String> {
    WsClientBuilder::default()
        .build(ws_url(url))
        .await
        .map_err(|e| format!("cannot reach the indexer at {url}: {e}"))
}

/// The last block the indexer has finalized, or `None` before its first.
pub async fn last_block(client: &WsClient) -> Result<Option<BlockId>, String> {
    client
        .get_last_finalized_block_id()
        .await
        .map_err(|e| format!("getLastFinalizedBlockId: {e}"))
}

/// Every event `program` emitted in blocks `from..=to`, in block order:
/// block, then transaction index, then emission order. Queried in windows of
/// `MAX_EVENT_QUERY_BLOCK_SPAN` blocks.
pub async fn fetch_events(
    client: &WsClient,
    program: &AccountId,
    from: BlockId,
    to: BlockId,
) -> Result<Vec<EventAt>, String> {
    let mut out = Vec::new();
    let mut start = from;
    while start <= to {
        let end = to.min(start.saturating_add(MAX_EVENT_QUERY_BLOCK_SPAN - 1));
        let records = client
            .get_events(GetEventsFilter {
                from_block: Some(start),
                to_block: Some(end),
                tx_hash: None,
                program_account_id: Some(IndexerAccountId {
                    value: *program.value(),
                }),
                selector: None,
            })
            .await
            .map_err(|e| format!("getEvents {start}..={end}: {e}"))?;
        for record in records {
            out.push(EventAt {
                block_id: record.block_id,
                tx_index: record.tx_index,
                event: decode_event(record.selector.0, &record.data).map_err(|e| {
                    format!("block {} tx {}: {e}", record.block_id, record.tx_index)
                })?,
            });
        }
        let Some(next) = end.checked_add(1) else {
            break;
        };
        start = next;
    }
    // The indexer answers in block order; a stable sort keeps emission order
    // within a transaction should a window ever come back out of order.
    out.sort_by_key(|e| (e.block_id, e.tx_index));
    Ok(out)
}

/// Every event `program` has emitted for registry `tree_id` up to the
/// indexer's last finalized block, in block order.
pub async fn fetch_all_events(
    url: &str,
    program: &AccountId,
    tree_id: &[u8; 32],
) -> Result<Vec<EventAt>, String> {
    let client = connect(url).await?;
    let events = match last_block(&client).await? {
        Some(tip) => fetch_events(&client, program, 0, tip).await?,
        None => Vec::new(),
    };
    Ok(events
        .into_iter()
        .filter(|at| at.event.tree_id() == *tree_id)
        .collect())
}

/// The membership set of registry `tree_id`, built from every event the
/// indexer holds for it, expired at `now_ms` when given.
pub async fn membership_set(
    url: &str,
    program: &AccountId,
    tree_id: &[u8; 32],
    now_ms: Option<u64>,
) -> Result<MembershipSet, String> {
    let mut set = MembershipSet::default();
    for at in fetch_all_events(url, program, tree_id).await? {
        set.apply(&at.event)
            .map_err(|e| format!("block {} tx {}: {e}", at.block_id, at.tx_index))?;
    }
    if let Some(now_ms) = now_ms {
        set.expire(now_ms);
    }
    Ok(set)
}

/// Poll the indexer until `id_commitment` has a live leaf, and return the set
/// it was found in. The indexer trails the sequencer, so a registration the
/// chain already holds may take a few blocks to show up here.
pub async fn wait_for_member(
    url: &str,
    program: &AccountId,
    tree_id: &[u8; 32],
    id_commitment: &[u8; 32],
    attempts: u32,
) -> Result<MembershipSet, String> {
    for _ in 0..attempts {
        let set = membership_set(url, program, tree_id, None).await?;
        if set.member(id_commitment).is_some_and(|m| m.live) {
            return Ok(set);
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    Err(format!(
        "no live leaf for {} in the indexer's events after {attempts} polls",
        hex::encode(id_commitment)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_urls_are_dialed_as_websockets() {
        assert_eq!(ws_url("http://127.0.0.1:8779"), "ws://127.0.0.1:8779");
        assert_eq!(ws_url("https://indexer.example"), "wss://indexer.example");
        assert_eq!(ws_url("ws://127.0.0.1:8779"), "ws://127.0.0.1:8779");
    }
}
