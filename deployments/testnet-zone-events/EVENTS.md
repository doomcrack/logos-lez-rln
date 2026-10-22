# testnet-zone-events: reading the program's events

This note is for a service that queries LEZ for the events the RLN registration program emits, and keeps listening for new ones. It covers the deployment on testnet built from `feat/rln-zone-events`.

The service needs a few values from this deployment, plus access to a LEZ **indexer**. The sequencer at `https://testnet.lez.logos.co/` has no event methods, so the events can only come from an indexer.

## Values from this deployment

| What | Value |
|---|---|
| Program account ID (what to filter on) | `HAxY9SiqUjJQHdtvazFDWFCxn1Jw1dtbUGio8DMC4bBw` |
| Same ID in hex (the `registration_program_id`) | `f04803944507677bb79b27b61cd0ad6eea81928f281570347e2df6249495106a` |
| Registry (`tree_id`), the first field of every event | `47b2de4f08080e74e2d4beffe8e5e87e709dd598619c9b322b64f2756979b4cf` |
| Config account | `BpxYQFLWf6Wi5HhWAaZRtbhxmeKa5P9THK7WBDCoXRg9` |
| Start block | **49431**, where the program was deployed. No event can come before it. |

The base58 ID and the hex ID are the same 32 bytes. The indexer's JSON-RPC takes the base58 form.

The `tree_id` matters because one program can serve several registries. The service should keep only the events whose `tree_id` matches. Right now there is only this one registry.

## Event formats

Each event has an 8-byte selector and borsh data. The selector is the first 8 bytes of `sha256("rln_registration::<Name>")`. All integers are u64 little-endian, with no length prefixes.

| Event | Selector | Data | Size |
|---|---|---|---|
| Registered | `b7ab5ade1703cde8` | tree_id(32), id_commitment(32), rate_limit, expiry_timestamp_ms, leaf_index | 88 B |
| Extended | `631ffa56866231d2` | tree_id(32), id_commitment(32), expiry_timestamp_ms | 72 B |
| Slashed | `19e9a783dd521a1b` | tree_id(32), id_commitment(32) | 64 B |
| Erased | `88af4b20b9dcb6aa` | tree_id(32), id_commitment(32) | 64 B |

If the service is written in Rust, it can depend on `rln-layouts` ([`events.rs`](../../lez-rln/rln-layouts/src/events.rs), `RlnEvent::decode`) instead of parsing the bytes itself. The tree it builds uses `Poseidon(id_commitment, rate_limit)` as the leaf at `leaf_index`. The rules for applying each event are in the [README](../../README.md)'s events section, and [`src/zone/reader.rs`](../../lez-rln/src/zone/reader.rs) implements them.

## Indexer methods (LEZ v0.3.1)

- **Past events:** `getEvents({from_block, to_block, program_account_id, selector?, tx_hash?})`.
  - Each call covers at most **1000 blocks**, so the service has to page from 49431 up to the tip. `getLastFinalizedBlockId` returns the tip.
  - Results come back in (block, tx_index, emission) order. Each record has `block_id`, `tx_index`, `tx_hash`, `program_account_id`, `selector` and base64 `data`.
- **New events:** the websocket subscription `subscribeToEvents({program_account_id, selector?, tx_hash?})`. It takes no block range.
- **Avoiding gaps:** subscribe first, then page through the past events, and drop duplicates by (block_id, tx_index, position). Otherwise events from the gap between the two steps can be lost or counted twice.
- **Selector filter:** leave it out to get all four event types in one stream. Their relative order matters for rebuilding the tree.

## Open questions

- **Which indexer to use on testnet.** There's no testnet indexer URL yet. The deployment only records the sequencer.
- **Whether that indexer keeps our events.** An indexer only stores events its `event_filter` config allows, and the default stores none. It needs either `"archival"` or a source entry like `{"program_id": "HAxY9SiqUjJQHdtvazFDWFCxn1Jw1dtbUGio8DMC4bBw"}`, optionally with the four selectors.
- **Whether it catches up on old blocks.** If the filter is added after block 49431, it hasn't been checked whether the indexer goes back and stores events from earlier blocks.

## Current state on chain

As of 2026-10-21, the config account shows 3 registrations, each at rate limit 100:

- `total_registrations` is 3.
- `current_total_rate_limit` is 300.
- `next_leaf_index` is 3.
- The treasury holds 3,000,000, which is three payments of 1e6.

So a correct reader should find three `Registered` events, with leaf indices 0, 1 and 2. These haven't been checked against an indexer yet.
