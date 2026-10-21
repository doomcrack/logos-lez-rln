//! The derivation rules: from the registration program's events to the
//! membership tree.

use std::collections::HashMap;

use rln::prelude::{Fr, Hasher, PoseidonHash, RLNMerkleProof};

use super::RlnEvent;
use crate::{
    fr_bytes::{bytes_le_to_fr, fr_to_bytes_le},
    proof_circuit::{CIRCUIT_DEPTH, zero_ladder},
    rln::client::registration_leaf,
};

/// One change to the tree, in the order a reader applies them. These are the
/// `Insert`/`Remove` changes a Zone batch carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// `rate_commitment = poseidon(id_commitment, rate_limit)` at `leaf_index`.
    Insert {
        leaf_index: u64,
        rate_commitment: [u8; 32],
    },
    /// Zero the leaf at `leaf_index`.
    Remove { leaf_index: u64 },
}

/// What a reader knows of one registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub id_commitment: [u8; 32],
    pub rate_limit: u64,
    pub expiry_timestamp_ms: u64,
    pub leaf_index: u64,
    /// The leaf holds the member's rate commitment.
    pub live: bool,
    /// Slashed or erased: the registration is over, and its index is never
    /// reused. A later `Registered` for the same commitment takes a new index.
    pub ended: bool,
}

/// Why an event cannot be applied. Each is something the registration program
/// does not allow, so it means the reader missed or misordered events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReaderError {
    /// Every leaf of a `depth` tree is taken.
    TreeFull { depth: usize },
    /// `Registered` for a commitment whose registration has not ended.
    AlreadyRegistered { id_commitment: [u8; 32] },
    /// An event for a commitment with no ongoing registration.
    UnknownMember { id_commitment: [u8; 32] },
    /// A `Registered` event's leaf index is not the next one: the chain
    /// assigns them consecutively, so an event was missed or misordered.
    LeafIndexMismatch { expected: u64, event: u64 },
}

impl std::fmt::Display for ReaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TreeFull { depth } => write!(f, "every leaf of the depth-{depth} tree is taken"),
            Self::AlreadyRegistered { id_commitment } => write!(
                f,
                "{} is registered and its registration has not ended",
                hex::encode(id_commitment)
            ),
            Self::UnknownMember { id_commitment } => write!(
                f,
                "{} has no ongoing registration",
                hex::encode(id_commitment)
            ),
            Self::LeafIndexMismatch { expected, event } => write!(
                f,
                "the next leaf index is {expected}, the Registered event says {event}"
            ),
        }
    }
}

impl std::error::Error for ReaderError {}

/// Merkle proof for a leaf of a [`MembershipSet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    /// The leaf value at `leaf_index`.
    pub leaf: [u8; 32],
    /// Sibling hashes from the leaf level up to the root (length = depth).
    pub path_elements: Vec<[u8; 32]>,
    /// 0 if the node on the path is a left child, 1 if a right child.
    pub path_indices: Vec<u8>,
    /// The root the proof verifies against.
    pub root: [u8; 32],
    pub leaf_index: u64,
}

/// The membership set a reader derives from the registration program's
/// events: a Poseidon Merkle tree of `depth` levels whose leaves are rate
/// commitments, plus what each registration's later events need.
///
/// One set is one registry: feed it only the events of one `tree_id`
/// ([`super::for_registry`]). A program serving several registries emits all
/// of their events under the same program id.
///
/// Leaf indices come from the `Registered` events, which the chain numbers
/// 0, 1, 2… per registry (the config's `next_leaf_index`); the set checks each
/// is the next one. They are never reused: `next_index` only advances.
#[derive(Debug, Clone)]
pub struct MembershipSet {
    depth: usize,
    /// Every registration ever seen, indexed by leaf index.
    members: Vec<Member>,
    /// The leaf index of each commitment's latest registration.
    latest: HashMap<[u8; 32], u64>,
    /// Non-empty nodes, keyed by `(height, index)`; height 0 is the leaves.
    nodes: HashMap<(usize, u64), Fr>,
}

impl Default for MembershipSet {
    /// A set at the depth of the circuit proofs are made against.
    fn default() -> Self {
        Self::new(CIRCUIT_DEPTH)
    }
}

impl MembershipSet {
    /// An empty set over a `depth`-level tree. Proofs made with
    /// [`proof_to_circuit`] need `depth == CIRCUIT_DEPTH`.
    pub fn new(depth: usize) -> Self {
        assert!(
            (1..=CIRCUIT_DEPTH).contains(&depth),
            "depth {depth} is outside 1..={CIRCUIT_DEPTH}: the empty-subtree ladder stops there"
        );
        Self {
            depth,
            members: Vec::new(),
            latest: HashMap::new(),
            nodes: HashMap::new(),
        }
    }

    /// A set built by applying `events` in order, then nothing else.
    pub fn from_events<'a>(
        depth: usize,
        events: impl IntoIterator<Item = &'a RlnEvent>,
    ) -> Result<Self, ReaderError> {
        let mut set = Self::new(depth);
        for event in events {
            set.apply(event)?;
        }
        Ok(set)
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    /// The index the next `Registered` event takes.
    pub fn next_index(&self) -> u64 {
        self.members.len() as u64
    }

    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// The commitment's latest registration, ended or not.
    pub fn member(&self, id_commitment: &[u8; 32]) -> Option<&Member> {
        self.latest
            .get(id_commitment)
            .map(|&index| &self.members[index as usize])
    }

    /// The leaf index of the commitment's latest registration.
    pub fn leaf_index_of(&self, id_commitment: &[u8; 32]) -> Option<u64> {
        self.latest.get(id_commitment).copied()
    }

    /// Apply one event. Returns the tree change it produces, if any.
    pub fn apply(&mut self, event: &RlnEvent) -> Result<Option<Change>, ReaderError> {
        match event {
            RlnEvent::Registered(e) => {
                if let Some(member) = self.member(&e.id_commitment)
                    && !member.ended
                {
                    return Err(ReaderError::AlreadyRegistered {
                        id_commitment: e.id_commitment,
                    });
                }
                let leaf_index = e.leaf_index;
                if leaf_index != self.next_index() {
                    return Err(ReaderError::LeafIndexMismatch {
                        expected: self.next_index(),
                        event: leaf_index,
                    });
                }
                if leaf_index >= 1u64 << self.depth {
                    return Err(ReaderError::TreeFull { depth: self.depth });
                }
                self.members.push(Member {
                    id_commitment: e.id_commitment,
                    rate_limit: e.rate_limit,
                    expiry_timestamp_ms: e.expiry_timestamp_ms,
                    leaf_index,
                    live: true,
                    ended: false,
                });
                self.latest.insert(e.id_commitment, leaf_index);
                Ok(Some(self.insert(leaf_index)))
            }
            RlnEvent::Slashed(e) => {
                let leaf_index = self.ongoing(&e.id_commitment)?;
                self.members[leaf_index as usize].ended = true;
                // A slash after the leaf expired changes nothing in the tree.
                Ok(self.remove(leaf_index))
            }
            RlnEvent::Extended(e) => {
                let leaf_index = self.ongoing(&e.id_commitment)?;
                let member = &mut self.members[leaf_index as usize];
                member.expiry_timestamp_ms = e.expiry_timestamp_ms;
                // The chain accepts an extension dated up to
                // `CLOCK_CLAIM_TOLERANCE_MS` behind its clock, so one can land
                // after a reader judged the leaf expired. The registration
                // never ended; put the leaf back where it was.
                Ok((!member.live).then(|| self.insert(leaf_index)))
            }
            RlnEvent::Erased(e) => {
                let leaf_index = self.ongoing(&e.id_commitment)?;
                self.members[leaf_index as usize].ended = true;
                // Erase requires an expired membership, so the expiry step has
                // normally removed the leaf already. If it has not, remove it:
                // an erased registration must not stay in the set.
                Ok(self.remove(leaf_index))
            }
        }
    }

    /// The expiry step: remove every live leaf whose registration expired at
    /// or before `now_ms` (`rln_layouts::is_expired`), in leaf order.
    pub fn expire(&mut self, now_ms: u64) -> Vec<Change> {
        let expired: Vec<u64> = self
            .members
            .iter()
            .filter(|m| m.live && now_ms >= m.expiry_timestamp_ms)
            .map(|m| m.leaf_index)
            .collect();
        expired
            .into_iter()
            .filter_map(|leaf_index| self.remove(leaf_index))
            .collect()
    }

    /// The tree's root, little-endian.
    pub fn root(&self) -> [u8; 32] {
        fr_to_bytes_le(&self.node(self.depth, 0))
    }

    /// The inclusion proof of `leaf_index` against the current root.
    pub fn proof(&self, leaf_index: u64) -> MerkleProof {
        assert!(
            leaf_index < 1u64 << self.depth,
            "leaf {leaf_index} is past the last leaf of a depth-{} tree",
            self.depth
        );
        let mut path_elements = Vec::with_capacity(self.depth);
        let mut path_indices = Vec::with_capacity(self.depth);
        let mut index = leaf_index;
        for height in 0..self.depth {
            path_indices.push((index % 2) as u8);
            path_elements.push(fr_to_bytes_le(&self.node(height, index ^ 1)));
            index /= 2;
        }
        MerkleProof {
            leaf: fr_to_bytes_le(&self.node(0, leaf_index)),
            path_elements,
            path_indices,
            root: self.root(),
            leaf_index,
        }
    }

    /// The leaf index of the commitment's ongoing registration.
    fn ongoing(&self, id_commitment: &[u8; 32]) -> Result<u64, ReaderError> {
        self.member(id_commitment)
            .filter(|m| !m.ended)
            .map(|m| m.leaf_index)
            .ok_or(ReaderError::UnknownMember {
                id_commitment: *id_commitment,
            })
    }

    fn insert(&mut self, leaf_index: u64) -> Change {
        let member = &mut self.members[leaf_index as usize];
        member.live = true;
        let rate_commitment = registration_leaf(&member.id_commitment, member.rate_limit);
        self.set_leaf(
            leaf_index,
            bytes_le_to_fr(&rate_commitment).expect("a Poseidon output is a field element"),
        );
        Change::Insert {
            leaf_index,
            rate_commitment,
        }
    }

    /// Zero a live leaf; `None` if it already reads zero.
    fn remove(&mut self, leaf_index: u64) -> Option<Change> {
        let member = &mut self.members[leaf_index as usize];
        if !member.live {
            return None;
        }
        member.live = false;
        self.set_leaf(leaf_index, Fr::from(0u64));
        Some(Change::Remove { leaf_index })
    }

    fn node(&self, height: usize, index: u64) -> Fr {
        self.nodes
            .get(&(height, index))
            .copied()
            .unwrap_or(zero_ladder()[height])
    }

    fn set_leaf(&mut self, leaf_index: u64, value: Fr) {
        let mut index = leaf_index;
        let mut node = value;
        for height in 0..=self.depth {
            if node == zero_ladder()[height] {
                self.nodes.remove(&(height, index));
            } else {
                self.nodes.insert((height, index), node);
            }
            if height == self.depth {
                break;
            }
            let sibling = self.node(height, index ^ 1);
            node = if index.is_multiple_of(2) {
                Hasher::<PoseidonHash>::hash_pair(node, sibling)
            } else {
                Hasher::<PoseidonHash>::hash_pair(sibling, node)
            };
            index /= 2;
        }
    }
}

/// A proof as zerokit's witness inputs: the [`RLNMerkleProof`] and the root as
/// a field element. The circuit takes exactly [`CIRCUIT_DEPTH`] siblings, so
/// the proof must come from a set of that depth.
pub fn proof_to_circuit(proof: &MerkleProof) -> (RLNMerkleProof, Fr) {
    assert_eq!(
        proof.path_elements.len(),
        CIRCUIT_DEPTH,
        "the circuit proves depth-{CIRCUIT_DEPTH} paths; build the MembershipSet at that depth"
    );
    let path_elements = proof
        .path_elements
        .iter()
        .map(|bytes| bytes_le_to_fr(bytes).expect("Invalid path element"))
        .collect();
    let root = bytes_le_to_fr(&proof.root).expect("Invalid root");
    (
        RLNMerkleProof::new(path_elements, proof.path_indices.clone()),
        root,
    )
}

#[cfg(test)]
mod tests {
    use rln_layouts::events::{Erased, Extended, Registered, Slashed};

    use super::*;

    const DEPTH: usize = 4;
    const TREE: [u8; 32] = [7; 32];

    /// A valid field element: small values are always below the modulus.
    fn id(n: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = n;
        b
    }

    fn registered(n: u8, leaf_index: u64, expiry: u64) -> RlnEvent {
        RlnEvent::Registered(Registered {
            tree_id: TREE,
            id_commitment: id(n),
            rate_limit: 100 + u64::from(n),
            expiry_timestamp_ms: expiry,
            leaf_index,
        })
    }

    fn slashed(n: u8) -> RlnEvent {
        RlnEvent::Slashed(Slashed {
            tree_id: TREE,
            id_commitment: id(n),
        })
    }

    fn erased(n: u8) -> RlnEvent {
        RlnEvent::Erased(Erased {
            tree_id: TREE,
            id_commitment: id(n),
        })
    }

    fn extended(n: u8, expiry: u64) -> RlnEvent {
        RlnEvent::Extended(Extended {
            tree_id: TREE,
            id_commitment: id(n),
            expiry_timestamp_ms: expiry,
        })
    }

    fn leaf(n: u8) -> Fr {
        bytes_le_to_fr(&registration_leaf(&id(n), 100 + u64::from(n))).unwrap()
    }

    /// The root of a depth-`DEPTH` tree holding `leaves` from index 0, built
    /// level by level with no sparse shortcuts.
    fn dense_root(leaves: &[Fr]) -> [u8; 32] {
        let mut level: Vec<Fr> = (0..1usize << DEPTH)
            .map(|i| leaves.get(i).copied().unwrap_or(Fr::from(0u64)))
            .collect();
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| Hasher::<PoseidonHash>::hash_pair(pair[0], pair[1]))
                .collect();
        }
        fr_to_bytes_le(&level[0])
    }

    fn zero() -> Fr {
        Fr::from(0u64)
    }

    #[test]
    fn an_empty_set_has_the_empty_root() {
        let set = MembershipSet::new(DEPTH);
        assert_eq!(set.root(), fr_to_bytes_le(&zero_ladder()[DEPTH]));
        assert_eq!(set.root(), dense_root(&[]));
    }

    #[test]
    fn registrations_take_consecutive_indices() {
        let mut set = MembershipSet::new(DEPTH);
        assert_eq!(
            set.apply(&registered(1, 0, 10)),
            Ok(Some(Change::Insert {
                leaf_index: 0,
                rate_commitment: registration_leaf(&id(1), 101),
            }))
        );
        assert_eq!(
            set.apply(&registered(2, 1, 10)).unwrap(),
            Some(Change::Insert {
                leaf_index: 1,
                rate_commitment: registration_leaf(&id(2), 102),
            })
        );
        assert_eq!(set.leaf_index_of(&id(2)), Some(1));
        assert_eq!(set.root(), dense_root(&[leaf(1), leaf(2)]));
    }

    #[test]
    fn a_slash_zeroes_the_leaf_and_its_index_is_never_reused() {
        let mut set = MembershipSet::new(DEPTH);
        set.apply(&registered(1, 0, 10)).unwrap();
        set.apply(&registered(2, 1, 10)).unwrap();
        assert_eq!(
            set.apply(&slashed(1)).unwrap(),
            Some(Change::Remove { leaf_index: 0 })
        );
        assert_eq!(set.root(), dense_root(&[zero(), leaf(2)]));

        // Re-registering the slashed commitment appends; index 0 stays empty.
        assert_eq!(
            set.apply(&registered(1, 2, 20)).unwrap(),
            Some(Change::Insert {
                leaf_index: 2,
                rate_commitment: registration_leaf(&id(1), 101),
            })
        );
        assert_eq!(set.root(), dense_root(&[zero(), leaf(2), leaf(1)]));
    }

    #[test]
    fn expiry_removes_and_erase_then_changes_nothing() {
        let mut set = MembershipSet::new(DEPTH);
        set.apply(&registered(1, 0, 10)).unwrap();
        set.apply(&registered(2, 1, 30)).unwrap();
        assert_eq!(set.expire(9), vec![]);
        assert_eq!(set.expire(10), vec![Change::Remove { leaf_index: 0 }]);
        assert_eq!(set.root(), dense_root(&[zero(), leaf(2)]));
        assert_eq!(set.apply(&erased(1)).unwrap(), None);
        assert!(set.member(&id(1)).unwrap().ended);
    }

    #[test]
    fn an_erase_of_a_live_leaf_removes_it_defensively() {
        let mut set = MembershipSet::new(DEPTH);
        set.apply(&registered(1, 0, 10)).unwrap();
        assert_eq!(
            set.apply(&erased(1)).unwrap(),
            Some(Change::Remove { leaf_index: 0 })
        );
        assert_eq!(set.root(), dense_root(&[]));
    }

    #[test]
    fn a_slash_after_expiry_changes_nothing_but_ends_the_registration() {
        let mut set = MembershipSet::new(DEPTH);
        set.apply(&registered(1, 0, 10)).unwrap();
        set.expire(10);
        assert_eq!(set.apply(&slashed(1)).unwrap(), None);
        assert!(set.member(&id(1)).unwrap().ended);
    }

    #[test]
    fn an_extension_moves_the_expiry() {
        let mut set = MembershipSet::new(DEPTH);
        set.apply(&registered(1, 0, 10)).unwrap();
        assert_eq!(set.apply(&extended(1, 50)).unwrap(), None);
        assert_eq!(set.expire(10), vec![]);
        assert_eq!(set.expire(50), vec![Change::Remove { leaf_index: 0 }]);
    }

    /// The chain can accept an extension dated before the reader's expiry
    /// step ran; the leaf goes back at its own index.
    #[test]
    fn a_late_extension_reinserts_the_leaf_at_its_index() {
        let mut set = MembershipSet::new(DEPTH);
        set.apply(&registered(1, 0, 10)).unwrap();
        set.apply(&registered(2, 1, 10)).unwrap();
        set.expire(10);
        assert_eq!(
            set.apply(&extended(1, 50)).unwrap(),
            Some(Change::Insert {
                leaf_index: 0,
                rate_commitment: registration_leaf(&id(1), 101),
            })
        );
        assert_eq!(set.root(), dense_root(&[leaf(1), zero()]));
    }

    #[test]
    fn events_the_program_never_emits_are_errors() {
        let mut set = MembershipSet::new(DEPTH);
        assert_eq!(
            set.apply(&slashed(1)),
            Err(ReaderError::UnknownMember {
                id_commitment: id(1)
            })
        );
        set.apply(&registered(1, 0, 10)).unwrap();
        assert_eq!(
            set.apply(&registered(1, 1, 10)),
            Err(ReaderError::AlreadyRegistered {
                id_commitment: id(1)
            })
        );
        assert_eq!(
            set.apply(&registered(2, 2, 10)),
            Err(ReaderError::LeafIndexMismatch {
                expected: 1,
                event: 2
            })
        );
        set.apply(&slashed(1)).unwrap();
        assert_eq!(
            set.apply(&erased(1)),
            Err(ReaderError::UnknownMember {
                id_commitment: id(1)
            })
        );
    }

    #[test]
    fn a_full_tree_refuses_another_registration() {
        let mut set = MembershipSet::new(1);
        set.apply(&registered(1, 0, 10)).unwrap();
        set.apply(&registered(2, 1, 10)).unwrap();
        assert_eq!(
            set.apply(&registered(3, 2, 10)),
            Err(ReaderError::TreeFull { depth: 1 })
        );
    }

    #[test]
    fn a_proof_folds_to_the_root() {
        let mut set = MembershipSet::new(DEPTH);
        for n in 1..=5 {
            set.apply(&registered(n, u64::from(n) - 1, 10)).unwrap();
        }
        set.apply(&slashed(2)).unwrap();
        for leaf_index in 0..5 {
            let proof = set.proof(leaf_index);
            let mut node = bytes_le_to_fr(&proof.leaf).unwrap();
            for (sibling, &is_right) in proof.path_elements.iter().zip(&proof.path_indices) {
                let sibling = bytes_le_to_fr(sibling).unwrap();
                node = if is_right == 0 {
                    Hasher::<PoseidonHash>::hash_pair(node, sibling)
                } else {
                    Hasher::<PoseidonHash>::hash_pair(sibling, node)
                };
            }
            assert_eq!(fr_to_bytes_le(&node), set.root(), "leaf {leaf_index}");
        }
        assert_eq!(set.proof(1).leaf, [0u8; 32], "the slashed leaf reads zero");
    }

    #[test]
    fn readers_fed_the_same_events_agree() {
        let events = [
            registered(1, 0, 10),
            registered(2, 1, 30),
            slashed(1),
            extended(2, 60),
            registered(3, 2, 40),
        ];
        let a = MembershipSet::from_events(DEPTH, &events).unwrap();
        let b = MembershipSet::from_events(DEPTH, &events).unwrap();
        assert_eq!(a.root(), b.root());
        assert_eq!(a.leaf_index_of(&id(3)), Some(2));
    }
}
