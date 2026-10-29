//! The RLN circuit this repo proves against.
//!
//! The membership tree lives with its readers, rebuilt from the registration
//! program's events (`crate::zone`), so its depth is the circuit's, not what
//! a transaction's gas can hash. Readers build it at exactly
//! [`CIRCUIT_DEPTH`], and a proof's path and root need no lifting to the
//! circuit's shape.

use std::sync::LazyLock;

use rln::prelude::{
    ArkGroth16Backend, Fr, Hasher, PoseidonHash, RLN, RLNBuilder, Stateless, graph_from_raw,
    zkey_from_raw,
};

/// The depth of the circuit we prove against.
///
/// Ten is the smallest zerokit publishes. It ships those artifacts in its
/// repository but excludes them from the crates.io package to stay under the
/// size limit, so they are vendored here; their circuit version is the one the
/// crate already carries, since the repository's pair is byte for byte the pair
/// embedded in `rln` 3.0.0.
pub const CIRCUIT_DEPTH: usize = 10;

const DEPTH_10_GRAPH: &[u8] = include_bytes!("../resources/tree_depth_10/graph.bin");
const DEPTH_10_ZKEY: &[u8] = include_bytes!("../resources/tree_depth_10/rln_final.arkzkey");

/// `zero_ladder()[h]` is the root of an all-empty subtree of height `h`, so
/// index 0 is the zero leaf itself.
pub fn zero_ladder() -> &'static [Fr] {
    static LADDER: LazyLock<Vec<Fr>> = LazyLock::new(|| {
        let mut ladder = vec![Fr::from(0u64)];
        for height in 1..=CIRCUIT_DEPTH {
            let below = ladder[height - 1];
            ladder.push(Hasher::<PoseidonHash>::hash_pair(below, below));
        }
        ladder
    });
    &LADDER
}

/// The stateless engine over the vendored depth-10 circuit, built once — the
/// zkey and graph are several MB and too expensive to clone per call.
///
/// `graph_from_raw` is told the depth it should find, so a mismatched artifact
/// fails here at first use rather than quietly proving against a tree shape
/// nobody expects.
pub fn engine() -> &'static RLN<Stateless, ArkGroth16Backend<PoseidonHash>> {
    static ENGINE: LazyLock<RLN<Stateless, ArkGroth16Backend<PoseidonHash>>> =
        LazyLock::new(|| {
            RLNBuilder::stateless()
                .graph(
                    graph_from_raw(DEPTH_10_GRAPH, Some(CIRCUIT_DEPTH), None)
                        .expect("vendored depth-10 graph must load"),
                )
                .zkey(zkey_from_raw(DEPTH_10_ZKEY).expect("vendored depth-10 zkey must load"))
                .build()
        });
    &ENGINE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ladder_folds_empty_subtrees() {
        let ladder = zero_ladder();
        assert_eq!(ladder.len(), CIRCUIT_DEPTH + 1);
        assert_eq!(ladder[0], Fr::from(0u64));
        for height in 1..=CIRCUIT_DEPTH {
            assert_eq!(
                ladder[height],
                Hasher::<PoseidonHash>::hash_pair(ladder[height - 1], ladder[height - 1])
            );
        }
    }
}
