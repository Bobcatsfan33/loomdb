//! **The branch-resident ANN index — the HNSW graph, in the branch's own tree.**
//!
//! Slice 2a proved the store-backed graph (in `loom-core`) against the recall oracle through bincode.
//! This wires it to the *branch tree*: [`TreeNodeStore`] reads and writes graph nodes at reserved keys
//! inside the branch, so the graph is exactly as isolated as everything else on the branch — a sibling
//! has a different head manifest and a different tree, and cannot address this graph (invariant I-11,
//! the reason it is never a shared index).
//!
//! Exposed as an **explicit build** (`Loom::build_ann_index`) rather than auto-run on every write.
//!
//! **v0.3 made the build O(N·log N)** (`crates/loom-core/tests/hnsw_build_scaling.rs`). The old cost —
//! measured at ~1.7 s / 15.5 s / 145 s for 500 / 2 000 / 8 000 vectors — was *never* quadratic and never
//! a brute-force scan (the insert has always navigated the graph); it was a large per-insert **constant**
//! paid through the per-operation tree/bincode path, plus the `M` scattered write-amplifying leaf writes
//! per insert. `build_ann_index` now builds the graph **in RAM** and persists it in **one sorted pass**,
//! which cuts the constant and removes the scatter — the build tracks N·log N to 1M with recall@10 held
//! (see the at-map's *HNSW index build* section for the curve and numbers).
//!
//! **v0.4 made the index LIVE (slice 2c, resolved on the number).** The placement question — inline on
//! every write vs. background compaction — was decided by measurement (`benches/ann_amplification.rs`):
//! an inline insert added growing amplification (~1.7–2.2× and climbing) and, disqualifyingly, ~220 ms of
//! per-write latency that grows with the graph, on the AT-045-certified write path. So the answer is
//! **compaction**: an indexed write appends its vector to an in-branch **buffer** (reserved
//! `\x00loom/annbuf/`, ≈1× baseline, in the same commit); `search_ann` **unions** the graph with a
//! bounded buffer brute-scan, so a freshly-written vector is searchable *immediately* — **0 staleness**;
//! and `Loom::ann_fold` folds the buffer into the graph off the write path, publishing with a
//! compare-and-set on the head so it never stalls or clobbers a live write. The buffer→graph handoff is
//! one atomic commit — a crash leaves every vector in the buffer or the graph, never neither (AT-045 over
//! the fold), and the fold racing appends and searches loses nothing and double-indexes nothing (the
//! `compaction.rs` concurrency gate). The full scan ([`Loom::search_scan`](crate::Loom::search_scan))
//! remains available as an exact fallback; ANN ([`Loom::search_ann`](crate::Loom::search_ann)) is the
//! accelerator, now live rather than an explicit-build snapshot.
//!
//! # Which is the default retrieval path — measured, not asserted (`benches/ann_vs_scan.rs`)
//!
//! The exact scan is O(indexed) per query; the ANN is sub-linear but pays a fixed graph-traversal cost
//! (each hop is a node read + decode, `efSearch` wide). So one is not universally faster — there is a
//! crossover, and it was measured rather than guessed (in-memory, DIM=64, k=10, clustered):
//!
//! ```text
//!        N    scan med (ms)    ann med (ms)    faster
//!     1 000        2.6            15.5         scan  (6×)
//!    10 000       29.3            53.3         scan  (2×)
//!    50 000      161.4            63.0         ann   (2.6×)
//! ```
//!
//! **The decision (guardrail 5), and it refines rather than flips the earlier one:** for a **small/medium
//! branch (≲ ~20 k indexed vectors) the exact scan is the better default** — it is faster *and* exact, so
//! there is nothing to trade; **past the ~20 k crossover the ANN accelerator wins** and the gap widens as
//! the scan grows linearly. "ANN whenever an index exists" would be the *wrong* default: at 1 k it is 6×
//! slower than just scanning. Two honest caveats: (1) this is **in-memory**, the conservative case for the
//! ANN — on object/disk storage the scan's O(N) page reads are far more punishing than the ANN's ~`ef`
//! node reads, so the crossover moves **left** (ANN earns its place sooner); that direction is structural
//! reasoning, not a number measured here. (2) The engine does **not** auto-route between the two — it
//! exposes both and the crossover, leaving the choice to the caller; an automatic size-based router is
//! new retrieval behavior and would land with its own oracle, not slipped in here.

use std::cell::RefCell;

use loom_core::{
    hnsw_meta_key, hnsw_node_key, HnswMeta, NodeStore, PersistedNode, Record, StoreError, Value,
};

use crate::tree::Tree;

/// A [`NodeStore`] over a branch's B-tree. Owns the tree behind a `RefCell` so the trait's `&self`
/// reads can reach `Tree::get` (which needs `&mut self` for its dirty-page cache) without `unsafe`.
pub(crate) struct TreeNodeStore<'a> {
    tree: RefCell<Tree<'a>>,
}

impl<'a> TreeNodeStore<'a> {
    pub(crate) fn new(tree: Tree<'a>) -> Self {
        TreeNodeStore {
            tree: RefCell::new(tree),
        }
    }

    /// Recover the tree, to flush it into the transaction after the graph is built.
    pub(crate) fn into_tree(self) -> Tree<'a> {
        self.tree.into_inner()
    }

    fn read_raw(&self, key: &[u8]) -> std::result::Result<Option<Vec<u8>>, StoreError> {
        match self.tree.borrow_mut().get(key).map_err(box_err)? {
            Some(Record::Value(Value::Blob(bytes))) => Ok(Some(bytes)),
            _ => Ok(None),
        }
    }
}

impl NodeStore for TreeNodeStore<'_> {
    fn get_node(&self, id: &[u8]) -> std::result::Result<Option<PersistedNode>, StoreError> {
        match self.read_raw(&hnsw_node_key(id))? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes).map_err(box_err)?)),
            None => Ok(None),
        }
    }

    fn put_node(&mut self, id: &[u8], node: &PersistedNode) -> std::result::Result<(), StoreError> {
        let bytes = bincode::serialize(node).map_err(box_err)?;
        self.tree
            .borrow_mut()
            .insert(hnsw_node_key(id), Record::Value(Value::Blob(bytes)))
            .map_err(box_err)
    }

    fn get_meta(&self) -> std::result::Result<HnswMeta, StoreError> {
        match self.read_raw(&hnsw_meta_key())? {
            Some(bytes) => bincode::deserialize(&bytes).map_err(box_err),
            None => Ok(HnswMeta::default()),
        }
    }

    fn put_meta(&mut self, meta: &HnswMeta) -> std::result::Result<(), StoreError> {
        let bytes = bincode::serialize(meta).map_err(box_err)?;
        self.tree
            .borrow_mut()
            .insert(hnsw_meta_key(), Record::Value(Value::Blob(bytes)))
            .map_err(box_err)
    }
}

fn box_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> StoreError {
    Box::new(e)
}
