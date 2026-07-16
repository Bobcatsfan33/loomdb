//! **The branch-resident ANN index — the HNSW graph, in the branch's own tree.**
//!
//! Slice 2a proved the store-backed graph (in `loom-core`) against the recall oracle through bincode.
//! This wires it to the *branch tree*: [`TreeNodeStore`] reads and writes graph nodes at reserved keys
//! inside the branch, so the graph is exactly as isolated as everything else on the branch — a sibling
//! has a different head manifest and a different tree, and cannot address this graph (invariant I-11,
//! the reason it is never a shared index).
//!
//! Exposed as an **explicit build** (`Loom::build_ann_index`) rather than auto-run on every write, and
//! **slice 2c measured why it stays that way** (`benches/ann_amplification.rs`): building the graph is
//! *super-linear* in the number of records — ~1.7 s / 15.5 s / 145 s to index 500 / 2 000 / 8 000
//! vectors, i.e. 4× the records for ~9× the time. The graph's storage is cheap (≈675 bytes/record,
//! graph/data ≈ 0.01), so the cost is time, not space, and it comes from the `M` scattered neighbour
//! updates per insert — the same random-leaf write amplification the append-ordered-provenance fix
//! removed elsewhere.
//!
//! **The decision that follows from the number:** ANN-on-write does **not** go inline. An inline insert
//! whose cost climbs with the graph would reintroduce exactly that amplification on the AT-045-certified
//! write path; and since the *explicit* build is already super-linear, inline would be strictly worse.
//! So for v0.2 the graph is an **explicit build**, the **brute-force scan stays the correct default**
//! retrieval path, and ANN is an opt-in accelerator. The production answer — incremental maintenance /
//! background compaction, plus fixing the build to be genuinely O(N·log N) — is its own project
//! (v0.3), not a fold-in. Written down here rather than discovered under load.

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
