//! **The branch-resident ANN index — the HNSW graph, in the branch's own tree.**
//!
//! Slice 2a proved the store-backed graph (in `loom-core`) against the recall oracle through bincode.
//! This wires it to the *branch tree*: [`TreeNodeStore`] reads and writes graph nodes at reserved keys
//! inside the branch, so the graph is exactly as isolated as everything else on the branch — a sibling
//! has a different head manifest and a different tree, and cannot address this graph (invariant I-11,
//! the reason it is never a shared index).
//!
//! Exposed as an **explicit build** (`Loom::build_ann_index`) rather than auto-run on every write.
//! Auto-inserting into HNSW on the hot write path adds real write amplification — `M` scattered
//! neighbour updates per record — to a path with its own crash-safety (AT-045) and amplification
//! budget, and that belongs behind its own measurement. So this slice proves the graph works *in the
//! branch* and accelerates retrieval; folding the insert into the write path is the next step.

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
