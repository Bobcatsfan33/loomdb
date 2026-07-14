//! The record store: a B+tree whose nodes are substrate pages.
//!
//! # Why there is no copy-on-write code in this file
//!
//! A copy-on-write B-tree is a famously fiddly thing to write: every update has to clone the leaf,
//! then the parent, then the grandparent, up to a new root, and get the reference counting right.
//!
//! We do not write any of that, because **substrate already is copy-on-write.** A node lives at a
//! *logical* page number, and substrate maps logical pages to immutable content. Writing a node
//! overwrites the logical page, and every manifest that existed before that write still points at the
//! old content — so an old snapshot reads the old tree, and nobody had to copy anything.
//!
//! ```text
//!   manifest v1 ──► page 3 ──► content Ab12…   (old leaf, still perfectly readable)
//!   manifest v2 ──► page 3 ──► content Cd34…   (new leaf)
//! ```
//!
//! Node identity is a *stable logical page number*. Snapshot isolation is the manifest's problem, and
//! it has already solved it. This is what it means for a data structure to be built on the right
//! foundation: the hard part is missing.
//!
//! # Layout
//!
//! Logical page **0** is the metadata page. Everything else is a node. See `docs/loom-format.md`.
//!
//! # What is deliberately missing
//!
//! **Deletes do not free logical pages.** A removed key is removed from its leaf; if the leaf empties,
//! the page is simply left empty rather than merged into a sibling and returned to a free list. That
//! is a real limitation, it wastes logical page numbers in a delete-heavy workload, and it is written
//! down here rather than discovered later. Rebalancing on delete is where B-trees get most of their
//! bugs, and LoomDB's workload is overwhelmingly append-and-supersede — a semantic store *never*
//! deletes a fact, it closes its validity interval (docs/03 §3.2). We will do it when a workload
//! needs it, not before.

use loom_core::{Key, LoomError, Record, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use substrate_pager::{LogicalPageNo, PageStore, Txn};

/// The logical page the metadata lives at. Always page 0.
pub const META_PAGE: LogicalPageNo = 0;

/// The on-disk format version. A change here is a format change.
pub const FORMAT_VERSION: u32 = 1;

/// How full a node may get before it splits, as a fraction of the page size.
///
/// Not 100%: a node that fills its page exactly leaves no room for the *next* insert to be encoded
/// before the split is detected, and a split that cannot be encoded is a wedged database.
const FILL_FACTOR: f64 = 0.7;

/// The metadata page.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Meta {
    /// Format version.
    pub format_version: u32,
    /// The logical page the root node lives at.
    pub root: LogicalPageNo,
    /// The next logical page number to hand out.
    pub next_free: LogicalPageNo,
    /// How many records the tree holds.
    pub count: u64,
}

impl Meta {
    /// A brand-new, empty tree: a metadata page and one empty leaf.
    pub fn empty() -> Self {
        Meta {
            format_version: FORMAT_VERSION,
            root: 1,
            next_free: 2,
            count: 0,
        }
    }
}

/// A node of the tree.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Node {
    /// Holds the records.
    Leaf {
        /// Sorted by key.
        entries: Vec<(Key, Record)>,
    },
    /// Holds separators and children.
    ///
    /// `keys[i]` separates `children[i]` from `children[i + 1]`, so there is always exactly one more
    /// child than key.
    Internal {
        /// Separators, sorted.
        keys: Vec<Key>,
        /// Children. `keys.len() + 1` of them.
        children: Vec<LogicalPageNo>,
    },
}

impl Node {
    fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|source| LoomError::Codec {
            op: "encode",
            what: "tree node",
            source,
        })
    }

    fn decode(bytes: &[u8], page: LogicalPageNo) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| LoomError::CorruptNode {
            page,
            detail: e.to_string(),
        })
    }

    /// Whether this node has outgrown its page.
    fn is_full(&self, page_size: usize) -> Result<bool> {
        Ok(self.encode()?.len() as f64 > page_size as f64 * FILL_FACTOR)
    }
}

/// The working context for one transaction against the tree.
///
/// # Why a dirty-page cache is not an optimisation here — it is required
///
/// substrate's `Txn` **stages** writes: they are not visible to `read()` until the transaction
/// commits. So a tree operation that writes a node and then reads it back within the same
/// transaction would get the *old* version, and the tree would quietly corrupt itself — a split
/// would write a new leaf and then the parent update would read the pre-split leaf.
///
/// So every node read and write in a transaction goes through this cache, and the cache is flushed
/// into the transaction at the end. Nothing else is correct.
pub struct Tree<'a> {
    store: &'a dyn PageStore,
    dirty: BTreeMap<LogicalPageNo, Node>,
    meta: Meta,
    meta_dirty: bool,
    page_size: usize,
}

impl<'a> Tree<'a> {
    /// Open the tree in a store, reading its metadata page.
    pub fn open(store: &'a dyn PageStore) -> Result<Self> {
        let page_size = store.page_size();

        let meta = match store.read_head(META_PAGE) {
            Ok(page) => {
                bincode::deserialize(page.as_bytes()).map_err(|e| LoomError::CorruptNode {
                    page: META_PAGE,
                    detail: format!("metadata page will not decode: {e}"),
                })?
            }
            // No metadata page: this is a fresh store.
            Err(substrate_pager::PagerError::PageNotFound { .. }) => Meta::empty(),
            Err(e) => return Err(e.into()),
        };

        Ok(Tree {
            store,
            dirty: BTreeMap::new(),
            meta,
            meta_dirty: false,
            page_size,
        })
    }

    /// How many records the tree holds.
    pub fn len(&self) -> u64 {
        self.meta.count
    }

    /// True if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.meta.count == 0
    }

    /// Read a node — from this transaction's writes first, then from the store.
    fn node(&mut self, page: LogicalPageNo) -> Result<Node> {
        if let Some(node) = self.dirty.get(&page) {
            return Ok(node.clone());
        }
        match self.store.read_head(page) {
            Ok(bytes) => Node::decode(bytes.as_bytes(), page),
            // A page the tree references but that has never been written is an empty leaf. This is
            // the state of a brand-new tree's root, and it is not an error.
            Err(substrate_pager::PagerError::PageNotFound { .. }) => {
                Ok(Node::Leaf { entries: vec![] })
            }
            Err(e) => Err(e.into()),
        }
    }

    fn set(&mut self, page: LogicalPageNo, node: Node) {
        self.dirty.insert(page, node);
    }

    fn alloc(&mut self) -> LogicalPageNo {
        let page = self.meta.next_free;
        self.meta.next_free += 1;
        self.meta_dirty = true;
        page
    }

    /// Look a key up.
    pub fn get(&mut self, key: &[u8]) -> Result<Option<Record>> {
        let mut page = self.meta.root;

        loop {
            match self.node(page)? {
                Node::Leaf { entries } => {
                    return Ok(entries
                        .binary_search_by(|(k, _)| k.as_slice().cmp(key))
                        .ok()
                        .map(|i| entries[i].1.clone()));
                }
                Node::Internal { keys, children } => {
                    page = children[child_index(&keys, key)];
                }
            }
        }
    }

    /// Insert or replace.
    pub fn insert(&mut self, key: Key, record: Record) -> Result<()> {
        let root = self.meta.root;

        if let Some((separator, right)) = self.insert_into(root, key, record)? {
            // The root split. A new root, one level taller.
            let new_root = self.alloc();
            self.set(
                new_root,
                Node::Internal {
                    keys: vec![separator],
                    children: vec![root, right],
                },
            );
            self.meta.root = new_root;
            self.meta_dirty = true;
        }
        Ok(())
    }

    /// Returns `Some((separator, right_page))` if this node split.
    fn insert_into(
        &mut self,
        page: LogicalPageNo,
        key: Key,
        record: Record,
    ) -> Result<Option<(Key, LogicalPageNo)>> {
        match self.node(page)? {
            Node::Leaf { mut entries } => {
                match entries.binary_search_by(|(k, _)| k.cmp(&key)) {
                    Ok(i) => entries[i].1 = record, // replace; the count does not move
                    Err(i) => {
                        entries.insert(i, (key, record));
                        self.meta.count += 1;
                        self.meta_dirty = true;
                    }
                }

                let node = Node::Leaf { entries };
                if !node.is_full(self.page_size)? {
                    self.set(page, node);
                    return Ok(None);
                }

                // Split. The left half stays where it is — which matters, because the parent already
                // points here and we do not want to rewrite it.
                let Node::Leaf { mut entries } = node else {
                    return Ok(None);
                };
                let mid = entries.len() / 2;
                let right_entries = entries.split_off(mid);

                let Some((separator, _)) = right_entries.first().cloned() else {
                    // A single entry too large to fit in a page. Splitting cannot help.
                    return Err(LoomError::CorruptNode {
                        page,
                        detail: format!(
                            "a single record does not fit in a {}-byte page",
                            self.page_size
                        ),
                    });
                };

                let right_page = self.alloc();
                self.set(page, Node::Leaf { entries });
                self.set(
                    right_page,
                    Node::Leaf {
                        entries: right_entries,
                    },
                );
                Ok(Some((separator, right_page)))
            }

            Node::Internal {
                mut keys,
                mut children,
            } => {
                let idx = child_index(&keys, &key);
                let child = children[idx];

                let Some((separator, right)) = self.insert_into(child, key, record)? else {
                    return Ok(None);
                };

                keys.insert(idx, separator);
                children.insert(idx + 1, right);

                let node = Node::Internal { keys, children };
                if !node.is_full(self.page_size)? {
                    self.set(page, node);
                    return Ok(None);
                }

                let Node::Internal {
                    mut keys,
                    mut children,
                } = node
                else {
                    return Ok(None);
                };

                // An internal split pushes its middle key UP rather than copying it down — that is
                // what makes it a B+tree rather than an expensive B-tree.
                let mid = keys.len() / 2;
                let separator = keys[mid].clone();
                let right_keys = keys.split_off(mid + 1);
                keys.pop(); // the separator moves up; it does not stay in either half
                let right_children = children.split_off(mid + 1);

                let right_page = self.alloc();
                self.set(page, Node::Internal { keys, children });
                self.set(
                    right_page,
                    Node::Internal {
                        keys: right_keys,
                        children: right_children,
                    },
                );
                Ok(Some((separator, right_page)))
            }
        }
    }

    /// Remove a key. See the module docs on what this deliberately does not do.
    pub fn remove(&mut self, key: &[u8]) -> Result<bool> {
        let mut page = self.meta.root;

        loop {
            match self.node(page)? {
                Node::Leaf { mut entries } => {
                    let Ok(i) = entries.binary_search_by(|(k, _)| k.as_slice().cmp(key)) else {
                        return Ok(false);
                    };
                    entries.remove(i);
                    self.set(page, Node::Leaf { entries });
                    self.meta.count = self.meta.count.saturating_sub(1);
                    self.meta_dirty = true;
                    return Ok(true);
                }
                Node::Internal { keys, children } => {
                    page = children[child_index(&keys, key)];
                }
            }
        }
    }

    /// Every record, in key order.
    pub fn scan(&mut self) -> Result<Vec<(Key, Record)>> {
        let mut out = Vec::new();
        let root = self.meta.root;
        self.collect(root, &mut out)?;
        Ok(out)
    }

    fn collect(&mut self, page: LogicalPageNo, out: &mut Vec<(Key, Record)>) -> Result<()> {
        match self.node(page)? {
            Node::Leaf { entries } => out.extend(entries),
            Node::Internal { children, .. } => {
                for child in children {
                    self.collect(child, out)?;
                }
            }
        }
        Ok(())
    }

    /// Every key in the leaves stored at these logical pages.
    ///
    /// This is the **merge prefilter** (docs/03 §3.3). substrate's `diff3` tells us which *pages*
    /// changed; this turns that into which *keys* might have changed. Pages that are internal nodes
    /// contribute nothing, because a split moves keys between leaves without changing any record.
    ///
    /// The result is a **superset** of the keys whose values actually changed, and that is exactly
    /// what a prefilter has to be: if a record's value changed, its leaf page changed, so its key is
    /// here. Extra keys cost a comparison; a missing key would cost a silently dropped merge.
    pub fn keys_in_pages(&mut self, pages: &[LogicalPageNo]) -> Result<Vec<Key>> {
        let mut keys = Vec::new();
        for &page in pages {
            if page == META_PAGE {
                continue;
            }
            // A page that will not decode as a node is not a reason to fail a merge — it may simply
            // be a page from a different tree layout, or garbage from an abandoned branch.
            if let Ok(Node::Leaf { entries }) = self.node(page) {
                keys.extend(entries.into_iter().map(|(k, _)| k));
            }
        }
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    /// Write everything this transaction touched.
    ///
    /// Nothing has been staged until this is called.
    pub fn flush(mut self, txn: &mut Txn) -> Result<()> {
        let dirty = std::mem::take(&mut self.dirty);
        for (page, node) in dirty {
            self.store.write(txn, page, node.encode()?)?;
        }

        if self.meta_dirty {
            let bytes = bincode::serialize(&self.meta).map_err(|source| LoomError::Codec {
                op: "encode",
                what: "tree metadata",
                source,
            })?;
            self.store.write(txn, META_PAGE, bytes)?;
        }
        Ok(())
    }
}

/// Which child of an internal node a key belongs under.
fn child_index(keys: &[Key], key: &[u8]) -> usize {
    // `partition_point` is the first index where the separator is > key, which is exactly the child
    // that owns the key. Getting this off by one sends every lookup down the wrong subtree, which is
    // the kind of bug that produces a database that is *mostly* right.
    keys.partition_point(|k| k.as_slice() <= key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_core::Value;
    use substrate_pager::{Pager, StoreConfig, MIN_PAGE_SIZE};

    fn store() -> Pager {
        Pager::in_memory(StoreConfig {
            page_size: MIN_PAGE_SIZE,
            ..Default::default()
        })
        .expect("store")
    }

    fn rec(n: u64) -> Record {
        Record::Value(Value::Counter(n as i64))
    }

    fn key(n: u64) -> Key {
        format!("key-{n:08}").into_bytes()
    }

    /// Write records through a transaction, the way a real caller does.
    fn write_all(store: &Pager, pairs: &[(Key, Record)]) -> Result<()> {
        let mut txn = store.begin()?;
        let mut tree = Tree::open(store)?;
        for (k, r) in pairs {
            tree.insert(k.clone(), r.clone())?;
        }
        tree.flush(&mut txn)?;
        store.commit(txn)?;
        Ok(())
    }

    #[test]
    fn a_fresh_tree_is_empty() -> Result<()> {
        let store = store();
        let mut tree = Tree::open(&store)?;
        assert!(tree.is_empty());
        assert_eq!(tree.get(b"nothing")?, None);
        Ok(())
    }

    #[test]
    fn round_trips_a_record() -> Result<()> {
        let store = store();
        write_all(&store, &[(key(1), rec(42))])?;

        let mut tree = Tree::open(&store)?;
        assert_eq!(tree.get(&key(1))?, Some(rec(42)));
        assert_eq!(tree.len(), 1);
        Ok(())
    }

    #[test]
    fn survives_enough_records_to_split_many_times() -> Result<()> {
        // The real test of a B-tree: enough inserts to split leaves, split internal nodes, and grow
        // the root more than once.
        let store = store();
        let pairs: Vec<_> = (0..2_000u64).map(|n| (key(n), rec(n))).collect();
        write_all(&store, &pairs)?;

        let mut tree = Tree::open(&store)?;
        assert_eq!(tree.len(), 2_000);

        for n in 0..2_000u64 {
            assert_eq!(tree.get(&key(n))?, Some(rec(n)), "lost key {n}");
        }
        assert_eq!(tree.get(b"key-99999999")?, None);

        // And a full scan comes back in order, with everything in it.
        let all = tree.scan()?;
        assert_eq!(all.len(), 2_000);
        let keys: Vec<_> = all.iter().map(|(k, _)| k.clone()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "a scan must come back in key order");
        Ok(())
    }

    #[test]
    fn inserting_in_reverse_order_also_works() -> Result<()> {
        // Descending inserts are the classic way to produce a pathologically unbalanced tree, and a
        // classic way to expose an off-by-one in child selection.
        let store = store();
        let pairs: Vec<_> = (0..500u64).rev().map(|n| (key(n), rec(n))).collect();
        write_all(&store, &pairs)?;

        let mut tree = Tree::open(&store)?;
        for n in 0..500u64 {
            assert_eq!(tree.get(&key(n))?, Some(rec(n)));
        }
        Ok(())
    }

    #[test]
    fn replacing_a_key_does_not_grow_the_tree() -> Result<()> {
        let store = store();
        write_all(&store, &[(key(1), rec(1))])?;
        write_all(&store, &[(key(1), rec(2))])?;

        let mut tree = Tree::open(&store)?;
        assert_eq!(tree.get(&key(1))?, Some(rec(2)));
        assert_eq!(tree.len(), 1, "a replace is not an insert");
        Ok(())
    }

    #[test]
    fn removal_works_and_is_idempotent() -> Result<()> {
        let store = store();
        let pairs: Vec<_> = (0..100u64).map(|n| (key(n), rec(n))).collect();
        write_all(&store, &pairs)?;

        let mut txn = store.begin()?;
        let mut tree = Tree::open(&store)?;
        assert!(tree.remove(&key(50))?);
        assert!(!tree.remove(&key(50))?, "removing twice is not an error");
        tree.flush(&mut txn)?;
        store.commit(txn)?;

        let mut tree = Tree::open(&store)?;
        assert_eq!(tree.get(&key(50))?, None);
        assert_eq!(tree.get(&key(49))?, Some(rec(49)));
        assert_eq!(tree.len(), 99);
        Ok(())
    }

    #[test]
    fn writes_within_one_transaction_see_each_other() -> Result<()> {
        // This is the bug the dirty-page cache exists to prevent. substrate STAGES writes: they are
        // invisible to read() until commit. Without the cache, a split would write a new leaf and the
        // parent update would then read the PRE-SPLIT leaf, and the tree would corrupt itself
        // silently. Enough inserts here to force splits inside a single transaction.
        let store = store();
        let mut txn = store.begin()?;
        let mut tree = Tree::open(&store)?;

        for n in 0..1_000u64 {
            tree.insert(key(n), rec(n))?;
            // Read back what we just wrote, mid-transaction.
            assert_eq!(
                tree.get(&key(n))?,
                Some(rec(n)),
                "lost key {n} mid-transaction"
            );
        }
        tree.flush(&mut txn)?;
        store.commit(txn)?;

        let mut tree = Tree::open(&store)?;
        assert_eq!(tree.len(), 1_000);
        for n in 0..1_000u64 {
            assert_eq!(tree.get(&key(n))?, Some(rec(n)));
        }
        Ok(())
    }

    #[test]
    fn the_tree_is_snapshot_isolated_for_free() -> Result<()> {
        // No copy-on-write code exists in this file. substrate's immutable manifests give it to us.
        let store = store();
        write_all(&store, &[(key(1), rec(1))])?;
        let v1 = store.head();

        write_all(&store, &[(key(1), rec(999))])?;

        // The old snapshot still reads the old tree.
        let old = store.fork(&v1)?;
        let mut old_tree = Tree::open(&*old)?;
        assert_eq!(old_tree.get(&key(1))?, Some(rec(1)));

        let mut new_tree = Tree::open(&store)?;
        assert_eq!(new_tree.get(&key(1))?, Some(rec(999)));
        Ok(())
    }

    #[test]
    fn child_index_picks_the_right_subtree() {
        let keys = vec![b"c".to_vec(), b"f".to_vec()];
        // < "c" goes left; "c" itself goes to the middle (separators are inclusive-left).
        assert_eq!(child_index(&keys, b"a"), 0);
        assert_eq!(child_index(&keys, b"c"), 1);
        assert_eq!(child_index(&keys, b"e"), 1);
        assert_eq!(child_index(&keys, b"f"), 2);
        assert_eq!(child_index(&keys, b"z"), 2);
    }
}
