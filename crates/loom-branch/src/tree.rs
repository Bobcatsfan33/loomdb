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
    /// Roughly how many bytes each node encodes to.
    ///
    /// # Why this exists
    ///
    /// `is_full` used to answer "does this node still fit in a page?" by bincode-serialising the
    /// **entire node**, on **every insert**. That is O(node) work per record, which makes filling a
    /// leaf O(leaf²) — and the AT-011 benchmark found it immediately: seeding 10,000 records took
    /// 3.8 seconds, and the 1M and 10M baselines were simply unreachable. The numbers we could not
    /// produce were the ones that mattered.
    ///
    /// So the size is tracked **incrementally**: an insert adds its own cost, a replace adds the
    /// difference. The estimate deliberately **over-counts**, so it can only ever trigger the
    /// fullness check *early*, never late — and when it does trigger, we pay for one real encode to
    /// get the truth, and resync. A cheap estimate that could under-count would let a node quietly
    /// grow past the page size, and the pager would reject the write at commit.
    sizes: BTreeMap<LogicalPageNo, usize>,
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
            sizes: BTreeMap::new(),
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
            Ok(bytes) => {
                // The encoded length, for free. This is the only place a node's true size is known
                // without paying to serialise it.
                self.sizes.insert(page, bytes.as_bytes().len());
                Node::decode(bytes.as_bytes(), page)
            }
            // A page the tree references but that has never been written is an empty leaf. This is
            // the state of a brand-new tree's root, and it is not an error.
            Err(substrate_pager::PagerError::PageNotFound { .. }) => {
                Ok(Node::Leaf { entries: vec![] })
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Take a node **by value**, without cloning it.
    ///
    /// `node()` clones, and a clone of a leaf is a fresh heap allocation for *every key in it* — a
    /// thousand allocations to insert one record. The insert path does not need a copy; it needs the
    /// node itself, and it always puts one back.
    ///
    /// The contract: **every path that takes a node must set one back**, including early returns.
    /// Forgetting to would silently drop a whole page of records from the transaction.
    fn take_node(&mut self, page: LogicalPageNo) -> Result<Node> {
        if let Some(node) = self.dirty.remove(&page) {
            return Ok(node);
        }
        self.node(page)
    }

    fn set(&mut self, page: LogicalPageNo, node: Node) {
        self.sizes.remove(&page);
        self.dirty.insert(page, node);
    }

    /// Set a node whose encoded size we already know.
    fn set_sized(&mut self, page: LogicalPageNo, node: Node, size: usize) {
        self.sizes.insert(page, size);
        self.dirty.insert(page, node);
    }

    /// The known-or-computed encoded size of a node.
    fn size_of(&mut self, page: LogicalPageNo, node: &Node) -> Result<usize> {
        match self.sizes.get(&page) {
            Some(size) => Ok(*size),
            None => {
                let size = node.encode()?.len();
                self.sizes.insert(page, size);
                Ok(size)
            }
        }
    }

    /// Has this node outgrown its page?
    ///
    /// Consults the running estimate first. Only when the estimate says "possibly" do we pay for a
    /// real encode — and then we resync the estimate to the truth. Because the estimate over-counts,
    /// this can fire early and be told no; it cannot fire late.
    fn overflowed(&self, node: &Node, est: &mut usize) -> Result<bool> {
        let limit = (self.page_size as f64 * FILL_FACTOR) as usize;
        if *est <= limit {
            return Ok(false);
        }
        let real = node.encode()?.len();
        *est = real;
        Ok(real > limit)
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
        match self.take_node(page)? {
            Node::Leaf { mut entries } => {
                let mut est = {
                    let node = Node::Leaf { entries };
                    let size = self.size_of(page, &node)?;
                    let Node::Leaf { entries: e } = node else {
                        unreachable!("just constructed a leaf")
                    };
                    entries = e;
                    size
                };

                match entries.binary_search_by(|(k, _)| k.cmp(&key)) {
                    Ok(i) => {
                        // A replace: the node grows by the difference, which may be negative.
                        est = est.saturating_sub(entry_cost(&entries[i].0, &entries[i].1)?);
                        est += entry_cost(&key, &record)?;
                        entries[i].1 = record; // replace; the count does not move
                    }
                    Err(i) => {
                        est += entry_cost(&key, &record)?;
                        entries.insert(i, (key, record));
                        self.meta.count += 1;
                        self.meta_dirty = true;
                    }
                }

                let node = Node::Leaf { entries };
                if !self.overflowed(&node, &mut est)? {
                    self.set_sized(page, node, est);
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
                let left = Node::Leaf { entries };
                let right = Node::Leaf {
                    entries: right_entries,
                };
                // One real encode per half, once per split — not once per insert. This is the whole
                // point of the exercise.
                let left_size = left.encode()?.len();
                let right_size = right.encode()?.len();
                self.set_sized(page, left, left_size);
                self.set_sized(right_page, right, right_size);
                Ok(Some((separator, right_page)))
            }

            Node::Internal {
                mut keys,
                mut children,
            } => {
                let idx = child_index(&keys, &key);
                let child = children[idx];

                let split = self.insert_into(child, key, record)?;

                let Some((separator, right)) = split else {
                    // The child absorbed it. **Put the node back** — `take_node` removed it from the
                    // dirty map, and an early return that does not restore it drops a whole page of
                    // records from the transaction.
                    self.dirty.insert(page, Node::Internal { keys, children });
                    return Ok(None);
                };

                keys.insert(idx, separator);
                children.insert(idx + 1, right);

                let node = Node::Internal { keys, children };
                let mut est = node.encode()?.len();
                if !self.overflowed(&node, &mut est)? {
                    self.set_sized(page, node, est);
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

    /// Every `(key, record)` whose key starts with `prefix`, in key order — **without reading the rest
    /// of the tree**. It descends only into subtrees whose key range overlaps `[prefix, prefix⁺)`, so it
    /// is O(log N + matches), not O(N). This is what keeps the ANN buffer scan (a reserved-prefix range)
    /// bounded by the buffer size rather than the whole branch.
    pub fn scan_prefix(&mut self, prefix: &[u8]) -> Result<Vec<(Key, Record)>> {
        let mut out = Vec::new();
        let root = self.meta.root;
        let hi = prefix_upper(prefix);
        self.collect_range(root, prefix, hi.as_deref(), &mut out)?;
        Ok(out)
    }

    fn collect_range(
        &mut self,
        page: LogicalPageNo,
        lo: &[u8],
        hi: Option<&[u8]>,
        out: &mut Vec<(Key, Record)>,
    ) -> Result<()> {
        match self.node(page)? {
            Node::Leaf { entries } => {
                for (k, r) in entries {
                    let ks = k.as_slice();
                    if ks >= lo && hi.is_none_or(|h| ks < h) {
                        out.push((k, r));
                    }
                }
            }
            Node::Internal { keys, children } => {
                // child[i] owns keys in [keys[i-1], keys[i]); descend only where that overlaps [lo, hi).
                for (i, &child) in children.iter().enumerate() {
                    let lower = if i == 0 { None } else { keys.get(i - 1) };
                    let upper = keys.get(i);
                    let below_hi = match (lower, hi) {
                        (Some(l), Some(h)) => l.as_slice() < h,
                        _ => true,
                    };
                    let above_lo = upper.is_none_or(|u| u.as_slice() > lo);
                    if below_hi && above_lo {
                        self.collect_range(child, lo, hi, out)?;
                    }
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

/// What one leaf entry costs, in encoded bytes — **over-counted on purpose**.
///
/// The estimate that drives the fullness check may fire early and be corrected by a real encode. It
/// must never fire *late*, because a node that grows past the page size is rejected by the pager at
/// commit, and the caller sees a `PageTooLarge` for a write that looked fine. So this rounds up: the
/// bincode length prefixes are 8 bytes each, and `SLACK` covers the enum tags and any discrepancy
/// between `serialized_size` and the real thing.
///
/// **This is a claim about the serializer, so it is tested rather than asserted in prose.** The
/// 8-byte prefix, the 4-byte enum tag, and the requirement that `SLACK` cover the per-entry framing
/// the estimate does not count are all pinned by `tests::page_fitting` below — as is the fanout they
/// produce, so a serializer whose framing differs fails loudly instead of silently repacking every
/// page. See `docs/design/serialization-format.md` (issue #50).
const SLACK: usize = 24;

fn entry_cost(key: &[u8], record: &Record) -> Result<usize> {
    let record_bytes = bincode::serialized_size(record).map_err(|source| LoomError::Codec {
        op: "size",
        what: "record",
        source,
    })? as usize;
    Ok(key.len() + record_bytes + SLACK)
}

/// Which child of an internal node a key belongs under.
/// The smallest key that does **not** begin with `prefix` — the exclusive upper bound of the prefix
/// range. Increment the last byte, carrying over trailing `0xFF`s; `None` means "no upper bound" (the
/// prefix was all `0xFF`, so everything `>= prefix` matches).
fn prefix_upper(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut hi = prefix.to_vec();
    while let Some(last) = hi.last_mut() {
        if *last < 0xFF {
            *last += 1;
            return Some(hi);
        }
        hi.pop();
    }
    None
}

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

    /// **The page-fitting invariant, pinned against the serializer.**
    ///
    /// # Why this module exists
    ///
    /// `is_full`/`overflowed` decides B-tree shape by *measuring the encoding*: `entry_cost` adds
    /// `bincode::serialized_size(record)` to the key length and a fixed `SLACK`, and the surrounding
    /// comment reasons explicitly about bincode's 8-byte length prefixes. So the serializer does not
    /// merely decide what a node *looks like* on disk — it decides **how many records fit in a
    /// page**, and therefore the tree's fanout, its depth, and its write amplification.
    ///
    /// A successor with different framing (a varint length prefix, say) would keep every existing
    /// test green while quietly repacking every page. That is not a correctness bug the suite can
    /// see; it is a performance and layout change that arrives unannounced.
    ///
    /// These tests fix the current relationship between a node's *logical contents* and its
    /// *serialized size*, so such a change fails loudly and names itself. They are companions to the
    /// golden byte fixtures in `tests/golden_format.rs`: the fixtures pin the bytes, this pins what
    /// the bytes *cost*.
    ///
    /// Issue #50; design note: `docs/design/serialization-format.md`.
    mod page_fitting {
        use super::*;

        /// The record shape the numbers below are measured against. Deliberately the simplest one:
        /// a fixed-size scalar, so a change in the measurement is a change in the *framing* and not
        /// in some incidental payload.
        fn counter(n: i64) -> Record {
            Record::Value(Value::Counter(n))
        }

        /// **`serialized_size` must agree with `serialize`.**
        ///
        /// `entry_cost` trusts `serialized_size` as a cheap stand-in for the real encode. If a
        /// successor's size oracle over- or under-reports relative to its own encoder, the whole
        /// over-count discipline in `Tree::overflowed` collapses — an under-report lets a node grow
        /// past the page and the pager rejects the write at commit, which surfaces as a
        /// `PageTooLarge` for an insert that looked fine.
        #[test]
        fn the_size_oracle_agrees_with_the_encoder() {
            for record in [
                counter(0),
                counter(-9_007_199_254_740_993),
                Record::Value(Value::Text("café ☕".to_string())),
                Record::Value(Value::Blob(vec![0xAB; 300])),
                Record::Value(Value::Bool(true)),
            ] {
                let claimed = bincode::serialized_size(&record).expect("size") as usize;
                let actual = bincode::serialize(&record).expect("encode").len();
                assert_eq!(
                    claimed, actual,
                    "serialized_size disagreed with serialize for {record:?}"
                );
            }
        }

        /// The pinned cost of one record, in encoded bytes.
        ///
        /// 16 = a 4-byte `Record` discriminant + a 4-byte `Value` discriminant + an 8-byte `i64`.
        /// Every one of those three widths is a bincode 1.x format property (see
        /// `tests/golden_format.rs::format_contract`), and a successor that changes any of them
        /// changes page packing.
        #[test]
        fn a_counter_record_encodes_to_sixteen_bytes() {
            assert_eq!(bincode::serialized_size(&counter(42)).expect("size"), 16);
        }

        /// `entry_cost` is `key.len() + serialized_size(record) + SLACK`, with nothing else in it.
        #[test]
        fn entry_cost_is_key_plus_record_plus_slack() -> Result<()> {
            let k = key(42);
            assert_eq!(k.len(), 12);
            assert_eq!(entry_cost(&k, &counter(42))?, 12 + 16 + SLACK);
            assert_eq!(entry_cost(&k, &counter(42))?, 52);
            assert_eq!(SLACK, 24);
            Ok(())
        }

        /// **What a leaf entry really costs, and the margin `SLACK` is buying.**
        ///
        /// A `(Key, Record)` pair in a leaf costs the key's 8-byte length prefix plus its bytes plus
        /// the record — 36 bytes for a 12-byte key and a counter. `entry_cost` charges 52. The
        /// 16-byte gap is the over-count, and it exists so the fullness check can only ever fire
        /// *early*.
        ///
        /// **The invariant that must hold, not merely the number:** `SLACK` must cover at least the
        /// per-entry framing that `entry_cost` does not otherwise count — which under bincode 1.x is
        /// the key's 8-byte length prefix. A successor with a *larger* per-entry framing than
        /// `SLACK` would make the estimate under-count, and `Tree::overflowed` would start firing
        /// late. That is the failure mode this assertion exists to prevent.
        #[test]
        fn slack_covers_the_per_entry_framing_the_estimate_does_not_count() -> Result<()> {
            let k = key(1);
            let record = counter(1);

            let one = bincode::serialize(&Node::Leaf {
                entries: vec![(k.clone(), record.clone())],
            })
            .expect("encode")
            .len();
            let two = bincode::serialize(&Node::Leaf {
                entries: vec![(k.clone(), record.clone()), (key(2), counter(2))],
            })
            .expect("encode")
            .len();

            let marginal = two - one;
            assert_eq!(marginal, 36, "the true marginal cost of one leaf entry");

            let uncounted =
                marginal - k.len() - bincode::serialized_size(&record).expect("size") as usize;
            assert_eq!(
                uncounted, 8,
                "the key's length prefix, which entry_cost omits"
            );
            assert!(
                SLACK >= uncounted,
                "SLACK ({SLACK}) must cover the per-entry framing ({uncounted}) or the fullness \
                 estimate under-counts and a node can grow past its page"
            );
            assert_eq!(entry_cost(&k, &record)?, marginal + 16);
            Ok(())
        }

        /// **The estimate over-counts for real leaves, at every size.** A property, not a constant:
        /// it must survive a serializer change even if the numbers above move.
        #[test]
        fn the_running_estimate_never_under_counts_a_real_leaf() -> Result<()> {
            for count in [1usize, 2, 7, 40, 79, 80, 500] {
                let entries: Vec<(Key, Record)> = (0..count as u64)
                    .map(|n| (key(n), counter(n as i64)))
                    .collect();
                let estimate: usize = entries
                    .iter()
                    .map(|(k, r)| entry_cost(k, r))
                    .sum::<Result<usize>>()?;
                let real = bincode::serialize(&Node::Leaf {
                    entries: entries.clone(),
                })
                .expect("encode")
                .len();
                assert!(
                    estimate >= real,
                    "the fullness estimate UNDER-counted a {count}-entry leaf ({estimate} < \
                     {real}). `Tree::overflowed` would fire late and the pager would reject the \
                     write at commit."
                );
            }
            Ok(())
        }

        /// **The split point.** With 4096-byte pages, a leaf of this record shape holds 79 entries
        /// and splits on the 80th.
        ///
        /// 79 entries encode to 2856 bytes, one under the 2867-byte limit (`4096 × 0.7`); 80 encode
        /// to 2892, one over. A serializer that framed entries differently would move this number,
        /// which is precisely the silent fanout change worth failing on.
        #[test]
        fn a_leaf_splits_on_the_eightieth_record() {
            let limit = (MIN_PAGE_SIZE as f64 * FILL_FACTOR) as usize;
            assert_eq!(limit, 2867);

            let leaf = |n: u64| {
                bincode::serialize(&Node::Leaf {
                    entries: (0..n).map(|i| (key(i), counter(i as i64))).collect(),
                })
                .expect("encode")
                .len()
            };
            assert_eq!(leaf(79), 2856);
            assert_eq!(leaf(80), 2892);
            assert!(leaf(79) <= limit, "79 entries must still fit");
            assert!(leaf(80) > limit, "80 entries must not");
        }

        /// **The tree's shape, end to end.** Ascending inserts of 2000 records into 4096-byte pages
        /// produce exactly 50 leaves of 40 entries under a root at page 3.
        ///
        /// This is the assertion that catches a repacking serializer even if every byte-level test
        /// above were somehow satisfied: it measures the thing the format actually decides.
        #[test]
        fn the_shape_of_a_two_thousand_record_tree_is_pinned() -> Result<()> {
            let st = store();
            let pairs: Vec<_> = (0..2_000u64).map(|n| (key(n), counter(n as i64))).collect();
            write_all(&st, &pairs)?;

            let mut tree = Tree::open(&st)?;
            assert_eq!(tree.meta.count, 2_000);
            assert_eq!(tree.meta.root, 3, "root page");
            assert_eq!(tree.meta.next_free, 52, "logical pages allocated");

            let mut leaves = Vec::new();
            for page in 1..tree.meta.next_free {
                if let Ok(Node::Leaf { entries }) = tree.node(page) {
                    leaves.push(entries.len());
                }
            }
            assert_eq!(leaves.len(), 50, "leaf count — this IS the fanout");
            assert!(
                leaves.iter().all(|n| *n == 40),
                "every leaf should hold 40 entries, got {leaves:?}"
            );

            // And the data survived the shape, which is the only reason any of it matters.
            for n in 0..2_000u64 {
                assert_eq!(tree.get(&key(n))?, Some(counter(n as i64)), "lost key {n}");
            }
            Ok(())
        }
    }
}
