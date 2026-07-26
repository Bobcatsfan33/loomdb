//! **A store-backed HNSW — the graph, persisted per node, keyed by record id.**
//!
//! Slice 1 (`hnsw.rs`) proved the algorithm in memory. This is the persistence-ready form: nodes are
//! addressed by their **record id** (not a `Vec` position), and adjacency stores ids too, so the graph
//! can live in a key-value store — the branch's own B-tree — and a search reads only the O(log N) nodes
//! it actually traverses, never the whole index. That is the sub-linear win, and keeping it in the
//! branch's tree is what preserves the AT-040 isolation (invariant I-11): a sibling branch has a
//! different tree and a different graph it cannot address.
//!
//! The algorithm is identical to slice 1; only the addressing changed (indices → ids, in-RAM `Vec` →
//! a [`NodeStore`] trait). It is tested by the **same recall oracle** over an in-memory store, so the
//! persisted form is held to the same bar as the in-memory one before it ever touches the tree.

use std::collections::{BinaryHeap, HashSet};

use crate::Embedding;
use serde::{Deserialize, Serialize};

use crate::hnsw::{ItemId, EF_DEFAULT, M};

/// A persisted graph node: its vector, and its neighbour **ids** per layer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PersistedNode {
    /// The vector.
    pub vector: Embedding,
    /// `neighbours[l]` = the ids adjacent at layer `l`. Layer 0 is densest.
    pub neighbours: Vec<Vec<ItemId>>,
}

/// The graph's global bookkeeping.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct HnswMeta {
    /// The entry-point id, or `None` for an empty graph.
    pub entry: Option<ItemId>,
    /// The highest layer any node occupies.
    pub max_level: usize,
    /// The dimensionality every vector must share, once the first is inserted.
    pub dim: Option<usize>,
}

/// An error from the backing store — boxed so this crate stays decoupled from any one storage layer's
/// error type (the tree's `LoomError`, a test map's infallibility).
pub type StoreError = Box<dyn std::error::Error + Send + Sync>;

/// Where the graph's nodes and meta live. The branch tree implements this; tests use an in-memory map.
///
/// **Fallible on purpose.** A tree-backed store can fail to read (I/O) or to decode (a torn node), and
/// a graph algorithm that treats a *failed* read as "the node is missing" would silently corrupt the
/// graph — the exact class of quiet-wrong bug the recall oracle exists to catch. So every access
/// returns `Result`, and `insert`/`search` propagate it.
pub trait NodeStore {
    /// Read a node by id. `Ok(None)` means "not present"; `Err` means "could not tell".
    fn get_node(&self, id: &[u8]) -> Result<Option<PersistedNode>, StoreError>;
    /// Write a node.
    fn put_node(&mut self, id: &[u8], node: &PersistedNode) -> Result<(), StoreError>;
    /// Read the meta.
    fn get_meta(&self) -> Result<HnswMeta, StoreError>;
    /// Write the meta.
    fn put_meta(&mut self, meta: &HnswMeta) -> Result<(), StoreError>;
}

/// Cosine distance in `[0, 2]`; an incomparable pair is maximally far so it never wins.
fn dist(a: &Embedding, b: &Embedding) -> f32 {
    a.cosine(b).map(|c| 1.0 - c).unwrap_or(2.0)
}

/// A node's level, from a hash of its id — deterministic, so the graph is reproducible.
fn level_of(id: &[u8]) -> usize {
    let h = blake3::hash(id);
    let bytes: [u8; 8] = h.as_bytes()[..8].try_into().unwrap_or([0; 8]);
    let unit =
        ((u64::from_le_bytes(bytes) >> 11) as f64 / (1u64 << 53) as f64).max(f64::MIN_POSITIVE);
    (-unit.ln() * (1.0 / (M as f64).ln())).floor() as usize
}

/// **Insert `(id, vector)` into the persisted graph.** Returns `false` on a dimension mismatch (a
/// mixed-dimension index is uncomparable and must be refused, not silently corrupt the graph).
pub fn insert(store: &mut dyn NodeStore, id: &[u8], vector: Embedding) -> Result<bool, StoreError> {
    let mut meta = store.get_meta()?;
    match meta.dim {
        Some(d) if d != vector.dim() => return Ok(false),
        None => meta.dim = Some(vector.dim()),
        _ => {}
    }
    if vector.dim() == 0 {
        return Ok(false);
    }

    let level = level_of(id);
    let existing = store.get_node(id)?;
    // A fresh node starts with empty adjacency at every layer up to its level; a re-insert keeps its
    // level but clears its links (they are recomputed below).
    let node_level = existing
        .as_ref()
        .map(|n| n.neighbours.len().saturating_sub(1))
        .unwrap_or(level);
    let mut node = PersistedNode {
        vector: vector.clone(),
        neighbours: vec![Vec::new(); node_level + 1],
    };

    // First node: it is the entry point, linked to nothing.
    let Some(entry) = meta.entry.clone() else {
        store.put_node(id, &node)?;
        meta.entry = Some(id.to_vec());
        meta.max_level = node_level;
        store.put_meta(&meta)?;
        return Ok(true);
    };

    // Persist the node NOW, before linking — with its vector but not yet its neighbours. This is
    // load-bearing: while a neighbour back-links to this node and then prunes itself to its M closest,
    // it computes the distance to this node by reading it from the store. If the node were not stored
    // yet, that read would miss, the distance would come back "maximally far", and the fresh node would
    // be pruned straight back out — so no back-link ever sticks and the node is unreachable. (The
    // in-memory graph sidesteps this by pushing the node before it links; the store must do the same.)
    store.put_node(id, &node)?;

    // Descend the upper layers greedily to find an entry point at the node's level.
    let mut current = entry;
    for layer in (node_level + 1..=meta.max_level).rev() {
        current = greedy_closest(store, &vector, &current, layer)?;
    }

    // Link at every layer up to the node's level.
    for layer in (0..=node_level.min(meta.max_level)).rev() {
        let found = search_layer(store, &vector, &[current.clone()], EF_DEFAULT, layer)?;
        let selected: Vec<ItemId> = found
            .iter()
            .filter(|(nid, _)| nid.as_slice() != id)
            .take(M)
            .map(|(nid, _)| nid.clone())
            .collect();
        node.neighbours[layer] = selected.clone();

        // Back-link, pruning each neighbour to its M closest.
        for nid in &selected {
            if let Some(mut neighbour) = store.get_node(nid)? {
                if let Some(nlayer) = neighbour.neighbours.get_mut(layer) {
                    if !nlayer.iter().any(|x| x == id) {
                        nlayer.push(id.to_vec());
                        if nlayer.len() > M {
                            let nvec = neighbour.vector.clone();
                            let mut ranked: Vec<(ItemId, f32)> = Vec::new();
                            for m in &neighbour.neighbours[layer] {
                                let d = store
                                    .get_node(m)?
                                    .map(|mn| dist(&mn.vector, &nvec))
                                    .unwrap_or(2.0);
                                ranked.push((m.clone(), d));
                            }
                            ranked.sort_by(|a, b| {
                                a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal)
                            });
                            neighbour.neighbours[layer] =
                                ranked.into_iter().take(M).map(|(m, _)| m).collect();
                        }
                        store.put_node(nid, &neighbour)?;
                    }
                }
            }
        }
        if let Some((first, _)) = found.first() {
            current = first.clone();
        }
    }

    store.put_node(id, &node)?;
    if node_level > meta.max_level {
        meta.max_level = node_level;
        meta.entry = Some(id.to_vec());
    }
    store.put_meta(&meta)?;
    Ok(true)
}

/// **Search the persisted graph for the `k` nearest ids.** Reads only the nodes it traverses.
pub fn search(
    store: &dyn NodeStore,
    query: &Embedding,
    k: usize,
    ef: usize,
) -> Result<Vec<(ItemId, f32)>, StoreError> {
    let meta = store.get_meta()?;
    let Some(entry) = meta.entry else {
        return Ok(Vec::new());
    };
    if meta.dim != Some(query.dim()) || k == 0 {
        return Ok(Vec::new());
    }

    let mut current = entry;
    for layer in (1..=meta.max_level).rev() {
        current = greedy_closest(store, query, &current, layer)?;
    }
    let found = search_layer(store, query, &[current], ef.max(k), 0)?;
    let mut out: Vec<(ItemId, f32)> = found.into_iter().map(|(id, d)| (id, 1.0 - d)).collect();
    out.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    out.truncate(k);
    Ok(out)
}

fn greedy_closest(
    store: &dyn NodeStore,
    query: &Embedding,
    start: &[u8],
    layer: usize,
) -> Result<ItemId, StoreError> {
    let mut current = start.to_vec();
    let mut current_dist = store
        .get_node(&current)?
        .map(|n| dist(&n.vector, query))
        .unwrap_or(2.0);
    loop {
        let mut improved = false;
        if let Some(node) = store.get_node(&current)? {
            if let Some(neighbours) = node.neighbours.get(layer) {
                for n in neighbours {
                    let d = store
                        .get_node(n)?
                        .map(|nn| dist(&nn.vector, query))
                        .unwrap_or(2.0);
                    if d < current_dist {
                        current_dist = d;
                        current = n.clone();
                        improved = true;
                    }
                }
            }
        }
        if !improved {
            return Ok(current);
        }
    }
}

fn search_layer(
    store: &dyn NodeStore,
    query: &Embedding,
    entries: &[ItemId],
    ef: usize,
    layer: usize,
) -> Result<Vec<(ItemId, f32)>, StoreError> {
    let mut visited: HashSet<ItemId> = HashSet::new();
    let mut candidates: BinaryHeap<Closest> = BinaryHeap::new();
    let mut result: BinaryHeap<Farthest> = BinaryHeap::new();

    for e in entries {
        let d = store
            .get_node(e)?
            .map(|n| dist(&n.vector, query))
            .unwrap_or(2.0);
        visited.insert(e.clone());
        candidates.push(Closest {
            id: e.clone(),
            dist: d,
        });
        result.push(Farthest {
            id: e.clone(),
            dist: d,
        });
    }

    while let Some(Closest { id, dist: cd }) = candidates.pop() {
        if let Some(worst) = result.peek() {
            if cd > worst.dist && result.len() >= ef {
                break;
            }
        }
        if let Some(node) = store.get_node(&id)? {
            if let Some(neighbours) = node.neighbours.get(layer) {
                for n in neighbours {
                    if !visited.insert(n.clone()) {
                        continue;
                    }
                    let d = store
                        .get_node(n)?
                        .map(|nn| dist(&nn.vector, query))
                        .unwrap_or(2.0);
                    let worst = result.peek().map(|f| f.dist).unwrap_or(f32::INFINITY);
                    if d < worst || result.len() < ef {
                        candidates.push(Closest {
                            id: n.clone(),
                            dist: d,
                        });
                        result.push(Farthest {
                            id: n.clone(),
                            dist: d,
                        });
                        if result.len() > ef {
                            result.pop();
                        }
                    }
                }
            }
        }
    }

    let mut out: Vec<(ItemId, f32)> = result.into_iter().map(|f| (f.id, f.dist)).collect();
    out.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    Ok(out)
}

/// Min-heap by distance (closest pops first).
struct Closest {
    id: ItemId,
    dist: f32,
}
impl PartialEq for Closest {
    fn eq(&self, o: &Self) -> bool {
        self.dist == o.dist
    }
}
impl Eq for Closest {}
impl Ord for Closest {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        o.dist
            .partial_cmp(&self.dist)
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}
impl PartialOrd for Closest {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

/// Max-heap by distance (farthest pops first, for eviction).
struct Farthest {
    id: ItemId,
    dist: f32,
}
impl PartialEq for Farthest {
    fn eq(&self, o: &Self) -> bool {
        self.dist == o.dist
    }
}
impl Eq for Farthest {}
impl Ord for Farthest {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.dist
            .partial_cmp(&o.dist)
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}
impl PartialOrd for Farthest {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

/// The reserved prefix the graph lives under, in the branch's own tree. Reserved (`\x00loom/`), so it
/// is hidden from `scan`, excluded from merge, and inherited on fork — the same treatment as index
/// entries, and the reason a sibling branch cannot address this branch's graph (invariant I-11).
pub const RESERVED_HNSW_PREFIX: &[u8] = b"\x00loom/hnsw/";

/// The key one graph node is stored at, derived from the record id.
pub fn hnsw_node_key(record_id: &[u8]) -> Vec<u8> {
    let mut k = RESERVED_HNSW_PREFIX.to_vec();
    k.extend_from_slice(b"n/");
    k.extend_from_slice(record_id);
    k
}

/// The key the graph's meta is stored at.
pub fn hnsw_meta_key() -> Vec<u8> {
    let mut k = RESERVED_HNSW_PREFIX.to_vec();
    k.extend_from_slice(b"meta");
    k
}

/// The reserved prefix for the **ANN write buffer** — freshly-written vectors that are searchable but
/// not yet folded into the graph (the live-index / background-compaction design).
///
/// Reserved (`\x00loom/`), so — like the graph — it is hidden from `scan`, excluded from merge, and
/// inherited on fork: the buffer is **in-branch**, so AT-040 isolation holds for a buffered vector
/// exactly as it does for a graph node. A record's vector lands here (alongside its index entry) on
/// write, is searched by a bounded brute-scan unioned with the graph, and is removed **atomically** when
/// a fold commits it into the graph.
pub const RESERVED_ANNBUF_PREFIX: &[u8] = b"\x00loom/annbuf/";

/// The key a buffered vector is stored at, derived from the record id. The value is the embedding.
pub fn ann_buffer_key(record_id: &[u8]) -> Vec<u8> {
    let mut k = RESERVED_ANNBUF_PREFIX.to_vec();
    k.extend_from_slice(record_id);
    k
}

/// Recover the record id from a buffer key (strip the reserved prefix).
pub fn ann_buffer_record_id(key: &[u8]) -> Option<&[u8]> {
    key.strip_prefix(RESERVED_ANNBUF_PREFIX)
}
