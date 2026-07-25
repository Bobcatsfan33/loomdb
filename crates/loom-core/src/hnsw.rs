//! **A per-branch HNSW index — sub-linear vector search that stays inside the branch.**
//!
//! # Why this exists, and the one constraint that shapes it
//!
//! v0.1 retrieval scans every index entry on the branch: correct, branch-isolated, and O(entries). This
//! is the sub-linear replacement — a Hierarchical Navigable Small World graph, the standard approximate
//! nearest-neighbour structure. The **load-bearing constraint** is invariant I-11: the index lives *in
//! the branch*, never in a shared store. A shared ANN index keyed by branch would reintroduce the exact
//! cross-branch leak AT-040 was designed out — so an HNSW graph belongs to one branch, is built only
//! from that branch's entries, and a sibling's graph is a different graph it cannot address.
//!
//! # Why an approximate index gets a *recall oracle*, not just tests
//!
//! HNSW trades exactness for speed: it can miss a true nearest neighbour. That is acceptable *only if
//! we measure how often*, so the recall is a number we stand behind rather than a hope. The oracle
//! (`tests/hnsw.rs`) computes the exact top-k by brute force — the ground truth the v0.1 scan already
//! gives — and asserts the graph's recall@k stays above a floor across many randomized datasets. An
//! approximate index without a recall measurement is a correctness claim with no evidence.
//!
//! This module is **pure and deterministic**: no clock, no RNG that varies run to run (level
//! assignment is a hash of the id, so the same items build the same graph). Persisting the graph into
//! the branch tree is the next slice; the algorithm is proven here first.

use std::cell::{Cell, RefCell};
use std::collections::{BinaryHeap, HashMap};

use crate::hnsw_store::{HnswMeta, PersistedNode};
use crate::Embedding;

/// The identity of an indexed item — its record key.
pub type ItemId = Vec<u8>;

/// How many neighbours a node keeps per **upper** layer (the classic HNSW `M`), and how many links a
/// new node forms per layer. Higher = better recall, more memory and slower insert.
pub const M: usize = 16;

/// The maximum degree at **layer 0** — the classic HNSW `Mmax0 = 2M`. Layer 0 is the densest and does
/// the fine-grained search, so it is allowed twice the connectivity of the sparse upper layers. Capping
/// layer 0 at `M` (as an earlier version did) starves the base layer and is why recall sagged as the
/// graph grew; `2M` here is what holds it at scale.
pub const M_MAX0: usize = 2 * M;

/// The base of the exponential level distribution. `1/ln(M)` is the value the HNSW paper derives as
/// optimal; a node's level is `floor(-ln(h) * mult)` for a hash `h` in (0,1].
const LEVEL_MULT: f64 = 0.36067; // 1 / ln(16)

/// How wide the **query** beam is by default (`ef`). The caller can override it per search.
pub const EF_DEFAULT: usize = 64;

/// How wide the **construction** beam is (`efConstruction`), separate from the query `ef`. The build can
/// afford a wider beam than a latency-sensitive query — it runs once and sets the graph quality every
/// later search inherits — so a larger value here buys recall at scale for a constant-factor build cost
/// (it does not change the N·log N shape). Tuned with the build-complexity benchmark's recall gate.
pub const EF_CONSTRUCTION: usize = 200;

/// One node: its vector, and its neighbours per layer.
struct Node {
    vector: Embedding,
    /// `neighbours[l]` is the adjacency at layer `l`. Layer 0 is the densest.
    neighbours: Vec<Vec<usize>>,
}

/// A per-branch HNSW graph.
///
/// Built by inserting `(ItemId, Embedding)` pairs. `search` returns the approximate `k` nearest by
/// cosine distance. Deterministic: the same inserts in the same order always build the same graph.
pub struct Hnsw {
    nodes: Vec<Node>,
    ids: Vec<ItemId>,
    id_to_index: HashMap<ItemId, usize>,
    entry: Option<usize>,
    max_level: usize,
    dim: Option<usize>,
    /// Reusable "visited" set for `search_layer`, keyed by node index, tagged with an epoch so it is
    /// cleared in O(1) (bump the epoch) instead of reallocated per call. This replaces a per-call
    /// `HashSet<usize>` — whose SipHash on ~1000 lookups/insert dominated the build — with a plain array
    /// probe, and it is the single largest per-insert constant cut. Interior-mutable so `search` (`&self`)
    /// and `relink` (`&mut self`) can both use it; a node `n` counts as visited this call iff
    /// `visited[n] == epoch`.
    visited: RefCell<Vec<u32>>,
    epoch: Cell<u32>,
}

impl Default for Hnsw {
    fn default() -> Self {
        Hnsw::new()
    }
}

impl Hnsw {
    /// An empty graph.
    pub fn new() -> Self {
        Hnsw {
            nodes: Vec::new(),
            ids: Vec::new(),
            id_to_index: HashMap::new(),
            entry: None,
            max_level: 0,
            dim: None,
            visited: RefCell::new(Vec::new()),
            epoch: Cell::new(0),
        }
    }

    /// How many items are indexed.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// **Insert an item.** Re-inserting the same id replaces its vector and relinks it.
    ///
    /// Returns `false` (and does nothing) if the vector's dimensionality disagrees with the graph's —
    /// a mixed-dimension index cannot be compared, and silently accepting it would corrupt every later
    /// search. The caller decides what to do; we do not guess.
    pub fn insert(&mut self, id: ItemId, vector: Embedding) -> bool {
        // Normalize on the way in, once: the graph is built with a bare dot product (see `dist`), which
        // on unit vectors is cosine exactly — same graph as cosine would build, at a fraction of the
        // per-distance cost. `normalized` returns `None` for a zero/empty vector (no direction, cannot
        // be placed), which subsumes the old dim-0 rejection.
        let Some(vector) = vector.normalized() else {
            return false;
        };
        match self.dim {
            Some(d) if d != vector.dim() => return false,
            None => self.dim = Some(vector.dim()),
            _ => {}
        }

        // Replace-in-place if the id already exists: drop its old links, keep its slot.
        if let Some(&idx) = self.id_to_index.get(&id) {
            self.nodes[idx].vector = vector;
            for layer in &mut self.nodes[idx].neighbours {
                layer.clear();
            }
            self.relink(idx);
            return true;
        }

        let level = self.level_of(&id);
        let idx = self.nodes.len();
        self.nodes.push(Node {
            vector,
            neighbours: vec![Vec::new(); level + 1],
        });
        self.ids.push(id.clone());
        self.id_to_index.insert(id, idx);

        if self.entry.is_none() {
            self.entry = Some(idx);
            self.max_level = level;
            return true;
        }
        self.relink(idx);
        if level > self.max_level {
            self.max_level = level;
            self.entry = Some(idx);
        }
        true
    }

    /// **Search for the `k` nearest ids to `query`, approximately.** `ef` is the beam width; a larger
    /// `ef` finds more true neighbours at more cost. Returns `(id, similarity)` best-first.
    pub fn search(&self, query: &Embedding, k: usize, ef: usize) -> Vec<(ItemId, f32)> {
        let Some(entry) = self.entry else {
            return Vec::new();
        };
        if self.dim != Some(query.dim()) || k == 0 {
            return Vec::new();
        }
        // Normalize the query once, so every `dist` below is a bare dot product against the unit-length
        // stored vectors. A zero-vector query has no direction and matches nothing.
        let Some(query_n) = query.normalized() else {
            return Vec::new();
        };
        let query = &query_n;

        // Descend the upper layers greedily to find a good entry point for layer 0.
        let mut current = entry;
        for layer in (1..=self.max_level).rev() {
            current = self.greedy_closest(query, current, layer);
        }

        // A proper beam search at layer 0.
        let found = self.search_layer(query, &[current], (ef).max(k), 0);
        let mut out: Vec<(ItemId, f32)> = found
            .into_iter()
            .map(|(idx, dist)| (self.ids[idx].clone(), 1.0 - dist))
            .collect();
        out.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        out.truncate(k);
        out
    }

    /// **Export the built graph as persisted nodes, carrying the caller's RAW vectors** — ready to
    /// bulk-write into a [`NodeStore`](crate::NodeStore).
    ///
    /// This is the bridge from the fast in-RAM build to the durable graph. The graph *structure* (levels,
    /// adjacency, entry point) was computed on normalized vectors with a dot product; the persisted
    /// vectors are the caller's originals (`raw`, keyed by id), so the on-disk bytes never change and a
    /// search over them with cosine reproduces the same ranking. A node whose id is absent from `raw`
    /// falls back to its normalized vector — still correct under cosine, so the export is total.
    ///
    /// Adjacency is translated from internal indices to ids here, once, at the end — the whole build
    /// never paid the cost of id-keyed lookups in its hot loop.
    pub fn export_persisted(
        &self,
        raw: &HashMap<ItemId, Embedding>,
    ) -> (Vec<(ItemId, PersistedNode)>, HnswMeta) {
        let mut out = Vec::with_capacity(self.nodes.len());
        for (idx, node) in self.nodes.iter().enumerate() {
            let id = &self.ids[idx];
            let neighbours: Vec<Vec<ItemId>> = node
                .neighbours
                .iter()
                .map(|layer| layer.iter().map(|&n| self.ids[n].clone()).collect())
                .collect();
            let vector = raw.get(id).cloned().unwrap_or_else(|| node.vector.clone());
            out.push((id.clone(), PersistedNode { vector, neighbours }));
        }
        let meta = HnswMeta {
            entry: self.entry.map(|e| self.ids[e].clone()),
            max_level: self.max_level,
            dim: self.dim,
        };
        (out, meta)
    }

    // ── internals ──────────────────────────────────────────────────────────────────────────────────

    /// Cosine *distance* in `[0, 2]` (`1 - cosine`); an incomparable pair is treated as maximally far,
    /// so it never wins a nearest-neighbour race.
    ///
    /// Stored vectors are unit-normalized ([`insert`](Self::insert)) and the query is normalized on entry
    /// ([`search`](Self::search)/[`relink`](Self::relink) queries with stored vectors), so cosine is a
    /// bare **dot product** here: `1 - dot`. An incomparable pair (dim mismatch) yields `None`, treated as
    /// dot `-1` ⇒ distance 2 (maximally far), never winning a race.
    fn dist(&self, a: usize, query: &Embedding) -> f32 {
        1.0 - self.nodes[a].vector.dot(query).unwrap_or(-1.0)
    }

    /// A node's level, from a hash of its id — deterministic, so the graph does not depend on a RNG
    /// that varies run to run (a graph that rebuilds differently each run is not reproducible).
    fn level_of(&self, id: &[u8]) -> usize {
        let h = blake3::hash(id);
        let bytes: [u8; 8] = h.as_bytes()[..8].try_into().unwrap_or([0; 8]);
        // Map to (0, 1], avoiding 0.
        let unit =
            ((u64::from_le_bytes(bytes) >> 11) as f64 / (1u64 << 53) as f64).max(f64::MIN_POSITIVE);
        (-unit.ln() * LEVEL_MULT).floor() as usize
    }

    /// Greedily hop to the neighbour closest to `query` at one layer, from `start`.
    fn greedy_closest(&self, query: &Embedding, start: usize, layer: usize) -> usize {
        let mut current = start;
        let mut current_dist = self.dist(current, query);
        loop {
            let mut improved = false;
            if let Some(neighbours) = self.nodes[current].neighbours.get(layer) {
                for &n in neighbours {
                    let d = self.dist(n, query);
                    if d < current_dist {
                        current_dist = d;
                        current = n;
                        improved = true;
                    }
                }
            }
            if !improved {
                return current;
            }
        }
    }

    /// Beam search at one layer: returns up to `ef` nearest `(idx, distance)` to `query`, best first.
    fn search_layer(
        &self,
        query: &Embedding,
        entries: &[usize],
        ef: usize,
        layer: usize,
    ) -> Vec<(usize, f32)> {
        // Epoch-tagged visited set: bump the epoch so the array reads as empty in O(1), growing it to
        // cover every node. `visited[n] == epoch` means "seen this call".
        let mut visited = self.visited.borrow_mut();
        if visited.len() < self.nodes.len() {
            visited.resize(self.nodes.len(), 0);
        }
        let epoch = self.epoch.get().wrapping_add(1);
        self.epoch.set(epoch);
        let mut seen = |n: usize| -> bool {
            if visited[n] == epoch {
                true
            } else {
                visited[n] = epoch;
                false
            }
        };

        // `candidates`: a min-heap by distance (closest first) to explore. `result`: a max-heap by
        // distance (farthest first) so we can evict the worst when it overflows `ef`.
        let mut candidates: BinaryHeap<Rev> = BinaryHeap::new();
        let mut result: BinaryHeap<Far> = BinaryHeap::new();

        for &e in entries {
            let d = self.dist(e, query);
            seen(e);
            candidates.push(Rev { idx: e, dist: d });
            result.push(Far { idx: e, dist: d });
        }

        while let Some(Rev { idx, dist }) = candidates.pop() {
            // If the closest unexplored candidate is farther than the worst kept result, stop.
            if let Some(worst) = result.peek() {
                if dist > worst.dist && result.len() >= ef {
                    break;
                }
            }
            if let Some(neighbours) = self.nodes[idx].neighbours.get(layer) {
                for &n in neighbours {
                    if seen(n) {
                        continue;
                    }
                    let d = self.dist(n, query);
                    let worst = result.peek().map(|f| f.dist).unwrap_or(f32::INFINITY);
                    if d < worst || result.len() < ef {
                        candidates.push(Rev { idx: n, dist: d });
                        result.push(Far { idx: n, dist: d });
                        if result.len() > ef {
                            result.pop();
                        }
                    }
                }
            }
        }

        let mut out: Vec<(usize, f32)> = result.into_iter().map(|f| (f.idx, f.dist)).collect();
        out.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        out
    }

    /// **The neighbour-selection heuristic** (HNSW paper, Algorithm 4) — pick up to `m` links from
    /// `candidates` (given as `(idx, distance-to-base)`, closest first) that are *diverse*, not merely
    /// closest.
    ///
    /// A candidate `e` is kept only if it is closer to `base` than to every neighbour already kept —
    /// `dist(e, base) < dist(e, r)` for all kept `r`. This drops a candidate that sits "behind" one
    /// already chosen (in roughly the same direction), so the `m` links spread around the node instead of
    /// clustering on one side. That diversity is what keeps the graph *navigable* as it grows: plain
    /// take-`m`-closest packs links into dense regions, and a query arriving from a sparse direction finds
    /// no edge to follow — the recall collapse this replaces.
    fn select_heuristic(&self, candidates: &[(usize, f32)], m: usize) -> Vec<usize> {
        let mut kept: Vec<usize> = Vec::with_capacity(m);
        for &(e, d_e_base) in candidates {
            if kept.len() >= m {
                break;
            }
            // Keep `e` unless it is closer to an already-kept neighbour than to `base`.
            let redundant = kept.iter().any(|&r| {
                let d_e_r = 1.0
                    - self.nodes[e]
                        .vector
                        .dot(&self.nodes[r].vector)
                        .unwrap_or(-1.0);
                d_e_r < d_e_base
            });
            if !redundant {
                kept.push(e);
            }
        }
        kept
    }

    /// Link a freshly-inserted (or replaced) node into the graph at every layer up to its level.
    fn relink(&mut self, idx: usize) {
        let Some(entry) = self.entry else { return };
        let node_level = self.nodes[idx].neighbours.len() - 1;
        let query = self.nodes[idx].vector.clone();

        // Descend from the top to the node's level, greedily.
        let mut current = entry;
        for layer in (node_level + 1..=self.max_level).rev() {
            current = self.greedy_closest(&query, current, layer);
        }

        for layer in (0..=node_level.min(self.max_level)).rev() {
            // A WIDE construction beam, then the diversity heuristic to pick M links from it.
            let found: Vec<(usize, f32)> = self
                .search_layer(&query, &[current], EF_CONSTRUCTION, layer)
                .into_iter()
                .filter(|(i, _)| *i != idx)
                .collect();
            let selected = self.select_heuristic(&found, M);

            // Layer 0 tolerates twice the degree (Mmax0); the sparse upper layers stay at M.
            let m_max = if layer == 0 { M_MAX0 } else { M };

            // Link both ways.
            self.nodes[idx].neighbours[layer] = selected.clone();
            for &n in &selected {
                let already = self.nodes[n]
                    .neighbours
                    .get(layer)
                    .map(|l| l.contains(&idx))
                    .unwrap_or(false);
                if already {
                    continue;
                }
                if let Some(nlayer) = self.nodes[n].neighbours.get_mut(layer) {
                    nlayer.push(idx);
                }
                // If the neighbour is now over-connected, re-select its links with the SAME diversity
                // heuristic (not just "keep closest") — so pruning preserves navigability too.
                if self.nodes[n].neighbours[layer].len() > m_max {
                    let nvec = self.nodes[n].vector.clone();
                    let mut ranked: Vec<(usize, f32)> = self.nodes[n].neighbours[layer]
                        .iter()
                        .map(|&m| (m, self.dist(m, &nvec)))
                        .collect();
                    ranked
                        .sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
                    self.nodes[n].neighbours[layer] = self.select_heuristic(&ranked, m_max);
                }
            }
            if let Some((i, _)) = found.first() {
                current = *i;
            }
        }
    }
}

/// A heap entry ordered so the CLOSEST pops first (a min-heap over distance).
struct Rev {
    idx: usize,
    dist: f32,
}
impl PartialEq for Rev {
    fn eq(&self, other: &Self) -> bool {
        self.dist == other.dist
    }
}
impl Eq for Rev {}
impl Ord for Rev {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reversed: smaller distance is "greater" so it pops first from a max-heap.
        other
            .dist
            .partial_cmp(&self.dist)
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}
impl PartialOrd for Rev {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A heap entry ordered so the FARTHEST pops first (a max-heap over distance) — for evicting the worst.
struct Far {
    idx: usize,
    dist: f32,
}
impl PartialEq for Far {
    fn eq(&self, other: &Self) -> bool {
        self.dist == other.dist
    }
}
impl Eq for Far {}
impl Ord for Far {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.dist
            .partial_cmp(&other.dist)
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}
impl PartialOrd for Far {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
