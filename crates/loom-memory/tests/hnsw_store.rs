//! **The store-backed HNSW, held to the same recall oracle — and proven to survive serialization.**
//!
//! The persisted form (nodes keyed by id, in a `NodeStore`) must recover the same nearest neighbours as
//! brute force, exactly as the in-memory form does, and it must survive a full round trip through
//! bincode — because in production the store IS the branch's B-tree, and a node that does not decode is
//! a lost fact.

use std::collections::BTreeMap;

use loom_core::Embedding;
use loom_memory::{
    hnsw_insert, hnsw_search, HnswMeta, NodeStore, PersistedNode, StoreError, EF_DEFAULT,
};

/// An in-memory `NodeStore` that also serializes every node through bincode on write and back on read —
/// so the test exercises the *encoded* form, the same bytes the tree would hold.
#[derive(Default)]
struct MapStore {
    nodes: BTreeMap<Vec<u8>, Vec<u8>>, // id -> encoded PersistedNode
    meta: Vec<u8>,
}

impl NodeStore for MapStore {
    fn get_node(&self, id: &[u8]) -> Result<Option<PersistedNode>, StoreError> {
        match self.nodes.get(id) {
            Some(b) => Ok(Some(bincode::deserialize(b)?)),
            None => Ok(None),
        }
    }
    fn put_node(&mut self, id: &[u8], node: &PersistedNode) -> Result<(), StoreError> {
        self.nodes.insert(id.to_vec(), bincode::serialize(node)?);
        Ok(())
    }
    fn get_meta(&self) -> Result<HnswMeta, StoreError> {
        if self.meta.is_empty() {
            Ok(HnswMeta::default())
        } else {
            Ok(bincode::deserialize(&self.meta)?)
        }
    }
    fn put_meta(&mut self, meta: &HnswMeta) -> Result<(), StoreError> {
        self.meta = bincode::serialize(meta)?;
        Ok(())
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn unit(&mut self) -> f32 {
        (self.next() >> 40) as f32 / (1u64 << 24) as f32
    }
}
fn random_vec(rng: &mut Rng, dim: usize) -> Embedding {
    Embedding::new((0..dim).map(|_| rng.unit() * 2.0 - 1.0).collect::<Vec<_>>())
}
fn brute_force(items: &[(Vec<u8>, Embedding)], q: &Embedding, k: usize) -> Vec<Vec<u8>> {
    let mut s: Vec<(&Vec<u8>, f32)> = items
        .iter()
        .filter_map(|(id, v)| q.cosine(v).map(|c| (id, c)))
        .collect();
    s.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    s.into_iter().take(k).map(|(id, _)| id.clone()).collect()
}

/// **The persisted graph clears the same recall@10 floor as the in-memory one, reading through
/// bincode on every node access.**
#[test]
fn store_backed_hnsw_meets_the_recall_floor_through_serialization() {
    const DIM: usize = 32;
    const N: usize = 800;
    const K: usize = 10;
    const DATASETS: usize = 12;
    const FLOOR: f64 = 0.85;

    let mut total = 0.0f64;
    for d in 0..DATASETS {
        let mut rng = Rng(0xB0B + d as u64 * 7919);
        let items: Vec<(Vec<u8>, Embedding)> = (0..N)
            .map(|i| (format!("k{i}").into_bytes(), random_vec(&mut rng, DIM)))
            .collect();

        let mut store = MapStore::default();
        for (id, v) in &items {
            assert!(
                hnsw_insert(&mut store, id, v.clone()).unwrap(),
                "insert must accept a same-dim vector"
            );
        }
        assert_eq!(
            store.nodes.len(),
            N,
            "every distinct id is one persisted node"
        );

        let mut hits = 0usize;
        let mut possible = 0usize;
        for _ in 0..15 {
            let q = random_vec(&mut rng, DIM);
            let truth = brute_force(&items, &q, K);
            let got: std::collections::HashSet<Vec<u8>> = hnsw_search(&store, &q, K, EF_DEFAULT)
                .unwrap()
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            hits += truth.iter().filter(|id| got.contains(*id)).count();
            possible += truth.len();
        }
        total += hits as f64 / possible as f64;
    }
    let mean = total / DATASETS as f64;
    assert!(
        mean >= FLOOR,
        "store-backed recall@{K} = {mean:.3}, below floor {FLOOR}"
    );
}

/// **A graph rebuilt from ONLY the persisted bytes searches identically — nothing lives outside the
/// store.** This is the persistence guarantee: the tree is the whole graph.
#[test]
fn a_graph_rebuilt_from_stored_bytes_alone_still_searches() {
    let mut rng = Rng(42);
    let items: Vec<(Vec<u8>, Embedding)> = (0..200)
        .map(|i| (format!("k{i}").into_bytes(), random_vec(&mut rng, 16)))
        .collect();

    let mut store = MapStore::default();
    for (id, v) in &items {
        hnsw_insert(&mut store, id, v.clone()).unwrap();
    }
    let q = random_vec(&mut rng, 16);
    let before: Vec<Vec<u8>> = hnsw_search(&store, &q, 10, EF_DEFAULT)
        .unwrap()
        .into_iter()
        .map(|(id, _)| id)
        .collect();

    // "Reboot": a brand-new store holding only the serialized bytes.
    let rebuilt = MapStore {
        nodes: store.nodes.clone(),
        meta: store.meta.clone(),
    };
    let after: Vec<Vec<u8>> = hnsw_search(&rebuilt, &q, 10, EF_DEFAULT)
        .unwrap()
        .into_iter()
        .map(|(id, _)| id)
        .collect();

    assert_eq!(
        before, after,
        "a graph is defined entirely by its stored bytes — nothing in RAM outside them"
    );
}
