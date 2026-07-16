//! **The HNSW recall oracle.**
//!
//! An approximate index is only honest if you *measure* how approximate it is. The brute-force scan
//! (the v0.1 retrieval) is the ground truth: for a query, the exact `k` nearest by cosine are knowable.
//! This computes that exact set and asserts the HNSW graph recovers a high fraction of it —
//! **recall@k** — averaged across many randomized datasets and queries. The graph is *allowed* to miss;
//! it is not allowed to miss more than the floor we publish.
//!
//! It also pins the two things that must be exact, not approximate: the graph never returns an id it
//! was not given (no phantom results), and re-inserting an id replaces rather than duplicates it.

use loom_core::Embedding;
use loom_memory::{Hnsw, EF_DEFAULT};

/// A tiny deterministic PRNG (SplitMix64) — no external rng, and reproducible so a failing seed is
/// debuggable.
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

/// Exact top-k by cosine — the ground truth.
fn brute_force(items: &[(Vec<u8>, Embedding)], query: &Embedding, k: usize) -> Vec<Vec<u8>> {
    let mut scored: Vec<(&Vec<u8>, f32)> = items
        .iter()
        .filter_map(|(id, v)| query.cosine(v).map(|c| (id, c)))
        .collect();
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored
        .into_iter()
        .take(k)
        .map(|(id, _)| id.clone())
        .collect()
}

/// **recall@10 against brute force stays above the floor, across randomized datasets.**
#[test]
fn hnsw_recall_at_10_meets_the_floor() {
    const DIM: usize = 32;
    const K: usize = 10;
    // Scaled by env so the debug `test` job stays fast; the full-scale run is a dedicated release CI
    // job (RECALL_FULL=1), the same pattern the model oracles use. A small graph still catches gross
    // recall regressions; the large one is the meaningful floor.
    let full = std::env::var("RECALL_FULL").is_ok();
    let n: usize = if full { 1000 } else { 150 };
    let datasets: usize = if full { 20 } else { 3 };
    // The published floor. HNSW at M=16, ef=64 comfortably clears this on random data; we assert a
    // conservative bar so the test is a regression guard, not a coin flip.
    const FLOOR: f64 = 0.85;

    let mut total_recall = 0.0f64;
    for d in 0..datasets {
        let mut rng = Rng(0xA11CE + d as u64 * 7919);
        let items: Vec<(Vec<u8>, Embedding)> = (0..n)
            .map(|i| (format!("k{i}").into_bytes(), random_vec(&mut rng, DIM)))
            .collect();

        let mut index = Hnsw::new();
        for (id, v) in &items {
            assert!(
                index.insert(id.clone(), v.clone()),
                "insert must accept a same-dim vector"
            );
        }
        assert_eq!(index.len(), n, "every distinct id is indexed once");

        // 20 queries per dataset.
        let mut hits = 0usize;
        let mut possible = 0usize;
        for _ in 0..20 {
            let q = random_vec(&mut rng, DIM);
            let truth = brute_force(&items, &q, K);
            let got: std::collections::HashSet<Vec<u8>> = index
                .search(&q, K, EF_DEFAULT)
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            hits += truth.iter().filter(|id| got.contains(*id)).count();
            possible += truth.len();
        }
        total_recall += hits as f64 / possible as f64;
    }

    let mean_recall = total_recall / datasets as f64;
    assert!(
        mean_recall >= FLOOR,
        "HNSW recall@{K} = {mean_recall:.3}, below the floor {FLOOR}. An approximate index that misses \
         this much is not returning the memory the agent needs."
    );
}

/// **No phantom results, and re-insert replaces rather than duplicates.**
#[test]
fn hnsw_returns_only_indexed_ids_and_dedupes_reinserts() {
    let mut index = Hnsw::new();
    for i in 0..50 {
        let mut rng = Rng(i);
        index.insert(format!("k{i}").into_bytes(), random_vec(&mut rng, 8));
    }
    // Re-insert an existing id with a new vector: count must not change.
    let before = index.len();
    let mut rng = Rng(999);
    index.insert(b"k7".to_vec(), random_vec(&mut rng, 8));
    assert_eq!(
        index.len(),
        before,
        "re-inserting an id must replace, not duplicate"
    );

    // Every returned id was inserted.
    let q = random_vec(&mut Rng(123), 8);
    for (id, _) in index.search(&q, 20, EF_DEFAULT) {
        let s = String::from_utf8_lossy(&id);
        assert!(
            s.starts_with('k'),
            "search returned an id that was never inserted: {s}"
        );
    }
}

/// **Mixed dimensions are refused, not silently corrupting the index.**
#[test]
fn hnsw_refuses_a_mismatched_dimension() {
    let mut index = Hnsw::new();
    assert!(index.insert(b"a".to_vec(), Embedding::new([1.0, 2.0, 3.0])));
    assert!(
        !index.insert(b"b".to_vec(), Embedding::new([1.0, 2.0])),
        "a different-dimension vector must be refused — a mixed index compares apples to oranges"
    );
    assert_eq!(index.len(), 1);
}

/// **An empty graph, a zero-k query, and a one-item graph are all well-formed, not panics.**
#[test]
fn hnsw_degenerate_cases_do_not_panic() {
    let empty = Hnsw::new();
    assert!(empty
        .search(&Embedding::new([1.0, 2.0]), 5, EF_DEFAULT)
        .is_empty());

    let mut one = Hnsw::new();
    one.insert(b"only".to_vec(), Embedding::new([1.0, 0.0]));
    assert_eq!(
        one.search(&Embedding::new([1.0, 0.0]), 5, EF_DEFAULT).len(),
        1
    );
    assert!(
        one.search(&Embedding::new([1.0, 0.0]), 0, EF_DEFAULT)
            .is_empty(),
        "k=0 returns nothing"
    );
}
