//! **HNSW build complexity, measured — O(N·log N), proven against O(N²) with a fitted curve.**
//!
//! The graph build inserts each vector by *navigating the graph it has so far* (greedy descent + a
//! bounded beam), so each insert is ~O(log N) and the whole build ~O(N·log N). The old story was that it
//! was quadratic; it never was (see the at-map note), but it was slow — the cost was a large per-insert
//! constant paid through the per-operation tree/bincode path plus write amplification, not a brute-force
//! scan. The build now runs in RAM (unit-normalized vectors, a bare-dot distance, an epoch-tagged
//! visited set) and persists once in a sorted pass; this benchmark is the evidence that what remains is
//! N·log N, not N².
//!
//! # What it proves, and how (same discipline as AT-011)
//!
//! It times the build across a geometric range and reports, per size:
//! - `c_nlogn = build_ms / (N · log₂N)` — the constant **if** the build is N·log N. Under N·log N this is
//!   ~flat (it drifts up only with the CPU cache-miss rate as the working set outgrows cache — a memory
//!   effect, not an algorithmic one).
//! - `c_n²   = build_ms / N² · 1e6` — the constant **if** the build is N². Under a genuine N·log N build
//!   this **collapses** by ~10× per 10× N (because N² / (N·log N) ≈ N/log N grows). A build that were
//!   really quadratic would instead hold `c_n²` roughly flat.
//! - the empirical **exponent** between consecutive points (`log(ratio_ms)/log(ratio_N)`) — for N·log N
//!   this sits near 1 (a little above, from cache), and is nowhere near 2.
//!
//! # Recall is the gate the speed is not allowed to buy
//!
//! Fast-but-wrong is not a win, so it also measures **recall@10 vs brute force** at the smallest and
//! largest sizes and asserts ≥ 0.85. Normalizing the vectors is recall-neutral by construction
//! (`dot(â,b̂) = cos(a,b)`), so this gate confirms the *whole* pipeline, not just the arithmetic.
//!
//! # Run it
//!
//! ```sh
//! # up to 100k (a couple of minutes, in release):
//! cargo test -p loom-core --release --test hnsw_build_scaling -- --ignored --nocapture
//! # add the 1M point (needs ~1–2 GB RAM; run on a host with headroom):
//! HNSW_BENCH_1M=1 cargo test -p loom-core --release --test hnsw_build_scaling -- --ignored --nocapture
//! ```

use std::time::Instant;

use loom_core::{Embedding, Hnsw};

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
/// A built graph held for the recall gate: the graph, its vectors, the cluster centers, and N.
type Built = (Hnsw, Vec<Embedding>, Vec<Vec<f32>>, usize);

/// A **clustered** dataset — the honest stand-in for real embeddings, which live near topics/clusters,
/// not spread uniformly over the sphere. Uniform-random high-dim vectors are the pathological case for
/// *any* nearest-neighbour index: everything is near-orthogonal, so the "true top-10" are barely
/// separated from the rest and recall is meaningless. Real embeddings have structure, and this makes it:
/// `centers` random hubs, each point a hub plus small noise. Recall against this is what a deployment
/// actually sees.
fn clustered_dataset(n: usize, dim: usize, seed: u64) -> (Vec<Embedding>, Vec<Vec<f32>>) {
    let mut rng = Rng(seed);
    let n_centers = (n / 500).clamp(16, 4096);
    let centers: Vec<Vec<f32>> = (0..n_centers)
        .map(|_| (0..dim).map(|_| rng.unit() * 2.0 - 1.0).collect())
        .collect();
    let vecs = (0..n)
        .map(|i| {
            let c = &centers[i % n_centers];
            Embedding::new(
                c.iter()
                    .map(|&x| x + (rng.unit() * 2.0 - 1.0) * 0.25)
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    (vecs, centers)
}

/// A query drawn from the same clustered distribution: a random center plus noise.
fn clustered_query(centers: &[Vec<f32>], dim: usize, rng: &mut Rng) -> Embedding {
    let c = &centers[(rng.next() as usize) % centers.len()];
    Embedding::new(
        c.iter()
            .take(dim)
            .map(|&x| x + (rng.unit() * 2.0 - 1.0) * 0.25)
            .collect::<Vec<_>>(),
    )
}

/// Exact top-`k` by brute force — the ground truth recall is measured against.
fn brute_top_k(vecs: &[Embedding], q: &Embedding, k: usize) -> Vec<usize> {
    let mut scored: Vec<(usize, f32)> = vecs
        .iter()
        .enumerate()
        .filter_map(|(i, v)| q.cosine(v).map(|c| (i, c)))
        .collect();
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored.into_iter().take(k).map(|(i, _)| i).collect()
}

/// Recall@k of the graph against brute force, averaged over `queries` clustered queries, at beam `ef`.
fn recall_at_k(
    graph: &Hnsw,
    vecs: &[Embedding],
    centers: &[Vec<f32>],
    dim: usize,
    k: usize,
    queries: usize,
    ef: usize,
) -> f64 {
    let mut rng = Rng(0xF00D);
    let mut hit = 0usize;
    let mut total = 0usize;
    for _ in 0..queries {
        let q = clustered_query(centers, dim, &mut rng);
        let truth: std::collections::HashSet<usize> =
            brute_top_k(vecs, &q, k).into_iter().collect();
        let got = graph.search(&q, k, ef);
        for (id, _) in got {
            // ids are "k{i}" — recover i and check membership.
            if let Ok(s) = std::str::from_utf8(&id) {
                if let Ok(i) = s.trim_start_matches('k').parse::<usize>() {
                    if truth.contains(&i) {
                        hit += 1;
                    }
                }
            }
        }
        total += truth.len();
    }
    hit as f64 / total.max(1) as f64
}

#[test]
#[ignore = "build-complexity benchmark; run with --release --ignored --nocapture. HNSW_BENCH_1M=1 adds the 1M point (~1-2 GB RAM)."]
fn hnsw_build_is_n_log_n() {
    const DIM: usize = 64;
    const K: usize = 10;
    const FLOOR: f64 = 0.85;

    let mut sizes: Vec<usize> = vec![1_000, 10_000, 100_000];
    if std::env::var("HNSW_BENCH_1M").is_ok() {
        sizes.push(1_000_000);
    }
    if let Ok(spec) = std::env::var("HNSW_BENCH_SIZES") {
        sizes = spec
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
    }

    println!("\n=== HNSW build complexity (DIM={DIM}, release) ===");
    println!(
        "{:>10}  {:>11}  {:>11}  {:>13}  {:>11}  {:>8}",
        "N", "build_ms", "us/insert", "c_nlogn(ns)", "c_n2(ps)", "exp"
    );

    let mut rows: Vec<(usize, f64)> = Vec::new();
    // Keep the largest built graph + its vectors + cluster centers for the recall gate.
    let mut largest: Option<Built> = None;

    for (idx, &n) in sizes.iter().enumerate() {
        let (vecs, centers) = clustered_dataset(n, DIM, 0xB0B);

        let mut graph = Hnsw::new();
        let t = Instant::now();
        for (i, v) in vecs.iter().enumerate() {
            graph.insert(format!("k{i}").into_bytes(), v.clone());
        }
        let ms = t.elapsed().as_secs_f64() * 1000.0;

        let nf = n as f64;
        let c_nlogn = ms * 1e6 / (nf * nf.log2()); // ns per (N·log₂N)
        let c_n2 = ms * 1e6 / (nf * nf) * 1e6; // ps per N²
        let exp = rows
            .last()
            .map(|&(pn, pm)| (ms / pm).ln() / (n as f64 / pn as f64).ln());
        println!(
            "{n:>10}  {ms:>11.0}  {:>11.1}  {c_nlogn:>13.2}  {c_n2:>11.3}  {}",
            ms * 1000.0 / nf,
            exp.map(|e| format!("{e:>8.2}"))
                .unwrap_or_else(|| format!("{:>8}", "-"))
        );

        rows.push((n, ms));
        if idx + 1 == sizes.len() {
            largest = Some((graph, vecs, centers, n));
        }
    }

    // ── the verdict on the curve ──
    // If the build is N·log N, c_nlogn stays within a small factor across the whole range while c_n2
    // collapses by ~10× per decade. Report both spreads so the reader sees which model the data fits.
    let c_nlogn_of = |&(n, ms): &(usize, f64)| ms * 1e6 / (n as f64 * (n as f64).log2());
    let c_n2_of = |&(n, ms): &(usize, f64)| ms * 1e6 / (n as f64 * n as f64) * 1e6;
    let spread = |f: &dyn Fn(&(usize, f64)) -> f64| -> f64 {
        let vs: Vec<f64> = rows.iter().map(f).collect();
        let (mn, mx) = vs
            .iter()
            .fold((f64::MAX, 0.0f64), |(a, b), &v| (a.min(v), b.max(v)));
        if mn > 0.0 {
            mx / mn
        } else {
            f64::INFINITY
        }
    };
    let nlogn_spread = spread(&c_nlogn_of);
    let n2_spread = spread(&c_n2_of);
    println!(
        "\n  c_nlogn spread across the range: {nlogn_spread:.2}×   (N·log N ⇒ small, from cache only)"
    );
    println!(
        "  c_n²    spread across the range: {n2_spread:.2}×   (a real N² would be small here; a N·log N build makes it collapse)"
    );
    println!(
        "  ⇒ the data tracks {} — c_n² varies {:.0}× more than c_nlogn, so N² is rejected.",
        if n2_spread > nlogn_spread * 4.0 {
            "N·log N"
        } else {
            "AMBIGUOUS — investigate"
        },
        n2_spread / nlogn_spread.max(1e-9),
    );
    assert!(
        n2_spread > nlogn_spread * 4.0,
        "the build does not clearly track N·log N over N²: c_nlogn spread {nlogn_spread:.2}× vs c_n² spread {n2_spread:.2}×"
    );

    // ── recall gate: fast is not allowed to mean wrong ──
    // Recall@10 vs brute force on the CLUSTERED (real-embedding-shaped) data, swept across query beam
    // widths — recall trades against `ef`, and the honest number names the `ef` that reaches the floor at
    // this scale (the graph the build produced is what makes a modest `ef` enough).
    if let Some((graph, vecs, centers, n)) = &largest {
        let queries = if *n >= 200_000 { 25 } else { 50 };
        println!("\n  recall@{K} vs brute force at N={n} (clustered data), by query beam ef:");
        let mut passed_ef = None;
        for &ef in &[64usize, 128, 256] {
            let recall = recall_at_k(graph, vecs, centers, DIM, K, queries, ef);
            let mark = if recall >= FLOOR { " ✓" } else { "" };
            println!("    ef={ef:>4}: {recall:.3}{mark}");
            if recall >= FLOOR && passed_ef.is_none() {
                passed_ef = Some(ef);
            }
        }
        assert!(
            passed_ef.is_some(),
            "recall@{K} stayed below the {FLOOR} floor at N={n} for every beam up to 256 — the build \
             under-connects the graph"
        );
        println!(
            "  ⇒ floor {FLOOR} reached at ef={} for N={n}",
            passed_ef.unwrap()
        );
    }

    // And at the smallest size, where the default query beam must already clear the floor.
    {
        let n = *sizes.iter().min().unwrap();
        let (vecs, centers) = clustered_dataset(n, DIM, 0xB0B);
        let mut graph = Hnsw::new();
        for (i, v) in vecs.iter().enumerate() {
            graph.insert(format!("k{i}").into_bytes(), v.clone());
        }
        let recall = recall_at_k(&graph, &vecs, &centers, DIM, K, 50, loom_core::EF_DEFAULT);
        println!(
            "  recall@{K} at N={n} (ef={}, the default): {recall:.3}  (floor {FLOOR})",
            loom_core::EF_DEFAULT
        );
        assert!(
            recall >= FLOOR,
            "recall@{K} = {recall:.3} at N={n} below floor at the default beam"
        );
    }
}
