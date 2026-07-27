//! **The old-vs-new ANN build curve, side by side — the honest before/after for the v0.3 build change.**
//!
//! The v0.3 perf commit (`cc2718c`) took HNSW construction *off the per-operation store*: the pre-v0.3
//! `build_ann_index` inserted each vector through the tree/bincode `NodeStore` (reading every one of a
//! node's `M` neighbours back through a bincode decode to re-link them, with a per-call `HashSet` visited
//! set and cosine distance), so the graph was rebuilt against durable storage as it grew. The v0.3 build
//! scans the vectors once, builds the whole graph **in RAM** (unit vectors, a bare-dot distance, an
//! epoch-tagged visited set), and persists it in **one sorted pass**. Same graph, same recall floor; the
//! change is *where* construction happens.
//!
//! This test builds the index live on the current engine and prints its per-insert cost next to the
//! **measured** pre-v0.3 cost, so a single run shows both curves on one axis.
//!
//! # The pre-v0.3 numbers are measured, not asserted — and reproducible
//!
//! The old build path no longer exists on `main` (that is the point), so its column is a recorded
//! constant, not a live re-run. It was measured with *this same harness* checked out at the pre-perf
//! parent commit `9126c72` (in-memory Loom, clustered DIM=64, release):
//!
//! ```text
//!        N     old µs/insert     new µs/insert (live)    speedup
//!      500          5502              ~100                 ~55×
//!     2000          7559              ~170                 ~44×
//!     8000         26140              ~310                 ~85×
//! ```
//!
//! To reproduce the old column:
//! `git worktree add -d /tmp/old 9126c72 && cp <this file> /tmp/old/crates/loom-branch/tests/ && \
//!  (cd /tmp/old && HNSW_TIMING_SIZES=500,2000,8000 cargo test -p loom-branch --release \
//!  --test build_timing -- --ignored --nocapture)`  (8000 takes ~3.5 min on the old path — that climb is
//! the whole story).
//!
//! # What the two curves say
//!
//! The **old** per-insert cost *climbs* with N (5502 → 7559 → 26140 µs) — construction-on-the-per-op-store
//! scatters `M` random leaf reads/writes per insert and that scatter grows with the tree. The **new**
//! per-insert cost stays **flat** (~100–340 µs across 500 → 32000, matching the ~190 µs/insert the
//! RAM-only build holds to 1M in `loom-core/tests/hnsw_build_scaling`). Flat-vs-climbing is exactly
//! "construction came off the per-op store", made visible. The end-to-end build (scan + RAM build + one
//! bulk commit) shows **no** store-side superlinearity through 32k — the single bulk commit is not the
//! per-commit ref rewrite that Phase 2 addresses.
//!
//! `HNSW_TIMING_SIZES=500,2000,8000,16000,32000 cargo test -p loom-branch --release --test build_timing \
//!  -- --ignored --nocapture`

use std::time::Instant;

use loom_branch::Loom;
use loom_core::{
    ActorId, BranchId, Embedding, IndexHint, Observation, ObservationId, Record, SessionId,
    SourceRef, TenantId, Timestamp, TrustClass, WriteEnvelope,
};

const NOW: u64 = 1_700_000_000_000;
const DIM: usize = 64;

/// Pre-v0.3 build cost, µs/insert, measured at commit `9126c72` with this harness (in-memory, clustered,
/// DIM=64, release). Cited so a single run shows both curves; reproducible via the worktree recipe above.
const OLD_US_PER_INSERT: &[(usize, f64)] = &[(500, 5501.9), (2000, 7559.2), (8000, 26140.4)];

/// A tripwire: if the *new* build ever regresses back toward per-op-store construction, its per-insert
/// cost climbs into the thousands (the old path hit 26000 µs at 8k). This ceiling is far above the
/// measured ~100–340 µs band and far below the old cost, so it fires on a real regression, not on noise.
const NEW_US_PER_INSERT_CEILING: f64 = 2000.0;

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

/// Clustered vectors: `n/500` hubs, each point a hub plus small noise — the honest stand-in for real
/// embeddings (matches `loom-core/tests/hnsw_build_scaling`).
fn clustered(n: usize, dim: usize, seed: u64) -> Vec<Embedding> {
    let mut rng = Rng(seed);
    let n_centers = (n / 500).clamp(16, 4096);
    let centers: Vec<Vec<f32>> = (0..n_centers)
        .map(|_| (0..dim).map(|_| rng.unit() * 2.0 - 1.0).collect())
        .collect();
    (0..n)
        .map(|i| {
            let c = &centers[i % n_centers];
            Embedding::new(
                c.iter()
                    .map(|&x| x + (rng.unit() * 2.0 - 1.0) * 0.25)
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

fn env(session: &SessionId, branch: &BranchId) -> WriteEnvelope {
    WriteEnvelope::new(
        ActorId::new("bench"),
        session.clone(),
        branch.clone(),
        "seed",
    )
}
fn obs(i: usize) -> Record {
    Record::Observation(Box::new(Observation {
        id: ObservationId::of(format!("s{i}").as_bytes()),
        source: SourceRef::new("web", format!("s{i}")),
        trust: TrustClass::VerifiedSystem,
        observed_at: None,
        ingested_at: Timestamp::from_ms(NOW),
        payload: b"x".to_vec(),
    }))
}

#[test]
#[ignore = "build-timing artifact (old-vs-new curve); run with --release --ignored --nocapture"]
fn old_vs_new_build_curve() {
    let sizes: Vec<usize> = std::env::var("HNSW_TIMING_SIZES")
        .unwrap_or_else(|_| "500,2000,8000".into())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    println!("\n=== HNSW build: pre-v0.3 (per-op store) vs v0.3 (RAM + bulk persist) ===");
    println!("    in-memory, clustered, DIM={DIM}, release. old = measured @ 9126c72 (cited).\n");
    println!(
        "{:>10}  {:>15}  {:>15}  {:>10}",
        "N", "old us/insert", "new us/insert", "speedup"
    );
    println!("{}", "-".repeat(56));

    for &n in &sizes {
        let db = Loom::in_memory(TenantId::new("bench")).unwrap();
        let (session, token) = db.open_session().unwrap();
        let branch = session.branch.clone();

        let vecs = clustered(n, DIM, 0xB0B);
        for (i, v) in vecs.iter().enumerate() {
            db.write_indexed(
                &token,
                &branch,
                format!("obs/{i:08}").into_bytes(),
                obs(i),
                IndexHint::text("f").with_embedding(v.clone()),
                &env(&session.id, &branch),
            )
            .unwrap();
        }

        let t = Instant::now();
        let count = db.build_ann_index(&token, &branch).unwrap();
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(count, n, "indexed count mismatch");
        let new_us = ms * 1000.0 / n as f64;

        let old = OLD_US_PER_INSERT
            .iter()
            .find(|(on, _)| *on == n)
            .map(|(_, us)| *us);
        let (old_col, speedup_col) = match old {
            Some(o) => (format!("{o:.0}"), format!("{:.0}x", o / new_us)),
            None => ("-".into(), "-".into()),
        };
        println!("{n:>10}  {old_col:>15}  {new_us:>15.0}  {speedup_col:>10}");

        assert!(
            new_us < NEW_US_PER_INSERT_CEILING,
            "new build cost {new_us:.0} us/insert at N={n} exceeded the {NEW_US_PER_INSERT_CEILING} us \
             ceiling — construction may have regressed onto the per-op store"
        );
    }

    println!(
        "\n  old climbs superlinearly (per-op-store scatter grows with N); new stays flat (~100-340 us,\n  \
         matching the RAM build's ~190 us/insert to 1M). Flat-vs-climbing is the v0.3 change made visible."
    );
}
