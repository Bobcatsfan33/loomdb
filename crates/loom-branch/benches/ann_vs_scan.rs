//! **The retrieval-latency decision number: ANN search vs the exact full scan, across index sizes.**
//!
//! `ann.rs` says "the full scan remains available as an exact fallback; ANN is the accelerator." Guardrail
//! 5 says a decision like *which is the default retrieval path* must be **read off a measurement**, not
//! asserted. This is that measurement: on the same seeded branch, at growing index sizes, it times
//!
//! - **scan** — `Loom::search_scan`, exact top-k by scoring every indexed vector (O(indexed) per query);
//! - **ann**  — `Loom::search_ann`, the folded HNSW unioned with the write buffer (sub-linear per query).
//!
//! and reports per-query latency and the ratio, so the **crossover** (the N past which ANN wins, and by
//! how much) is visible. If ANN wins even at small N, "scan is the default" is the wrong default and the
//! docs change with the number (guardrail 6).
//!
//! In-memory on purpose, and that makes the result **conservative for ANN**: both paths read from the
//! same warm in-RAM tree, so the scan pays no disk cost. On real object/disk storage the scan's O(N) leaf
//! reads are far more punishing than ANN's handful of node reads, so any crossover measured here is a
//! *lower bound* on ANN's real-world advantage. Clustered (real-embedding-shaped) data, DIM=64.
//!
//! `ANN_VS_SCAN_SIZES=1000,10000,50000,100000 cargo bench -p loom-branch --bench ann_vs_scan`

use std::time::Instant;

use loom_branch::Loom;
use loom_core::{
    ActorId, BranchId, Embedding, IndexHint, Observation, ObservationId, Record, SessionId,
    SourceRef, TenantId, Timestamp, TrustClass, WriteEnvelope,
};

const NOW: u64 = 1_700_000_000_000;
const DIM: usize = 64;
const K: usize = 10;
const QUERIES: usize = 200;

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

/// `n/500` hubs, each point a hub plus small noise — the honest stand-in for real embeddings.
fn clustered(n: usize, dim: usize, seed: u64) -> (Vec<Embedding>, Vec<Vec<f32>>) {
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

fn query_from(centers: &[Vec<f32>], dim: usize, rng: &mut Rng) -> Embedding {
    let c = &centers[(rng.next() as usize) % centers.len()];
    Embedding::new(
        c.iter()
            .take(dim)
            .map(|&x| x + (rng.unit() * 2.0 - 1.0) * 0.25)
            .collect::<Vec<_>>(),
    )
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

/// Median and p95 of a set of per-query millisecond timings.
fn stats(mut ms: Vec<f64>) -> (f64, f64) {
    ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let med = ms[ms.len() / 2];
    let p95 = ms[(ms.len() * 95 / 100).min(ms.len() - 1)];
    (med, p95)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sizes: Vec<usize> = std::env::var("ANN_VS_SCAN_SIZES")
        .unwrap_or_else(|_| "1000,10000,50000".into())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    println!("\n=== Retrieval latency: exact full scan vs ANN (in-memory, DIM={DIM}, k={K}, clustered) ===");
    println!(
        "    per-query ms over {QUERIES} clustered queries. in-memory ⇒ conservative for ANN.\n"
    );
    println!(
        "{:>10}  {:>16}  {:>16}  {:>10}",
        "N", "scan med/p95", "ann med/p95", "speedup(med)"
    );
    println!("{}", "-".repeat(60));

    for &n in &sizes {
        let db = Loom::in_memory(TenantId::new("bench"))?;
        let (session, token) = db.open_session()?;
        let branch = session.branch.clone();

        let (vecs, centers) = clustered(n, DIM, 0xB0B);
        for (i, v) in vecs.iter().enumerate() {
            db.write_indexed(
                &token,
                &branch,
                format!("obs/{i:08}").into_bytes(),
                obs(i),
                IndexHint::text("f").with_embedding(v.clone()),
                &env(&session.id, &branch),
            )?;
        }
        db.build_ann_index(&token, &branch)?;

        // Pre-generate the query set so both paths answer the identical queries.
        let mut qrng = Rng(0xF00D);
        let queries: Vec<Embedding> = (0..QUERIES)
            .map(|_| query_from(&centers, DIM, &mut qrng))
            .collect();

        let mut scan_ms = Vec::with_capacity(QUERIES);
        let mut ann_ms = Vec::with_capacity(QUERIES);
        for q in &queries {
            let t = Instant::now();
            let s = db.search_scan(&token, &branch, q, K)?;
            scan_ms.push(t.elapsed().as_secs_f64() * 1000.0);

            let t = Instant::now();
            let a = db.search_ann(&token, &branch, q, K)?;
            ann_ms.push(t.elapsed().as_secs_f64() * 1000.0);

            // Sanity: both return k results on a populated index (recall is gated elsewhere).
            debug_assert_eq!(s.len(), K.min(n));
            debug_assert_eq!(a.len(), K.min(n));
        }

        let (scan_med, scan_p95) = stats(scan_ms);
        let (ann_med, ann_p95) = stats(ann_ms);
        println!(
            "{n:>10}  {:>16}  {:>16}  {:>10}",
            format!("{scan_med:.3}/{scan_p95:.3}"),
            format!("{ann_med:.3}/{ann_p95:.3}"),
            format!("{:.1}x", scan_med / ann_med.max(1e-9)),
        );
    }

    println!("\nReading the result:");
    println!(
        "  scan is O(indexed) per query — its latency grows linearly with N; ann is sub-linear —"
    );
    println!(
        "  its latency grows ~log N. The crossover N (where speedup>1) and its slope decide the"
    );
    println!("  default retrieval path. Because this is in-memory, on-disk/object-store the scan is worse");
    println!("  and the crossover moves LEFT (ANN wins sooner). Whatever it says, ann.rs states the decision.");
    Ok(())
}
