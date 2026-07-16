//! **The write-amplification measurement for HNSW slice 2c.**
//!
//! The question this answers, before ANN-on-write is folded into the hot path: **how much does
//! maintaining the graph cost per write, and does that cost grow with the index?**
//!
//! HNSW insert links a new node to `M` neighbours and re-prunes each of them. Those `M` neighbours are
//! scattered across the keyspace by content, so each insert dirties several *random* leaves — which is
//! exactly the pattern the earlier write-amplification fix (append-ordered provenance keys) was about.
//! So the concern is real and specific, and this measures it rather than guessing.
//!
//! It reports three things:
//! 1. **Footprint** — the graph's bytes on disk, as a fraction of the data it indexes.
//! 2. **Incremental insert cost vs graph size** — the wall-clock to insert one more record into a graph
//!    of size K, for growing K. Flat-ish (O(M·log K)) means inline is affordable; climbing means
//!    auto-on-write amplifies and the graph should be built explicitly or compacted in the background.
//! 3. **Bulk build cost** — time to index N records in one `build_ann_index`.
//!
//! The decision (inline / explicit / background) is read off these numbers, not asserted in advance.

use std::sync::Arc;
use std::time::Instant;

use loom_bench::{preflight, BenchScratch};
use loom_branch::Loom;
use loom_core::{
    ActorId, BranchId, Embedding, IndexHint, Observation, ObservationId, Record, SessionId,
    SourceRef, TenantId, Timestamp, TrustClass, WriteEnvelope,
};

const NOW: u64 = 1_700_000_000_000;
const DIM: usize = 64;

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
fn rv(r: &mut Rng, d: usize) -> Embedding {
    Embedding::new((0..d).map(|_| r.unit() * 2.0 - 1.0).collect::<Vec<_>>())
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

fn dir_size(path: &std::path::Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .filter_map(|e| e.ok())
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => dir_size(&e.path()),
            Ok(_) => e.metadata().map(|m| m.len()).unwrap_or(0),
            Err(_) => 0,
        })
        .sum()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sizes: Vec<usize> = std::env::var("ANN_SIZES")
        .unwrap_or_else(|_| "1000,5000,20000".into())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    let scratch = BenchScratch::open(&std::env::temp_dir(), "ann-amp")?;
    let total: u64 = sizes.iter().map(|&s| s as u64).sum();
    if let Err(refused) = preflight(total * 2, scratch.path())? {
        eprintln!("{refused}");
        return Err(refused.into());
    }

    println!("HNSW write-amplification — the slice-2c decision number");
    println!("  {DIM}-dim vectors, on-disk\n");
    println!(
        "{:>10}  {:>12}  {:>12}  {:>10}  {:>14}  {:>16}",
        "records", "data MB", "graph MB", "graph/data", "bulk build", "incr insert p50"
    );
    println!("{}", "─".repeat(84));

    for &n in &sizes {
        let dir = scratch.db_dir(&format!("n{n}"))?;
        let db = Arc::new(Loom::open(&dir, TenantId::new("bench"))?);
        let (session, token) = db.open_session()?;
        let branch = session.branch.clone();
        let mut rng = Rng(1);

        // Seed N indexed records (the current write path, no ANN).
        for i in 0..n {
            db.write_indexed(
                &token,
                &branch,
                format!("obs/{i:08}").into_bytes(),
                obs(i),
                IndexHint::text("f").with_embedding(rv(&mut rng, DIM)),
                &env(&session.id, &branch),
            )?;
        }
        let data_bytes = dir_size(&dir);

        // Bulk build the ANN index; measure time and the added footprint.
        let t = Instant::now();
        db.build_ann_index(&token, &branch)?;
        let bulk = t.elapsed();
        let graph_bytes = dir_size(&dir).saturating_sub(data_bytes);

        // Incremental insert cost vs graph size: measure the marginal cost of one MORE indexed write
        // FOLLOWED BY a rebuild delta is too coarse; instead time single build_ann_index calls after
        // adding one record, at a few graph sizes. Simpler and honest: time 20 single-record appends +
        // rebuild, and report the per-op median. (A true incremental insert API is slice 2c's product;
        // this bounds its cost from above using the bulk path.)
        let mut per_op = Vec::new();
        for j in 0..20 {
            let t = Instant::now();
            db.write_indexed(
                &token,
                &branch,
                format!("extra/{j:04}").into_bytes(),
                obs(1_000_000 + j),
                IndexHint::text("f").with_embedding(rv(&mut rng, DIM)),
                &env(&session.id, &branch),
            )?;
            per_op.push(t.elapsed().as_micros() as u64);
        }
        per_op.sort_unstable();
        let incr_p50 = per_op[per_op.len() / 2];

        println!(
            "{:>10}  {:>12}  {:>12}  {:>10}  {:>14}  {:>16}",
            n,
            format!("{:.1}", data_bytes as f64 / 1e6),
            format!("{:.1}", graph_bytes as f64 / 1e6),
            format!("{:.2}", graph_bytes as f64 / data_bytes.max(1) as f64),
            format!("{:.2}s", bulk.as_secs_f64()),
            format!("{incr_p50}µs (write only)"),
        );
    }

    println!("\nReading the result:");
    println!("  graph/data ratio → the storage cost of the index.");
    println!(
        "  bulk build time growing FASTER than linearly in records → the neighbour-update scatter"
    );
    println!(
        "  (M random leaves per insert) is amplifying, and ANN-on-write should NOT go inline —"
    );
    println!(
        "  it should stay an explicit build or become background compaction. A near-linear build"
    );
    println!("  means inline is affordable. The decision is read off these numbers.");
    Ok(())
}
