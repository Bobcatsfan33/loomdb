//! **AT-011 — branch creation is cheap, and its cost does not depend on how much is in the database.**
//!
//! # Why this is a benchmark and not a test, and why it was held
//!
//! The claim is *"cost is independent of baseline size"*. One measurement against one database cannot
//! demonstrate independence of anything — it can only demonstrate that one number was small once. So
//! this runs the same operation against baselines that differ by four orders of magnitude and reports
//! the distribution at each. If the numbers are flat across the sweep, the claim is supported. If they
//! climb with the baseline, the claim is false and we say so.
//!
//! It was deliberately held until persistence landed, because branching now **writes a durable ref** —
//! so any figure taken before that would have been a figure for a different operation. It changed,
//! exactly as predicted.
//!
//! # Reproducing it
//!
//! ```text
//! cargo bench -p loom-branch --bench branching
//! LOOM_BENCH_SIZES=1000,1000000,10000000 cargo bench -p loom-branch --bench branching
//! ```
//!
//! p50/p95/p99 over 200 branch operations per baseline, against an **on-disk** database (a tmpdir), so
//! the ref write is real and the fsync is real. Numbers taken on a machine that is not doing anything
//! else. The absolute figures will differ on your hardware; the **shape across the sweep** is the
//! claim, and it is the part that should reproduce.

use loom_branch::Loom;
use loom_core::{ActorId, Key, Record, SessionId, TenantId, Value, WriteEnvelope};
use std::time::Instant;

/// Branch operations timed per baseline. Enough for a p99 to mean something.
const SAMPLES: usize = 200;

/// Records inserted per commit while seeding. Seeding 10M records one commit at a time would measure
/// the commit path, not the branch path, and would take all day.
const SEED_BATCH: usize = 10_000;

fn seed_batch() -> usize {
    std::env::var("LOOM_SEED_BATCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(SEED_BATCH)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sizes: Vec<usize> = std::env::var("LOOM_BENCH_SIZES")
        .unwrap_or_else(|_| "1000,10000,100000,1000000".into())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    println!("AT-011 — branch creation vs. baseline size");
    println!("  {SAMPLES} branches per baseline, on-disk, durable refs");
    println!();
    println!(
        "{:>12}  {:>10}  {:>10}  {:>10}  {:>10}  {:>10}",
        "baseline", "seed", "p50", "p95", "p99", "on disk"
    );
    println!("{}", "─".repeat(72));

    for &size in &sizes {
        let dir = tempfile::tempdir()?;
        let db = Loom::open(dir.path(), TenantId::new("bench"))?;
        let (session, mut token) = db.open_session()?;

        let seed_start = Instant::now();
        let mut written = 0usize;
        while written < size {
            let batch: Vec<(Key, Record)> = (written..(written + seed_batch()).min(size))
                .map(|n| {
                    (
                        format!("key-{n:010}").into_bytes(),
                        Record::Value(Value::Counter(n as i64)),
                    )
                })
                .collect();
            written += batch.len();
            db.write_many(&token, &session.branch, batch, &envelope(&session.id))?;
        }
        let seed = seed_start.elapsed();

        // ── the measurement ──────────────────────────────────────────────
        let mut samples = Vec::with_capacity(SAMPLES);
        for i in 0..SAMPLES {
            let name = format!("b-{i}");
            let start = Instant::now();
            let (_branch, next) = db.branch(&token, &session.branch, &name)?;
            samples.push(start.elapsed().as_micros() as u64);
            token = next;
        }
        samples.sort_unstable();

        println!(
            "{:>12}  {:>10}  {:>10}  {:>10}  {:>10}  {:>10}",
            size,
            format!("{:.1}s", seed.as_secs_f64()),
            micros(pct(&samples, 50.0)),
            micros(pct(&samples, 95.0)),
            micros(pct(&samples, 99.0)),
            bytes(dir_size(dir.path())),
        );
    }

    println!();
    println!("The claim is that the columns are FLAT across the rows. If p95 climbs with the");
    println!("baseline, branching is copying something, and AT-011 is false.");
    println!();
    println!(
        "Known and not yet fixed: the refs file is rewritten in full on every commit, so this"
    );
    println!("is O(branches), not O(1). It does not show up against baseline SIZE — which is what");
    println!(
        "AT-011 actually claims — but it will show up on a tenant with a great many branches,"
    );
    println!("and it is why the p99 column drifts up within a single run as branches accumulate.");

    Ok(())
}

/// What the database actually costs on disk.
///
/// Worth reporting, because it is what stopped the 10M baseline from being measured: pages are
/// content-addressed and **stored at full page size**, and provenance writes four records for every
/// one the caller writes. A reader sizing a deployment needs this number, and it is not one they
/// would guess.
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

fn bytes(n: u64) -> String {
    const GB: u64 = 1 << 30;
    const MB: u64 = 1 << 20;
    if n >= GB {
        format!("{:.2}GB", n as f64 / GB as f64)
    } else {
        format!("{:.0}MB", n as f64 / MB as f64)
    }
}

fn pct(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn micros(us: u64) -> String {
    if us >= 1000 {
        format!("{:.2}ms", us as f64 / 1000.0)
    } else {
        format!("{us}µs")
    }
}

fn envelope(session: &SessionId) -> WriteEnvelope {
    WriteEnvelope::new(
        ActorId::new("bench"),
        session.clone(),
        loom_core::BranchId::new("main"),
        "seed the baseline",
    )
}
