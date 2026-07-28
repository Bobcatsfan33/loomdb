//! **The refs before/after: how a single commit's ref-write scales with branch count.**
//!
//! The known-limit: `FileRefStore::save` bincode-serializes the **entire** `Refs` — every branch, every
//! tag, and the whole commit DAG — and atomic-writes it (temp → fsync → rename → fsync dir) on **every**
//! commit (`set_head` → `persist` → `save`). So each commit costs O(branches + commits), not O(1). This
//! bench is the *before* number Phase 2 improves on, published on the same axes as the *after* (guardrail
//! 5): the deliverable is the curve, not an assertion that the curve is bad.
//!
//! It measures, at 10 / 1 000 / 100 000 branches (a linear commit DAG of the same size — commits
//! accumulate too):
//! - **save** — one `FileRefStore::save`, the exact per-commit ref cost (fsync'd, the real durability
//!   cost). The substrate manifest commit on top is O(1), a constant offset this isolates away.
//! - **load** — one `FileRefStore::load`, the cost paid once at startup/recovery (feeds Phase 2's
//!   "recovery time at 100k branches" measurement).
//! - **bytes** — the encoded size, the thing being rewritten every commit.
//!
//! `cargo bench -p loom-branch --bench refs_scaling`  (100k writes ~11 MB × the sample count — a few
//! seconds; that cost, paid once per commit, is the whole point).

use std::path::PathBuf;
use std::time::Instant;

use loom_branch::{FileRefStore, RefStore, Refs};
use loom_core::CommitId;

/// A distinct 32-byte commit id derived from `i` (SplitMix64-filled, no RNG state needed).
fn cid(i: u64) -> CommitId {
    let mut bytes = [0u8; 32];
    let mut z = i.wrapping_add(0x9E37_79B9_7F4A_7C15);
    for chunk in bytes.chunks_mut(8) {
        z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut v = z;
        v = (v ^ (v >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        v = (v ^ (v >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        v ^= v >> 31;
        chunk.copy_from_slice(&v.to_le_bytes()[..chunk.len()]);
    }
    CommitId::from_bytes(bytes)
}

/// A `Refs` with `n` branches and an `n`-commit linear DAG — the shape after `n` commits across `n`
/// branches, which is what a single further commit must rewrite in full.
fn refs_with(n: usize) -> Refs {
    let mut refs = Refs::rooted("main", cid(0));
    for i in 1..n as u64 {
        refs.branches.insert(format!("branch-{i:08}"), cid(i));
        // Linear history: commit i's parent is commit i-1. A real DAG is a mix, but the size — one
        // entry per commit — is what the full-file rewrite pays, and that is identical.
        refs.commits.insert(cid(i), vec![cid(i - 1)]);
    }
    refs
}

/// Median of per-op millisecond timings.
fn median(mut ms: Vec<f64>) -> f64 {
    ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    ms[ms.len() / 2]
}

fn bench_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("loom-refs-scaling-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create bench dir");
    dir
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sizes: Vec<usize> = std::env::var("REFS_SIZES")
        .unwrap_or_else(|_| "10,1000,100000".into())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    let samples: usize = std::env::var("REFS_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(21);

    println!("\n=== Current refs: per-commit save + recovery load vs branch count (fsync'd, on-disk) ===");
    println!("    the full-file rewrite every commit pays. {samples} samples, median.\n");
    println!(
        "{:>10}  {:>12}  {:>14}  {:>14}",
        "branches", "encoded", "save med (ms)", "load med (ms)"
    );
    println!("{}", "-".repeat(56));

    for &n in &sizes {
        let refs = refs_with(n);
        let bytes = refs.encode()?.len();

        let dir = bench_dir(&format!("n{n}"));
        let store = FileRefStore::open(&dir)?;

        // Warm one write so the file exists (atomic_write rename target), then sample.
        store.save(&refs)?;
        let mut save_ms = Vec::with_capacity(samples);
        for _ in 0..samples {
            let t = Instant::now();
            store.save(&refs)?;
            save_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        let mut load_ms = Vec::with_capacity(samples);
        for _ in 0..samples {
            let t = Instant::now();
            let got = store.load()?.expect("refs present");
            load_ms.push(t.elapsed().as_secs_f64() * 1000.0);
            debug_assert_eq!(got.branches.len(), refs.branches.len());
        }
        let _ = std::fs::remove_dir_all(&dir);

        println!(
            "{n:>10}  {:>12}  {:>14.3}  {:>14.3}",
            format!("{:.1} KB", bytes as f64 / 1024.0),
            median(save_ms),
            median(load_ms),
        );
    }

    println!("\nReading the result:");
    println!("  save grows with branches+commits — every commit rewrites the whole file, fsync'd. That is");
    println!("  the O(branches) per-commit tax Phase 2 removes; the 'after' bench prints on these same axes.");
    Ok(())
}
