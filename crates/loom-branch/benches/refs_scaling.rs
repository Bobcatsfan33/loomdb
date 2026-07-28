//! **The refs before/after: how a single commit's ref-write scales with branch count.**
//!
//! *Before* (pre-Phase-2, recorded in `docs/refs-design.md` and commit `f4ff820`): every commit
//! serialized the **entire** `Refs` and atomic-wrote it — O(branches + commits), 41 ms and a 12.4 MB
//! rewrite at 100k branches.
//!
//! *After* (this bench, the log-structured store): a commit is **one appended [`RefEdit`] frame**,
//! `FileRefStore::apply` — O(1), independent of branch count. Compaction (`save`, the full snapshot) is
//! still O(branches), but it is amortized: it runs only when the log outgrows the snapshot, not per
//! commit. Measured at 10 / 1 000 / 100 000 branches, fsync'd, on-disk, median:
//!
//! - **apply** — one per-commit `RefEdit` append. THE number: this is what a commit now pays, and it must
//!   stay flat as branches grow (vs the old `save` climbing to 41 ms).
//! - **save** — one full-snapshot write (compaction). Still O(branches), shown for honesty — it is the
//!   amortized cost, not the per-commit cost.
//! - **load** — one `load` (snapshot + replayed log): the recovery/startup read at this branch count
//!   (acceptance bar (e), "recovery time at 100k branches").
//!
//! `cargo bench -p loom-branch --bench refs_scaling`

use std::path::PathBuf;
use std::time::Instant;

use loom_branch::{FileRefStore, RefEdit, RefStore, Refs};
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
/// branches, seeded as the snapshot so `apply`/`save`/`load` are measured at that scale.
fn refs_with(n: usize) -> Refs {
    let mut refs = Refs::rooted("main", cid(0));
    for i in 1..n as u64 {
        refs.branches.insert(format!("branch-{i:08}"), cid(i));
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

    println!("\n=== Log-structured refs (AFTER): per-commit apply vs compaction save vs recovery load ===");
    println!("    fsync'd, on-disk, {samples} samples, median. before: save was 4.5/4.4/41.0 ms @ 10/1k/100k.\n");
    println!(
        "{:>10}  {:>12}  {:>15}  {:>15}  {:>14}",
        "branches", "snapshot", "apply med (ms)", "save med (ms)", "load med (ms)"
    );
    println!("{}", "-".repeat(74));

    for &n in &sizes {
        let refs = refs_with(n);
        let bytes = refs.encode()?.len();

        let dir = bench_dir(&format!("n{n}"));
        let store = FileRefStore::open(&dir)?;
        store.save(&refs)?; // seed the snapshot at this scale (also the first compaction baseline)

        // apply: the per-commit cost — one SetHead append. With an N-branch snapshot the compaction floor
        // is well above a handful of small frames, so these samples never trigger a compaction; this is
        // the pure per-commit append + fsync, which must stay flat as N grows.
        let mut apply_ms = Vec::with_capacity(samples);
        for s in 0..samples {
            let edit = RefEdit::SetHead {
                branch: "main".into(),
                to: cid(1_000_000 + s as u64),
            };
            let t = Instant::now();
            store.apply(std::slice::from_ref(&edit))?;
            apply_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        }

        // save: the compaction cost (full snapshot) — still O(branches), shown for honesty.
        let mut save_ms = Vec::with_capacity(samples);
        for _ in 0..samples {
            let t = Instant::now();
            store.save(&refs)?;
            save_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        }

        // load: recovery read (snapshot + replay).
        let mut load_ms = Vec::with_capacity(samples);
        for _ in 0..samples {
            let t = Instant::now();
            let got = store.load()?.expect("refs present");
            load_ms.push(t.elapsed().as_secs_f64() * 1000.0);
            debug_assert_eq!(got.branches.len(), refs.branches.len());
        }
        let _ = std::fs::remove_dir_all(&dir);

        println!(
            "{n:>10}  {:>12}  {:>15.3}  {:>15.3}  {:>14.3}",
            format!("{:.1} KB", bytes as f64 / 1024.0),
            median(apply_ms),
            median(save_ms),
            median(load_ms),
        );
    }

    println!("\nReading the result:");
    println!("  apply is the per-commit cost now — it must stay ~flat as branches grow (the old save climbed");
    println!("  to 41 ms at 100k). save is compaction, amortized (runs when the log outgrows the snapshot,");
    println!(
        "  not per commit). load is the recovery read at that branch count (acceptance bar e)."
    );
    Ok(())
}
