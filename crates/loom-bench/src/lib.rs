//! **The benchmark disk guard.**
//!
//! # Why this crate exists — an incident, not a nicety
//!
//! A benchmark run seeded databases into `tempfile::tempdir()` scratch directories. Two of those runs
//! were *killed* — a poller and an oversized attempt — and `tempfile`'s cleanup runs on `Drop`, which a
//! kill does not call. So each dead run **stranded hundreds of megabytes** that nothing ever reaped,
//! and a host that was already tight went to **zero bytes free**. Every process on it, this one
//! included, then failed on `ENOSPC`.
//!
//! That is darkly funny for a database whose pitch includes *clean backpressure under a full disk*. The
//! **engine** did the right thing — a 10M-record seed hit `StorageFull` and refused, which is exactly
//! the AT-045 behaviour. The **harness** did not: it had no pre-flight check and no crash-durable
//! cleanup. A benchmark that DoSes its own host has no business certifying anything.
//!
//! So this crate does the two things the harness was missing, and it is a *library* so that both can be
//! unit-tested without filling a disk to prove it:
//!
//! 1. **[`BenchScratch`]** — scratch lives under one **named** directory, reaped on startup (which
//!    catches whatever a previous *killed* run stranded) and on `Drop` (the normal path). A dead run
//!    can no longer strand data, because the *next* run deletes it before it begins.
//! 2. **[`preflight`]** — before seeding, check free space against the run's *measured* cost and refuse
//!    a run there is no room for, **naming the shortfall**. Fail fast at the harness, the same way the
//!    engine fails fast with `StorageFull`.

use std::io;
use std::path::{Path, PathBuf};

/// The measured on-disk cost of one seeded record, in bytes.
///
/// Not a guess. The AT-011 sweep measured 37 MB at 100 000 records and 370 MB at 1 000 000 — linear, at
/// ~370 bytes/record — because pages are content-addressed and stored at full page size and LoomDB
/// writes four records per record. This is the number `preflight` sizes a run against.
pub const MEASURED_BYTES_PER_RECORD: u64 = 370;

/// How much headroom to insist on beyond the run's own estimate.
///
/// The per-record figure is an average over a specific workload; a different one will differ, and a
/// disk that is *exactly* full is a disk one rounding error from `ENOSPC`. We refuse unless the run
/// fits with this much to spare. Over-refusing a benchmark is free; filling the host is not.
pub const SAFETY_HEADROOM_BYTES: u64 = 512 * 1024 * 1024;

/// Why a run was refused before it started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightError {
    /// The disk does not have room for the run, with headroom.
    InsufficientSpace {
        /// Records the run intends to seed.
        records: u64,
        /// What the run is estimated to need, including headroom.
        needed_bytes: u64,
        /// What is actually free.
        free_bytes: u64,
    },
}

impl std::fmt::Display for PreflightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreflightError::InsufficientSpace {
                records,
                needed_bytes,
                free_bytes,
            } => write!(
                f,
                "refusing to seed {records} records: this run needs about {needed} \
                 (at ~{MEASURED_BYTES_PER_RECORD} bytes/record plus {headroom} headroom) but only \
                 {free} is free — short by {short}. Free space or reduce LOOM_BENCH_SIZES; a benchmark \
                 must not fill the host it is measuring.",
                needed = human(*needed_bytes),
                headroom = human(SAFETY_HEADROOM_BYTES),
                free = human(*free_bytes),
                short = human(needed_bytes.saturating_sub(*free_bytes)),
            ),
        }
    }
}

impl std::error::Error for PreflightError {}

/// What a run of `records` records is estimated to cost on disk, including headroom.
pub fn estimated_bytes(records: u64) -> u64 {
    records
        .saturating_mul(MEASURED_BYTES_PER_RECORD)
        .saturating_add(SAFETY_HEADROOM_BYTES)
}

/// **The pure decision.** Refuse a run that does not fit, given the free bytes.
///
/// Pure and total, so it is tested without touching a disk: the whole point is to be *certain* the
/// harness refuses an oversized seed, and a test that had to fill a disk to prove it would be the very
/// thing this exists to prevent.
pub fn check(records: u64, free_bytes: u64) -> Result<(), PreflightError> {
    let needed = estimated_bytes(records);
    if needed > free_bytes {
        return Err(PreflightError::InsufficientSpace {
            records,
            needed_bytes: needed,
            free_bytes,
        });
    }
    Ok(())
}

/// **Pre-flight a run against the real free space at `path`.** Refuse if it will not fit.
pub fn preflight(records: u64, path: &Path) -> io::Result<Result<(), PreflightError>> {
    Ok(check(records, free_space_bytes(path)?))
}

/// Bytes free on the filesystem holding `path`.
#[cfg(unix)]
pub fn free_space_bytes(path: &Path) -> io::Result<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // SAFETY: `statvfs` reads into a struct we own and zero-initialise; `c_path` is a valid
    // NUL-terminated C string that outlives the call. We check the return code before reading the
    // struct, and touch only plain integer fields.
    let stat = unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) != 0 {
            return Err(io::Error::last_os_error());
        }
        stat
    };

    // Available to an unprivileged process (f_bavail), not merely unused (f_bfree) — the disk may
    // reserve blocks we cannot use, and counting them would let a run start that then hits ENOSPC.
    Ok((stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64))
}

/// A named scratch directory that reaps itself on startup **and** shutdown.
///
/// The startup reap is the one that matters: it deletes whatever a *previous, killed* run left behind,
/// which `Drop`-based cleanup by definition cannot. The `Drop` reap keeps the normal path tidy.
pub struct BenchScratch {
    root: PathBuf,
}

impl BenchScratch {
    /// Open (or re-open) the scratch root, deleting anything already there.
    ///
    /// `label` names a subdirectory so concurrent benches do not reap each other's live data.
    pub fn open(base: &Path, label: &str) -> io::Result<Self> {
        let root = base.join("loom-bench-scratch").join(label);
        // Reap whatever a prior run — including a *killed* one — stranded here. This is the crash-durable
        // half: cleanup does not depend on the previous process having run its destructors.
        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
        std::fs::create_dir_all(&root)?;
        Ok(BenchScratch { root })
    }

    /// A fresh, empty subdirectory inside the scratch root for one database.
    pub fn db_dir(&self, name: &str) -> io::Result<PathBuf> {
        let dir = self.root.join(name);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// The scratch root.
    pub fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for BenchScratch {
    fn drop(&mut self) {
        // Best-effort: a failure here must not panic a benchmark, and the *next* run's startup reap is
        // the real guarantee regardless.
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn human(bytes: u64) -> String {
    const GB: u64 = 1 << 30;
    const MB: u64 = 1 << 20;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else {
        format!("{:.0} MB", bytes as f64 / MB as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The harness refuses an oversized seed rather than filling the disk.**
    ///
    /// This is the test the incident demanded. A 10-million-record run needs ~3.7 GB; told there is
    /// 1 GB free, the guard must refuse *before* a single record is written.
    #[test]
    fn refuses_a_seed_that_would_not_fit() {
        let ten_million = 10_000_000;
        let one_gb_free = 1 << 30;

        let result = check(ten_million, one_gb_free);

        assert!(
            matches!(result, Err(PreflightError::InsufficientSpace { .. })),
            "the harness must refuse a run it has no room for; got {result:?}"
        );
    }

    /// A run that fits is allowed.
    #[test]
    fn allows_a_seed_that_fits_with_headroom() {
        // 100k records: ~37 MB of data plus 512 MB headroom, well under 2 GB free.
        assert!(check(100_000, 2 << 30).is_ok());
    }

    /// The refusal **names the shortfall** — a message an operator can act on, not just "no".
    #[test]
    fn the_refusal_states_the_shortfall() {
        let err = check(10_000_000, 1 << 30).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("10000000"),
            "must name the record count: {msg}"
        );
        assert!(
            msg.contains("short by"),
            "must state the shortfall so it is actionable: {msg}"
        );
    }

    /// The estimate covers the measured per-record cost. 1M records must be sized at **at least** the
    /// 370 MB that was actually observed, or the guard would wave through a run that then fills the disk.
    #[test]
    fn the_estimate_is_not_below_what_was_measured() {
        let one_million = 1_000_000;
        // 370 MB was the measured footprint at 1M records.
        let measured = 370u64 * 1024 * 1024;
        assert!(
            estimated_bytes(one_million) >= measured,
            "the estimate must not undercount the measured footprint, or the guard is theatre"
        );
    }

    /// **Startup reaps what a killed run stranded.** This is the half `Drop` cannot do.
    #[test]
    fn startup_reaps_a_stranded_run() {
        let base = std::env::temp_dir().join("loom-bench-selftest");
        let _ = std::fs::remove_dir_all(&base);

        // Simulate a *killed* previous run: scratch on disk, no destructor ever ran.
        {
            let scratch = BenchScratch::open(&base, "unit").unwrap();
            let db = scratch.db_dir("victim").unwrap();
            std::fs::write(db.join("stranded.page"), b"hundreds of MB, pretend").unwrap();
            std::mem::forget(scratch); // the kill: Drop never runs, the bytes stay on disk
        }
        let stranded = base.join("loom-bench-scratch").join("unit").join("victim");
        assert!(
            stranded.exists(),
            "precondition: the killed run left data behind"
        );

        // The next run opens the same label. Startup must reap the stranded data.
        {
            let scratch = BenchScratch::open(&base, "unit").unwrap();
            assert!(
                !stranded.exists(),
                "startup did not reap what the killed run stranded — a dead run can still fill the disk"
            );
            drop(scratch);
        }

        let _ = std::fs::remove_dir_all(&base);
    }
}
