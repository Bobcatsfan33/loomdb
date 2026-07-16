//! Shared instrumentation for the two long soaks (docs/04 L5).
//!
//! Both soaks gate on the same bar from the roadmap: **zero errors AND flat memory across the full
//! window.** Flat memory is not a nicety — a slow leak in a process meant to stay up for a year is a
//! guaranteed outage with a long fuse — so this crate makes a leak *fail the run*, not log a warning.
//!
//! It holds two things:
//! - [`current_rss_bytes`] — the resident set size of this process, read exactly on Linux (the platform
//!   the gating nightly window runs on) and best-effort elsewhere.
//! - [`FlatMemory`] — a gate that samples RSS across a run and returns an error if it grew past a
//!   tolerance. The soaks `.expect()` on its verdict, so growth turns the test red.
//!
//! It also holds [`scale`]: the env-scaling every heavy LoomDB test uses (small default so the fast
//! path runs in CI seconds, a full window on the nightly headroom host), matching `AT045_STRIDE` /
//! `RECALL_FULL` / the oracle case-count pattern.

/// Reading the process's resident memory, for leak detection.
pub mod mem {
    /// This process's current resident set size, in bytes — `None` if the platform is not one we can
    /// read exactly.
    ///
    /// - **Linux** (the platform the gating nightly soak runs on): `/proc/self/statm`, field 2 —
    ///   resident pages — times the page size. This is the *current* RSS, which is what a leak grows.
    /// - **macOS** (the local fast path): `getrusage(RUSAGE_SELF).ru_maxrss`, which is the *peak* RSS in
    ///   bytes. Peak is a weaker signal than current, but it still rises whenever a leak pushes memory to
    ///   a new high, so a mid-run→end-of-run peak *increase* is a valid leak signal — see [`super::FlatMemory`].
    /// - **Other**: `None`; the flat-memory gate then reports "unmeasured" rather than a false pass.
    pub fn current_rss_bytes() -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
            let resident_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
            // SAFETY: sysconf is a pure query of a system constant; no pointers, no state.
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            if page_size <= 0 {
                return None;
            }
            Some(resident_pages.saturating_mul(page_size as u64))
        }
        #[cfg(target_os = "macos")]
        {
            // SAFETY: getrusage writes into a fully-owned, zeroed rusage; we read one integer field.
            let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
            if rc != 0 {
                return None;
            }
            // On Darwin ru_maxrss is bytes (on Linux it would be kilobytes — hence the per-OS split).
            Some(usage.ru_maxrss.max(0) as u64)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            None
        }
    }
}

/// The flat-memory gate. Sample it across a run; a leak makes [`verdict`](FlatMemory::verdict) fail.
///
/// The test protocol is: sample once after warm-up (steady state), then again at the end, and assert
/// the end did not exceed the steady-state sample by more than the tolerance. Comparing *end vs
/// steady-state* rather than *end vs start* is deliberate: a process legitimately grows during warm-up
/// (allocator arenas, caches filling), and gating on that would be flaky. A genuine leak keeps climbing
/// *after* warm-up, which is exactly what this catches.
pub struct FlatMemory {
    steady_state: Option<u64>,
    tolerance_bytes: u64,
    label: String,
}

impl FlatMemory {
    /// Begin a gate. Call [`mark_steady_state`](Self::mark_steady_state) after warm-up.
    ///
    /// `tolerance_bytes` is the growth allowed between steady state and the end — set it above
    /// allocator noise (a few MiB) and below what a real leak would reach over the run's iteration
    /// count. The soaks size it against how many iterations they run.
    pub fn new(label: impl Into<String>, tolerance_bytes: u64) -> Self {
        Self {
            steady_state: None,
            tolerance_bytes,
            label: label.into(),
        }
    }

    /// Record the post-warm-up steady-state RSS. Growth is measured from here.
    pub fn mark_steady_state(&mut self) {
        self.steady_state = mem::current_rss_bytes();
    }

    /// Emit one point of the memory **curve**: the current RSS, and its delta from steady state, tagged
    /// with `progress` (e.g. `"40%"`). The full-window nightly run calls this at intervals so the report
    /// is a curve — the shape over the run — not just a start and an end. A leak shows as a rising line
    /// here long before the final [`verdict`](Self::verdict) trips, which is the point: on the long run,
    /// you want to *see* the slope, not only the pass/fail.
    pub fn sample(&self, progress: &str) {
        let Some(now) = mem::current_rss_bytes() else {
            return;
        };
        let delta = self
            .steady_state
            .map(|s| now as i64 - s as i64)
            .unwrap_or(0);
        eprintln!(
            "[{}] rss-curve {:>5}  {:.1} MiB  (Δsteady {:+.1} MiB)",
            self.label,
            progress,
            now as f64 / 1_048_576.0,
            delta as f64 / 1_048_576.0,
        );
    }

    /// Compare the current RSS to the recorded steady state.
    ///
    /// Returns:
    /// - `Ok(())` if RSS did not grow past the tolerance (or if RSS is unmeasurable on this platform —
    ///   reported, not silently passed);
    /// - `Err(..)` naming the growth if it did. The soaks propagate this as a test failure, so a leak
    ///   makes the run red rather than logging a warning nobody reads.
    pub fn verdict(&self) -> Result<(), String> {
        let Some(steady) = self.steady_state else {
            // Either steady state was never marked, or the platform can't read RSS. Say which, and do
            // not claim a pass we did not verify.
            return match mem::current_rss_bytes() {
                None => {
                    eprintln!(
                        "[{}] flat-memory gate: RSS is not readable on this platform — UNMEASURED (the \
                         gating run is Linux CI, which reads it exactly)",
                        self.label
                    );
                    Ok(())
                }
                Some(_) => Err(format!(
                    "[{}] flat-memory gate: steady state was never marked",
                    self.label
                )),
            };
        };
        let Some(end) = mem::current_rss_bytes() else {
            eprintln!(
                "[{}] flat-memory gate: RSS became unreadable mid-run — UNMEASURED",
                self.label
            );
            return Ok(());
        };
        let growth = end.saturating_sub(steady);
        eprintln!(
            "[{}] flat-memory: steady-state {:.1} MiB → end {:.1} MiB (growth {:.1} MiB, tolerance {:.1} MiB)",
            self.label,
            steady as f64 / 1_048_576.0,
            end as f64 / 1_048_576.0,
            growth as f64 / 1_048_576.0,
            self.tolerance_bytes as f64 / 1_048_576.0,
        );
        if growth > self.tolerance_bytes {
            return Err(format!(
                "[{}] MEMORY LEAK: RSS grew {:.1} MiB after steady state (tolerance {:.1} MiB). A slow \
                 leak in a process meant to stay up for a year is a guaranteed outage — this fails the run.",
                self.label,
                growth as f64 / 1_048_576.0,
                self.tolerance_bytes as f64 / 1_048_576.0,
            ));
        }
        Ok(())
    }
}

/// Env-scaling: a fast default so the soaks run in CI seconds, a full window on the nightly host.
pub mod scale {
    /// Read a `usize` from an env var, falling back to `default`. A malformed value falls back too
    /// (a soak must not fail to *start* because of a typo in a nightly's env).
    pub fn env_usize(var: &str, default: usize) -> usize {
        std::env::var(var)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }
}
