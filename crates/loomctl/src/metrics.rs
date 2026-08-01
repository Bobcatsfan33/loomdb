//! Operational signals for backup, verification, and retention, as a Prometheus textfile.
//!
//! # Why a file and not an exporter
//!
//! These signals come from **jobs**, not from a process that is up long enough to be scraped. A
//! backup runs for a minute and exits; nothing can poll it. So each command writes the numbers it
//! just produced to a file the host's collector already reads (a node-exporter textfile directory, a
//! sidecar, whatever the deployment uses). `loomctl` opens no socket and links no exporter — that is
//! the same amputation the air-gap build makes everywhere else.
//!
//! # Why there is no tenant label
//!
//! For the same reason `loomd` forbids one on its RPC instruments: a tenant identifier inside a
//! metric is tenant data leaving the tenant boundary through the monitoring pipeline, and it is
//! unbounded cardinality besides. One job serves one tenant and writes one file, so the *path*
//! carries the tenant and the collector attaches workload labels from the pod or unit it scraped.
//! Nothing here emits a label at all.
//!
//! # The honest limit
//!
//! A metric is an operational record, not an authenticity claim. `loomdb_backup_last_success…`
//! saying "yesterday" does not prove a restorable backup exists; only
//! `loomctl verify-backup-signed` against the trust root does. The signals exist so a *missing* or
//! *stale* backup is loud, not so a present number can be trusted in place of a signature.

use std::io::Write;
use std::path::Path;

/// The instant a backup last completed successfully, in Unix seconds.
pub const LAST_SUCCESS: &str = "loomdb_backup_last_success_timestamp_seconds";
/// The instant a backup was last independently verified, in Unix seconds.
pub const LAST_VERIFIED: &str = "loomdb_backup_last_verified_timestamp_seconds";
/// The recovery point that verification proved: when the *verified backup* was taken.
pub const RECOVERY_POINT: &str = "loomdb_backup_last_verified_recovery_point_seconds";
/// How long the command took.
pub const DURATION: &str = "loomdb_backup_duration_seconds";
/// Total bytes in the backup manifest's allow-list.
pub const BYTES: &str = "loomdb_backup_bytes";
/// Number of files in the backup manifest's allow-list.
pub const FILES: &str = "loomdb_backup_files";
/// 1 when this run failed, 0 when it succeeded. A job that dies still writes this.
pub const FAILURES: &str = "loomdb_backup_failures_total";
/// Objects an integrity scrub found corrupt, missing, or carrying a bad manifest.
pub const SCRUB_DAMAGE: &str = "loomdb_backup_scrub_damaged_objects";
/// Backup copies retention kept.
pub const RETAINED: &str = "loomdb_backup_retained_copies";
/// Backup copies retention removed on this run.
pub const PRUNED: &str = "loomdb_backup_pruned_total";
/// Backup copies retention kept **because a legal hold names them**.
pub const LEGAL_HOLD: &str = "loomdb_backup_legal_hold_retained";

/// Every signal this binary can emit, with its Prometheus type and help text.
///
/// Deployment configuration is validated against this list — `scripts/verify_host_profile.py`
/// refuses a profile that wires an alert to a signal `loomctl` never writes, the same discipline
/// `observability.instruments` applies to `loomd`.
pub const ALL: &[(&str, &str, &str)] = &[
    (
        LAST_SUCCESS,
        "gauge",
        "Unix time of the last successful signed backup.",
    ),
    (
        LAST_VERIFIED,
        "gauge",
        "Unix time of the last independent signature verification.",
    ),
    (
        RECOVERY_POINT,
        "gauge",
        "Unix time the last independently verified backup was taken.",
    ),
    (DURATION, "gauge", "Seconds the last run took."),
    (BYTES, "gauge", "Bytes in the last backup manifest."),
    (FILES, "gauge", "Files in the last backup manifest."),
    (
        FAILURES,
        "gauge",
        "1 if the last run failed, 0 if it succeeded.",
    ),
    (
        SCRUB_DAMAGE,
        "gauge",
        "Objects the last integrity scrub found damaged.",
    ),
    (RETAINED, "gauge", "Backup copies retention kept."),
    (PRUNED, "gauge", "Backup copies retention removed."),
    (
        LEGAL_HOLD,
        "gauge",
        "Backup copies retained because a legal hold names them.",
    ),
];

fn describe(name: &str) -> Result<(&'static str, &'static str), String> {
    ALL.iter()
        .find(|(candidate, _, _)| *candidate == name)
        .map(|(_, kind, help)| (*kind, *help))
        .ok_or_else(|| format!("{name} is not a signal loomctl emits"))
}

/// A set of signals from one run, rendered in declaration order.
#[derive(Debug, Default)]
pub struct Signals {
    values: Vec<(&'static str, f64)>,
}

impl Signals {
    /// Start an empty set.
    pub fn new() -> Self {
        Signals::default()
    }

    /// Record one signal. A name is a compile-time constant from this module.
    pub fn set(&mut self, name: &'static str, value: f64) -> &mut Self {
        self.values.retain(|(existing, _)| *existing != name);
        self.values.push((name, value));
        self
    }

    /// Render the Prometheus text exposition body.
    pub fn render(&self) -> Result<String, String> {
        let mut out = String::new();
        for (name, value) in &self.values {
            let (kind, help) = describe(name)?;
            out.push_str(&format!("# HELP {name} {help}\n"));
            out.push_str(&format!("# TYPE {name} {kind}\n"));
            // Integral values render without a decimal point; Prometheus accepts both, and whole
            // seconds and byte counts read better without a trailing `.0`.
            if value.fract() == 0.0 && value.is_finite() {
                out.push_str(&format!("{name} {}\n", *value as i64));
            } else {
                out.push_str(&format!("{name} {value}\n"));
            }
        }
        Ok(out)
    }

    /// **Write the signals atomically.**
    ///
    /// A collector reads this file on its own schedule and must never see a half-written one, so the
    /// body lands in a sibling `.partial` and is published with a single rename — the same publish
    /// discipline the backup itself uses.
    pub fn write(&self, path: &Path) -> Result<(), String> {
        let body = self.render()?;
        let partial = path.with_extension("partial");
        let mut file = std::fs::File::create(&partial)
            .map_err(|error| format!("cannot create {}: {error}", partial.display()))?;
        file.write_all(body.as_bytes())
            .map_err(|error| format!("cannot write {}: {error}", partial.display()))?;
        file.sync_all()
            .map_err(|error| format!("cannot sync {}: {error}", partial.display()))?;
        drop(file);
        std::fs::rename(&partial, path).map_err(|error| {
            format!(
                "cannot publish {} to {}: {error}",
                partial.display(),
                path.display()
            )
        })
    }
}

/// Unix seconds now, saturating at the epoch on a clock set before 1970.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_help_type_and_value_for_a_known_signal() {
        let mut signals = Signals::new();
        signals.set(FAILURES, 0.0).set(BYTES, 4096.0);
        let body = signals.render().expect("known signals render");
        assert!(body.contains("# TYPE loomdb_backup_failures_total gauge"));
        assert!(body.contains("\nloomdb_backup_failures_total 0\n"));
        assert!(body.contains("\nloomdb_backup_bytes 4096\n"));
    }

    #[test]
    fn setting_a_signal_twice_keeps_the_last_value_once() {
        let mut signals = Signals::new();
        signals.set(FAILURES, 1.0).set(FAILURES, 0.0);
        let body = signals.render().expect("renders");
        // Match whole sample lines: the HELP text for this signal legitimately begins with "1".
        let samples: Vec<&str> = body
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter(|line| line.starts_with(FAILURES))
            .collect();
        assert_eq!(samples, vec!["loomdb_backup_failures_total 0"]);
    }

    #[test]
    fn every_declared_signal_has_a_type_and_help() {
        for (name, kind, help) in ALL {
            assert!(name.starts_with("loomdb_backup_"), "{name}");
            assert!(matches!(*kind, "gauge" | "counter"), "{name}");
            assert!(!help.is_empty(), "{name}");
        }
    }
}
