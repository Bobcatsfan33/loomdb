//! What a recovery drill measured, in a form a machine and an auditor can both read.
//!
//! # Why measurements are first class, not a pass/fail
//!
//! A drill that reports "PASS — within RTO" throws away the only number anyone will want later. The
//! approved targets are RPO 24 h and RTO 4 h, chosen to describe the schedule actually deployed; if
//! the measured numbers come in far better, that evidence is what justifies tightening the targets
//! when a contract demands it. So the receipt records what was *measured*, states the target beside
//! it, and computes the headroom — and a reader can disagree with the verdict while still trusting
//! the numbers.
//!
//! # Why every receipt is labelled
//!
//! `topology` and `backend` are mandatory because a drill on a developer laptop against a
//! software-backed key proves something much narrower than the same drill on the target storage
//! stack with an HSM. A receipt that omitted them would be quotable as evidence for a claim it never
//! supported.

use serde::{Deserialize, Serialize};

/// Receipt format version.
pub const RECEIPT_SCHEMA_VERSION: u32 = 1;

/// The approved recovery point objective, in seconds (24 hours).
pub const RPO_TARGET_SECONDS: u64 = 24 * 3600;
/// The approved recovery time objective, in seconds (4 hours).
pub const RTO_TARGET_SECONDS: u64 = 4 * 3600;

/// Where the drill ran, and therefore what it is evidence *for*.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Topology {
    /// A local filesystem, with the point-in-time clone made by copying the store directory.
    ///
    /// This is what a developer machine can exercise honestly. It drives the real backup, custody,
    /// restore, and attested-reopen paths; it does **not** exercise a CSI driver, a storage array,
    /// a backup product, or an object-lock target.
    LocalFilesystemCopyClone,
}

impl Topology {
    /// The topology's stable wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Topology::LocalFilesystemCopyClone => "local-filesystem-copy-clone",
        }
    }

    /// What this topology does **not** cover. Recorded in the receipt so a reader cannot mistake it
    /// for coverage it never had.
    pub fn not_exercised(&self) -> &'static [&'static str] {
        match self {
            Topology::LocalFilesystemCopyClone => &[
                "CSI volume snapshots and clone provisioning",
                "storage-array or filesystem snapshot primitives",
                "third-party backup products and their agents",
                "immutable off-account object-lock targets",
                "customer-scale data volumes",
                "multi-node or cross-availability-zone recovery",
                "a true ENOSPC / full-filesystem injection (a file blocking the destination path \
                 stands in for it; filling a filesystem is not portably arrangeable here)",
            ],
        }
    }
}

/// One measured duration, with the target it is judged against.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Measured {
    /// What was measured, in seconds. The number, not a verdict.
    pub seconds: f64,
    /// The approved target, in seconds.
    pub target_seconds: u64,
    /// Whether the measurement is inside the target.
    pub within_target: bool,
    /// How much room is left, as a multiple of the measurement. `None` when the measurement is zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headroom_factor: Option<f64>,
    /// The measurement rendered for a human, without rounding in either direction.
    pub human: String,
}

impl Measured {
    /// Record a measurement against a target.
    pub fn new(seconds: f64, target_seconds: u64) -> Self {
        Measured {
            seconds,
            target_seconds,
            within_target: seconds <= target_seconds as f64,
            headroom_factor: (seconds > 0.0).then(|| target_seconds as f64 / seconds),
            human: human_duration(seconds),
        }
    }
}

/// Render a duration the way an operator would say it, at full precision.
pub fn human_duration(seconds: f64) -> String {
    if seconds < 60.0 {
        return format!("{seconds:.2}s");
    }
    let whole = seconds as u64;
    let (hours, minutes, secs) = (whole / 3600, (whole % 3600) / 60, whole % 60);
    let fraction = seconds - whole as f64;
    if hours > 0 {
        format!("{hours}h{minutes:02}m{:05.2}s", secs as f64 + fraction)
    } else {
        format!("{minutes}m{:05.2}s", secs as f64 + fraction)
    }
}

/// A known-answer check: something read back out of the restored store and compared to what was
/// recorded before the failure.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownAnswer {
    /// What was checked.
    pub check: String,
    /// What was expected, recorded before the drill began.
    pub expected: String,
    /// What the restored store actually produced.
    pub actual: String,
    /// Whether they matched.
    pub matched: bool,
}

impl KnownAnswer {
    /// Compare an expectation recorded before the failure with what came back after.
    pub fn compare(
        check: impl Into<String>,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        let (expected, actual) = (expected.into(), actual.into());
        KnownAnswer {
            check: check.into(),
            matched: expected == actual,
            expected,
            actual,
        }
    }
}

/// One injected fault and the refusal it produced.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultOutcome {
    /// What was done to the system.
    pub fault: String,
    /// Whether the operation was refused, as it must be.
    pub refused: bool,
    /// The exact refusal, so an operator can recognize it in a log.
    pub error: String,
    /// Whether the live store and the backup shelf were both intact afterwards.
    pub survivors_intact: bool,
}

/// What the backup that was actually consumed looked like.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupConsumed {
    /// The directory name of the backup restored from.
    pub name: String,
    /// BLAKE3 of the exact signed manifest bytes — the same value the signature commits to.
    pub manifest_blake3: String,
    /// The trust root that verified it, resolved through custody.
    pub verified_by_key_id: String,
    /// Which role that key speaks for.
    pub verified_by_role: String,
    /// Files covered by the manifest.
    pub files: u64,
    /// Bytes covered by the manifest.
    pub bytes: u64,
    /// **The exact size of the payload the backup signature covers.**
    ///
    /// Recorded because AWS KMS `Sign` accepts a `Message` of at most 4096 bytes and pure Ed25519
    /// (`ED25519_SHA_512`) requires `MessageType: RAW`. The backup payload is the domain separator,
    /// the key id, and the whole manifest — so it grows with the store, and whether this role can be
    /// moved to KMS unmodified is a measured question rather than an assumed one. See
    /// `docs/key-custody.md` §5.
    pub signed_payload_bytes: u64,
    /// Whether that payload fits the KMS `Sign` RAW limit.
    pub fits_kms_raw_sign_limit: bool,
    /// Which backup signature format the drill exercised: 1 signs the manifest, 2 signs its digest.
    pub signature_format_version: u32,
}

/// The complete record of one drill.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DrillReceipt {
    /// Receipt format version.
    pub schema_version: u32,
    /// Where the drill ran.
    pub topology: Topology,
    /// What this topology did not cover.
    pub not_exercised: Vec<String>,
    /// Which signer backend produced the signatures involved. A drill against a software key proves
    /// the sequence, never custody.
    pub backend: String,
    /// The tenant recovered.
    pub tenant: String,
    /// When the point-in-time clone was taken, Unix seconds. **This is the recovery point.**
    pub clone_taken_unix: u64,
    /// When the simulated failure occurred, Unix seconds.
    pub failure_unix: u64,
    /// **Measured recovery point**: how much work the clone did not contain, in this drill.
    ///
    /// Read this with [`DrillReceipt::recovery_point_bounded_by_seconds`]. On a developer machine
    /// the gap between taking the clone and simulating the failure is seconds, so this number says
    /// the *boundary is in the right place* — everything before the clone came back, everything
    /// after it did not — and says nothing about how much work a real outage would lose. In
    /// production the recovery point is bounded by the backup schedule, not by how fast a test runs.
    pub recovery_point: Measured,
    /// What bounds the recovery point in the deployed system: `backupIntervalSeconds`.
    ///
    /// Recorded beside the measurement so the small number above cannot be quoted as a claim about
    /// production. A deployment taking one backup a day has a worst-case recovery point of a day,
    /// however fast this drill ran.
    pub recovery_point_bounded_by_seconds: u64,
    /// **Measured recovery time**: restore, attested reopen, and verification.
    pub recovery_time: Measured,
    /// The backup actually consumed.
    pub backup: BackupConsumed,
    /// Branch heads in the restored store, branch name → commit id.
    pub restored_heads: std::collections::BTreeMap<String, String>,
    /// Whether `verify_integrity` came back clean on the restored store.
    pub integrity_healthy: bool,
    /// Whether the restored store opened through the attested constructor.
    pub attested_open: bool,
    /// Known-answer checks against expectations recorded before the failure.
    pub known_answers: Vec<KnownAnswer>,
    /// Faults injected, and the refusals they produced.
    pub faults: Vec<FaultOutcome>,
    /// Bytes restored, for context on the recovery-time number.
    pub restored_bytes: u64,
    /// Whether every check in this receipt held.
    pub all_checks_held: bool,
}

impl DrillReceipt {
    /// Whether every known-answer check matched and every injected fault was refused.
    pub fn evaluate(&mut self) {
        self.all_checks_held = self.integrity_healthy
            && self.attested_open
            && self.known_answers.iter().all(|answer| answer.matched)
            && self
                .faults
                .iter()
                .all(|fault| fault.refused && fault.survivors_intact);
    }

    /// One line an operator can read without opening the JSON.
    pub fn summary(&self) -> String {
        format!(
            "{}: drill recovery point {} before failure (production worst case is the {} backup \
             interval; target {}), recovery time {} on {} — {} known-answer checks, {} faults \
             refused, backend {}",
            self.topology.as_str(),
            self.recovery_point.human,
            human_duration(self.recovery_point_bounded_by_seconds as f64),
            human_duration(self.recovery_point.target_seconds as f64),
            self.recovery_time.human,
            human_bytes(self.restored_bytes),
            self.known_answers.len(),
            self.faults.len(),
            self.backend,
        )
    }
}

/// Render a byte count the way an operator would say it.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [(&str, f64); 3] = [
        ("GiB", 1024.0 * 1024.0 * 1024.0),
        ("MiB", 1024.0 * 1024.0),
        ("KiB", 1024.0),
    ];
    for (unit, scale) in UNITS {
        if bytes as f64 >= scale {
            return format!("{:.2} {unit}", bytes as f64 / scale);
        }
    }
    // Below a kibibyte, say the exact count: a rounded "0.01 KiB" hides which of 5 and 15 it was.
    format!("{bytes} B")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_measurement_carries_its_target_and_its_headroom() {
        let measured = Measured::new(252.0, RTO_TARGET_SECONDS);
        assert!(measured.within_target);
        assert_eq!(measured.human, "4m12.00s");
        // 4 hours against 4m12s is a factor of about 57.
        let headroom = measured.headroom_factor.expect("non-zero measurement");
        assert!((headroom - 57.14).abs() < 0.1, "{headroom}");
    }

    /// A measurement outside its target is recorded as a number, not suppressed.
    #[test]
    fn a_measurement_over_target_is_still_recorded() {
        let measured = Measured::new(5.0 * 3600.0, RTO_TARGET_SECONDS);
        assert!(!measured.within_target);
        assert_eq!(measured.human, "5h00m00.00s");
    }

    #[test]
    fn durations_read_the_way_an_operator_says_them() {
        assert_eq!(human_duration(4.2), "4.20s");
        assert_eq!(human_duration(1560.0), "26m00.00s");
        assert_eq!(human_duration(3661.5), "1h01m01.50s");
    }

    #[test]
    fn bytes_read_the_way_an_operator_says_them() {
        assert_eq!(human_bytes(2_254_857_830), "2.10 GiB");
        assert_eq!(human_bytes(4096), "4.00 KiB");
        assert_eq!(human_bytes(12), "12 B");
    }

    #[test]
    fn a_known_answer_compares_what_was_recorded_before_the_failure() {
        assert!(KnownAnswer::compare("head", "abc", "abc").matched);
        assert!(!KnownAnswer::compare("head", "abc", "def").matched);
    }

    /// A topology must say what it did not cover, or its receipt is quotable for a claim it never
    /// supported. One topology today; the assertion is written over a slice so adding a second
    /// cannot skip it.
    #[test]
    fn every_topology_names_what_it_does_not_exercise() {
        let all: &[Topology] = &[Topology::LocalFilesystemCopyClone];
        for topology in all {
            assert!(!topology.not_exercised().is_empty(), "{topology:?}");
            assert!(!topology.as_str().is_empty());
        }
    }
}
