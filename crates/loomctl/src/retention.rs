//! Retention and legal hold over a local backup root.
//!
//! # The shape of the decision
//!
//! Deleting a backup is the one genuinely destructive thing this binary can do, so the decision is a
//! **plan** first and an action second: `loomctl backup-prune` prints what it would remove and
//! removes nothing unless `--apply` is passed. The plan is computed by pure code over a listing, so
//! it is testable without deleting anything.
//!
//! Four rules, and every one of them is a reason to *keep*:
//!
//! 1. **A legal hold names it.** Nothing overrides this — not age, not policy, not `--apply`.
//! 2. **It is one of the newest `minimum-copies`.** A policy that can empty the shelf is a policy
//!    that will, on the day the clock is wrong or the schedule stopped a month ago.
//! 3. **It is younger than `keep-days`.**
//! 4. Otherwise it is pruned.
//!
//! Anything this module does not positively recognize as a backup — a stray file, a partially
//! published directory, someone's notes — is reported as skipped and **never deleted**. A retention
//! tool that deletes what it does not understand is a retention tool that eventually deletes
//! something else.
//!
//! # What this is not
//!
//! It is not the immutable/off-account copy. That is a property of the storage target — object-lock
//! or WORM, in an account the loomDB deployment cannot delete from — and it is a host
//! responsibility, declared in the profile. loomDB links no object-storage client, so it could not
//! reach such a target even if it wanted to. This module governs the local staging root only, and
//! deleting from a staging root must never be the thing that loses the last copy.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use loom_branch::BACKUP_MANIFEST_FILE;

use crate::receipt::BackupReceipt;

/// The file a live store keeps its process lock in, relative to the store root.
const STORE_LOCK: &str = "loom/store.lock";

/// Why one candidate was kept, or that it was not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    /// A legal hold names it.
    KeepLegalHold,
    /// It is one of the newest `minimum-copies`.
    KeepMinimumCopies,
    /// It is younger than `keep-days`.
    KeepRecent,
    /// It is older than the policy allows and is not protected by any rule above.
    Prune,
}

/// One backup directory under the root, and what retention decided about it.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    /// Directory name under the root.
    pub name: String,
    /// Absolute path.
    pub path: PathBuf,
    /// When it was taken, from its receipt; falling back to directory mtime.
    pub created_unix: u64,
    /// Whether the recovery point came from a receipt or from the filesystem.
    pub created_from: &'static str,
    /// What retention decided.
    pub decision: Decision,
    /// The legal hold's recorded reason, when one applies.
    pub hold_reason: Option<String>,
}

/// The full retention plan for one root.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    /// The root that was surveyed.
    pub root: PathBuf,
    /// Every recognized backup, newest first.
    pub candidates: Vec<Candidate>,
    /// Entries under the root that are not recognized backups. Reported, never deleted.
    pub skipped: Vec<String>,
    /// Whether the plan was applied or is a dry run.
    pub applied: bool,
}

impl Plan {
    /// Candidates this plan would remove.
    pub fn to_prune(&self) -> impl Iterator<Item = &Candidate> {
        self.candidates
            .iter()
            .filter(|entry| entry.decision == Decision::Prune)
    }

    /// How many copies survive.
    pub fn retained(&self) -> usize {
        self.candidates.len() - self.to_prune().count()
    }

    /// How many copies survive *because a legal hold names them*.
    pub fn legal_hold_retained(&self) -> usize {
        self.candidates
            .iter()
            .filter(|entry| entry.decision == Decision::KeepLegalHold)
            .count()
    }
}

/// A legal-hold register: backup name → reason.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LegalHolds {
    holds: BTreeMap<String, String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegalHoldDocument {
    schema_version: u32,
    holds: Vec<LegalHoldEntry>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegalHoldEntry {
    backup: String,
    reason: String,
    #[serde(default)]
    opened_unix: Option<u64>,
}

impl LegalHolds {
    /// No holds.
    pub fn none() -> Self {
        LegalHolds::default()
    }

    /// Whether a backup is held, and why.
    pub fn reason(&self, name: &str) -> Option<&str> {
        self.holds.get(name).map(String::as_str)
    }

    /// **Load the register, fail closed.**
    ///
    /// A hold file that cannot be read or parsed is an error, never an empty register: "the legal
    /// hold list was unreadable so we deleted everything" is the failure mode this whole feature
    /// exists to prevent. A hold with no recorded reason is refused too — an unexplained hold cannot
    /// be reviewed or lifted.
    pub fn load(path: &Path) -> Result<Self, String> {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            format!(
                "cannot inspect the legal-hold file {}: {error}",
                path.display()
            )
        })?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "the legal-hold file {} must be a regular file, not a symlink or device",
                path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(format!(
                    "the legal-hold file {} must not be group- or world-writable",
                    path.display()
                ));
            }
        }
        let bytes = std::fs::read(path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let document: LegalHoldDocument = serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "{} is not a valid legal-hold register: {error}",
                path.display()
            )
        })?;
        if document.schema_version != 1 {
            return Err(format!(
                "{} has schemaVersion {}, expected 1",
                path.display(),
                document.schema_version
            ));
        }
        let mut holds = BTreeMap::new();
        for entry in document.holds {
            if entry.backup.is_empty() || entry.reason.trim().is_empty() {
                return Err(format!(
                    "{} registers a hold with no backup name or no reason; an unexplained hold \
                     cannot be reviewed or lifted",
                    path.display()
                ));
            }
            let _ = entry.opened_unix;
            holds.insert(entry.backup, entry.reason);
        }
        Ok(LegalHolds { holds })
    }
}

/// **List the recognized backups under `root`, newest first, plus what was ignored.**
///
/// Recognition is deliberately narrow: a real directory — never a symlink, which could be pointed at
/// a live store — that carries a backup manifest. Everything else is reported as skipped so an
/// operator sees it, and is never a candidate for anything destructive.
///
/// The recovery point comes from the backup's receipt when there is one and from the directory's
/// mtime when there is not, and which of the two was used is recorded rather than smoothed over.
pub fn survey(root: &Path) -> Result<(Vec<Candidate>, Vec<String>), String> {
    let mut candidates = Vec::new();
    let mut skipped = Vec::new();
    let entries = std::fs::read_dir(root)
        .map_err(|error| format!("cannot list {}: {error}", root.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot list {}: {error}", root.display()))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if !metadata.file_type().is_dir() || !path.join(BACKUP_MANIFEST_FILE).is_file() {
            skipped.push(name);
            continue;
        }
        let (created_unix, created_from) = match BackupReceipt::read_beside(&path)? {
            Some(receipt) => (receipt.created_unix, "receipt"),
            None => (directory_mtime_unix(&metadata), "filesystem"),
        };
        candidates.push(Candidate {
            name,
            path,
            created_unix,
            created_from,
            decision: Decision::Prune,
            hold_reason: None,
        });
    }
    // Newest first, with the name as a stable tiebreak so a listing is reproducible.
    candidates.sort_by(|a, b| {
        b.created_unix
            .cmp(&a.created_unix)
            .then_with(|| a.name.cmp(&b.name))
    });
    skipped.sort();
    Ok((candidates, skipped))
}

/// **The newest backup under `root`.**
///
/// This is how the scheduled verification and the restore rehearsal find what to work on. They
/// cannot be handed a path by the job that wrote it — they run later, as a different identity, and
/// deliberately share no state with the writer beyond the shelf itself.
///
/// An empty shelf is an error rather than a quiet success: "there was nothing to verify" must not
/// look like "verification passed".
pub fn newest(root: &Path) -> Result<PathBuf, String> {
    if !root.is_dir() {
        return Err(format!(
            "backup root does not exist or is not a directory: {}",
            root.display()
        ));
    }
    let (candidates, _) = survey(root)?;
    candidates
        .into_iter()
        .next()
        .map(|candidate| candidate.path)
        .ok_or_else(|| {
            format!(
                "no backup found under {}; an empty shelf is not a passing verification",
                root.display()
            )
        })
}

/// Survey `root` and decide what retention would do, deleting nothing.
///
/// `now_unix` is a parameter rather than a call to the clock so the decision is testable and so a
/// caller can reproduce a plan exactly.
pub fn plan(
    root: &Path,
    keep_days: u32,
    minimum_copies: usize,
    holds: &LegalHolds,
    now_unix: u64,
) -> Result<Plan, String> {
    if keep_days == 0 {
        return Err("--keep-days must be at least 1".into());
    }
    if minimum_copies == 0 {
        return Err(
            "--minimum-copies must be at least 1; a retention policy that can empty the shelf will"
                .into(),
        );
    }
    if !root.is_dir() {
        return Err(format!(
            "backup root does not exist or is not a directory: {}",
            root.display()
        ));
    }
    // A live store is not a backup root. Pruning inside one would delete a tenant's database.
    if root.join(STORE_LOCK).exists() {
        return Err(format!(
            "{} looks like a live LoomDB store ({STORE_LOCK} is present), not a backup root; \
             refusing to apply retention to a database",
            root.display()
        ));
    }

    let (mut candidates, skipped) = survey(root)?;

    let horizon = u64::from(keep_days).saturating_mul(86_400);
    for (index, candidate) in candidates.iter_mut().enumerate() {
        if let Some(reason) = holds.reason(&candidate.name) {
            candidate.decision = Decision::KeepLegalHold;
            candidate.hold_reason = Some(reason.to_string());
            continue;
        }
        if index < minimum_copies {
            candidate.decision = Decision::KeepMinimumCopies;
            continue;
        }
        if now_unix.saturating_sub(candidate.created_unix) <= horizon {
            candidate.decision = Decision::KeepRecent;
            continue;
        }
        candidate.decision = Decision::Prune;
    }

    Ok(Plan {
        root: root.to_path_buf(),
        candidates,
        skipped,
        applied: false,
    })
}

/// Remove exactly what the plan marked `Prune`, and nothing else.
pub fn apply(plan: &mut Plan) -> Result<(), String> {
    let doomed: Vec<PathBuf> = plan.to_prune().map(|entry| entry.path.clone()).collect();
    for path in doomed {
        std::fs::remove_dir_all(&path)
            .map_err(|error| format!("cannot remove {}: {error}", path.display()))?;
        let receipt = crate::receipt::path_for(&path);
        match std::fs::remove_file(&receipt) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot remove {}: {error}", receipt.display())),
        }
    }
    plan.applied = true;
    Ok(())
}

fn directory_mtime_unix(metadata: &std::fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;
    const NOW: u64 = 1_800_000_000;

    /// Build a backup root with named backups at given ages in days.
    fn root_with(ages: &[(&str, u64)]) -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        for (name, age_days) in ages {
            let path = dir.path().join(name);
            std::fs::create_dir(&path)?;
            std::fs::write(path.join(BACKUP_MANIFEST_FILE), b"{}")?;
            BackupReceipt {
                schema_version: BackupReceipt::SCHEMA_VERSION,
                tenant: "acme".into(),
                key_id: "k".into(),
                manifest_blake3: "h".into(),
                created_unix: NOW - age_days * DAY,
                duration_seconds: 1.0,
                bytes: 1,
                files: 1,
            }
            .write_beside(&path)?;
        }
        Ok(dir)
    }

    fn decision(plan: &Plan, name: &str) -> Decision {
        plan.candidates
            .iter()
            .find(|entry| entry.name == name)
            .unwrap_or_else(|| panic!("{name} is a candidate"))
            .decision
    }

    #[test]
    fn old_copies_are_pruned_and_recent_ones_kept() -> Result<(), Box<dyn std::error::Error>> {
        let root = root_with(&[("d0", 0), ("d10", 10), ("d90", 90), ("d200", 200)])?;
        let plan = plan(root.path(), 35, 1, &LegalHolds::none(), NOW)?;
        assert_eq!(decision(&plan, "d0"), Decision::KeepMinimumCopies);
        assert_eq!(decision(&plan, "d10"), Decision::KeepRecent);
        assert_eq!(decision(&plan, "d90"), Decision::Prune);
        assert_eq!(decision(&plan, "d200"), Decision::Prune);
        assert_eq!(plan.retained(), 2);
        Ok(())
    }

    /// **The legal-hold rule.** Nothing overrides it — not age, not policy.
    #[test]
    fn a_backup_under_legal_hold_is_never_pruned() -> Result<(), Box<dyn std::error::Error>> {
        let root = root_with(&[("d0", 0), ("d900", 900)])?;
        let mut holds = LegalHolds::none();
        holds
            .holds
            .insert("d900".into(), "litigation hold 2026-114".into());
        let plan = plan(root.path(), 35, 1, &holds, NOW)?;
        assert_eq!(decision(&plan, "d900"), Decision::KeepLegalHold);
        assert_eq!(plan.to_prune().count(), 0);
        assert_eq!(plan.legal_hold_retained(), 1);
        Ok(())
    }

    /// A policy that can empty the shelf will, on the day the schedule quietly stopped.
    #[test]
    fn the_newest_copies_survive_however_old_they_are() -> Result<(), Box<dyn std::error::Error>> {
        let root = root_with(&[("d400", 400), ("d500", 500), ("d600", 600)])?;
        let plan = plan(root.path(), 35, 2, &LegalHolds::none(), NOW)?;
        assert_eq!(decision(&plan, "d400"), Decision::KeepMinimumCopies);
        assert_eq!(decision(&plan, "d500"), Decision::KeepMinimumCopies);
        assert_eq!(decision(&plan, "d600"), Decision::Prune);
        Ok(())
    }

    #[test]
    fn a_minimum_of_zero_copies_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let root = root_with(&[("d0", 0)])?;
        assert!(plan(root.path(), 35, 0, &LegalHolds::none(), NOW).is_err());
        assert!(plan(root.path(), 0, 1, &LegalHolds::none(), NOW).is_err());
        Ok(())
    }

    /// Anything unrecognized is reported and left alone.
    #[test]
    fn unrecognized_entries_are_skipped_never_deleted() -> Result<(), Box<dyn std::error::Error>> {
        let root = root_with(&[("d900", 900)])?;
        std::fs::write(root.path().join("operator-notes.txt"), b"do not delete")?;
        std::fs::create_dir(root.path().join("half-published"))?;
        let mut plan = plan(root.path(), 35, 1, &LegalHolds::none(), NOW)?;
        assert!(plan.skipped.contains(&"operator-notes.txt".to_string()));
        assert!(plan.skipped.contains(&"half-published".to_string()));
        apply(&mut plan)?;
        assert!(root.path().join("operator-notes.txt").is_file());
        assert!(root.path().join("half-published").is_dir());
        Ok(())
    }

    /// Pruning inside a live database is refused before anything is listed.
    #[test]
    fn a_live_store_is_not_a_backup_root() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        std::fs::create_dir_all(root.path().join("loom"))?;
        std::fs::write(root.path().join(STORE_LOCK), b"")?;
        let error = plan(root.path(), 35, 1, &LegalHolds::none(), NOW)
            .expect_err("a live store must be refused");
        assert!(
            error.contains("refusing to apply retention to a database"),
            "{error}"
        );
        Ok(())
    }

    /// A symlinked entry is not followed, so retention cannot delete through a link.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_entry_is_skipped() -> Result<(), Box<dyn std::error::Error>> {
        let root = root_with(&[("d0", 0)])?;
        let elsewhere = tempfile::tempdir()?;
        std::fs::write(elsewhere.path().join(BACKUP_MANIFEST_FILE), b"{}")?;
        std::os::unix::fs::symlink(elsewhere.path(), root.path().join("linked"))?;
        let mut plan = plan(root.path(), 35, 1, &LegalHolds::none(), NOW)?;
        assert!(plan.skipped.contains(&"linked".to_string()));
        apply(&mut plan)?;
        assert!(elsewhere.path().join(BACKUP_MANIFEST_FILE).is_file());
        Ok(())
    }

    fn write_holds(dir: &Path, body: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let path = dir.join("legal-hold.json");
        std::fs::write(&path, body)?;
        Ok(path)
    }

    #[test]
    fn a_hold_register_loads_and_names_its_reason() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = write_holds(
            dir.path(),
            r#"{"schemaVersion":1,"holds":[{"backup":"d900","reason":"litigation 2026-114"}]}"#,
        )?;
        let holds = LegalHolds::load(&path)?;
        assert_eq!(holds.reason("d900"), Some("litigation 2026-114"));
        assert_eq!(holds.reason("d0"), None);
        Ok(())
    }

    /// A hold nobody explained cannot be reviewed or lifted, so it is refused at load.
    #[test]
    fn a_hold_with_no_reason_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = write_holds(
            dir.path(),
            r#"{"schemaVersion":1,"holds":[{"backup":"d900","reason":"  "}]}"#,
        )?;
        assert!(LegalHolds::load(&path).is_err());
        Ok(())
    }

    /// **Fail closed.** An unreadable hold register must never decay into "no holds".
    #[test]
    fn an_unreadable_hold_register_is_an_error_not_an_empty_one(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        assert!(LegalHolds::load(&dir.path().join("absent.json")).is_err());
        let path = write_holds(dir.path(), "{ not json")?;
        assert!(LegalHolds::load(&path).is_err());
        Ok(())
    }

    /// Anything that can rewrite the register can lift a hold silently.
    #[cfg(unix)]
    #[test]
    fn a_group_writable_hold_register_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir()?;
        let path = write_holds(dir.path(), r#"{"schemaVersion":1,"holds":[]}"#)?;
        let mut permissions = std::fs::metadata(&path)?.permissions();
        permissions.set_mode(0o660);
        std::fs::set_permissions(&path, permissions)?;
        let error = LegalHolds::load(&path).expect_err("a writable register must be refused");
        assert!(error.contains("group- or world-writable"), "{error}");
        Ok(())
    }

    #[test]
    fn applying_removes_the_backup_and_its_receipt() -> Result<(), Box<dyn std::error::Error>> {
        let root = root_with(&[("d0", 0), ("d900", 900)])?;
        let doomed = root.path().join("d900");
        let mut plan = plan(root.path(), 35, 1, &LegalHolds::none(), NOW)?;
        apply(&mut plan)?;
        assert!(!doomed.exists());
        assert!(!crate::receipt::path_for(&doomed).exists());
        assert!(root.path().join("d0").is_dir());
        assert!(plan.applied);
        Ok(())
    }
}
