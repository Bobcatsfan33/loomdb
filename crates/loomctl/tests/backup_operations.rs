//! Backup operations at the command boundary: receipts, signals, retention, and the one constraint
//! that shapes the whole deployment design.
//!
//! These run the real `loomctl` binary, because the CronJob and the systemd timer the reference
//! profile renders run the real `loomctl` binary. A retention policy that is correct as a function
//! and wrong as a command is wrong.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use loom_branch::{Loom, BACKUP_MANIFEST_FILE};
use loom_core::{ActorId, Record, SessionId, TenantId, Value, WriteEnvelope};

const TENANT: &str = "acme";
const KEY_ID: &str = "backup-root-2026-q3";

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_loomctl"))
        .args(arguments)
        .output()
        .expect("loomctl must execute")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn text(path: &Path) -> String {
    path.to_str().expect("UTF-8 path").to_string()
}

/// A seeded store plus the signing and public trust-root files a signed backup needs.
struct Fixture {
    _root: tempfile::TempDir,
    root: PathBuf,
    store: PathBuf,
    signing_file: PathBuf,
    public_file: PathBuf,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let store = root.path().join("store");
        {
            let db = Loom::open(&store, TenantId::new(TENANT))?;
            let (session, token) = db.open_session_named(SessionId::new("incident"))?;
            db.write(
                &token,
                &session.branch,
                b"status".to_vec(),
                Record::Value(Value::Text("contained".into())),
                &WriteEnvelope::new(
                    ActorId::new("operator"),
                    session.id,
                    session.branch.clone(),
                    "seed the backup fixture",
                ),
            )?;
        }
        let signing = ed25519_dalek::SigningKey::from_bytes(&[73u8; 32]);
        let signing_file = root.path().join("backup-signing.hex");
        let public_file = root.path().join("backup-public.hex");
        std::fs::write(&signing_file, format!("{}\n", hex(&signing.to_bytes())))?;
        std::fs::write(
            &public_file,
            format!("{}\n", hex(signing.verifying_key().as_bytes())),
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&signing_file, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Fixture {
            root: root.path().to_path_buf(),
            _root: root,
            store,
            signing_file,
            public_file,
        })
    }

    fn backup_signed(&self, out: &Path, metrics: Option<&Path>) -> Output {
        let mut arguments = vec![
            "backup-signed".to_string(),
            "--path".into(),
            text(&self.store),
            "--tenant".into(),
            TENANT.into(),
            "--out".into(),
            text(out),
            "--signing-key-file".into(),
            text(&self.signing_file),
            "--key-id".into(),
            KEY_ID.into(),
        ];
        if let Some(metrics) = metrics {
            arguments.push("--metrics-file".into());
            arguments.push(text(metrics));
        }
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        run(&borrowed)
    }

    /// The scheduled shape: hand the writer a shelf and let it mint its own destination.
    fn backup_signed_to_shelf(&self, shelf: &Path, metrics: Option<&Path>) -> Output {
        let mut arguments = vec![
            "backup-signed".to_string(),
            "--path".into(),
            text(&self.store),
            "--tenant".into(),
            TENANT.into(),
            "--root".into(),
            text(shelf),
            "--signing-key-file".into(),
            text(&self.signing_file),
            "--key-id".into(),
            KEY_ID.into(),
        ];
        if let Some(metrics) = metrics {
            arguments.push("--metrics-file".into());
            arguments.push(text(metrics));
        }
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        run(&borrowed)
    }

    fn verify_signed(&self, backup: &Path, metrics: Option<&Path>) -> Output {
        let mut arguments = vec![
            "verify-backup-signed".to_string(),
            "--path".into(),
            text(backup),
            "--public-key-file".into(),
            text(&self.public_file),
            "--key-id".into(),
            KEY_ID.into(),
        ];
        if let Some(metrics) = metrics {
            arguments.push("--metrics-file".into());
            arguments.push(text(metrics));
        }
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        run(&borrowed)
    }
}

/// Sample lines from a Prometheus textfile, as name → value.
fn samples(path: &Path) -> std::collections::BTreeMap<String, f64> {
    std::fs::read_to_string(path)
        .expect("the metrics file exists")
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .filter_map(|line| {
            let (name, value) = line.split_once(' ')?;
            Some((name.to_string(), value.parse().ok()?))
        })
        .collect()
}

// ── the scheduled write ──────────────────────────────────────────────────────────────────────────

#[test]
fn a_signed_backup_publishes_a_receipt_and_its_signals() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let backup = fixture.root.join("acme-2026-07-31");
    let metrics = fixture.root.join("backup.prom");

    let output = fixture.backup_signed(&backup, Some(&metrics));
    assert!(output.status.success(), "{output:?}");

    // The receipt is a sibling, never a member: a file inside the backup would break the manifest
    // allow-list that verification depends on.
    let receipt_path = fixture.root.join("acme-2026-07-31.receipt.json");
    assert!(
        receipt_path.is_file(),
        "the receipt is written beside the backup"
    );
    assert!(
        !backup.join("acme-2026-07-31.receipt.json").exists(),
        "the receipt must never land inside the signed backup"
    );
    let receipt: serde_json::Value = serde_json::from_slice(&std::fs::read(&receipt_path)?)?;
    assert_eq!(receipt["tenant"], TENANT);
    assert_eq!(receipt["keyId"], KEY_ID);
    assert!(receipt["createdUnix"].as_u64().unwrap_or(0) > 1_700_000_000);
    assert!(receipt["bytes"].as_u64().unwrap_or(0) > 0);

    let signals = samples(&metrics);
    assert_eq!(signals.get("loomdb_backup_failures_total"), Some(&0.0));
    assert!(signals["loomdb_backup_last_success_timestamp_seconds"] > 1_700_000_000.0);
    assert!(signals["loomdb_backup_bytes"] > 0.0);
    assert!(signals["loomdb_backup_files"] > 0.0);
    Ok(())
}

/// **No tenant identifier ever reaches the monitoring pipeline.** The path carries the tenant; the
/// payload must not, for the same reason `loomd` forbids a tenant dimension on its RPC instruments.
#[test]
fn the_metrics_file_carries_no_tenant_identifier() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let backup = fixture.root.join("acme-2026-07-31");
    let metrics = fixture.root.join("backup.prom");
    assert!(fixture
        .backup_signed(&backup, Some(&metrics))
        .status
        .success());

    let body = std::fs::read_to_string(&metrics)?;
    assert!(
        !body.contains(TENANT),
        "a metric must not carry a tenant identifier: {body}"
    );
    assert!(
        !body.contains('{'),
        "these signals carry no labels at all, so cardinality cannot grow: {body}"
    );
    Ok(())
}

/// **A failed run is loud.** A collector that only hears from successful runs cannot tell a healthy
/// backup from a job that stopped running.
#[test]
fn a_failed_backup_still_publishes_its_failure() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let backup = fixture.root.join("already-here");
    std::fs::create_dir(&backup)?;
    let metrics = fixture.root.join("backup.prom");

    let output = fixture.backup_signed(&backup, Some(&metrics));
    assert!(
        !output.status.success(),
        "an existing destination is refused"
    );

    let signals = samples(&metrics);
    assert_eq!(signals.get("loomdb_backup_failures_total"), Some(&1.0));
    assert!(
        !signals.contains_key("loomdb_backup_last_success_timestamp_seconds"),
        "a failed run must not advance the last-success signal"
    );
    Ok(())
}

/// **THE CONSTRAINT THE DEPLOYMENT IS BUILT AROUND.** `FileRefStore::open` holds an exclusive
/// advisory lock for the store's lifetime, so a scheduled backup cannot read a volume a live `loomd`
/// is serving. This is why the reference profile schedules the backup against a platform-provided
/// point-in-time clone and refuses to render a job that mounts the live tenant volume: the
/// alternative is a CronJob that fails every night.
#[test]
fn a_backup_cannot_be_taken_from_a_store_a_daemon_is_holding(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let owner = Loom::open(&fixture.store, TenantId::new(TENANT))?;

    let output = fixture.backup_signed(&fixture.root.join("while-live"), None);
    assert!(
        !output.status.success(),
        "a second process must not open a store the engine holds: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("already open by another process"),
        "the refusal must name the ownership conflict: {output:?}"
    );

    // Releasing the owner releases the lock; the same command then succeeds against the same path.
    drop(owner);
    let after = fixture.backup_signed(&fixture.root.join("after-release"), None);
    assert!(after.status.success(), "{after:?}");
    Ok(())
}

// ── the independent check ────────────────────────────────────────────────────────────────────────

#[test]
fn independent_verification_reports_the_recovery_point() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let backup = fixture.root.join("acme-2026-07-31");
    let metrics = fixture.root.join("verify.prom");
    assert!(fixture.backup_signed(&backup, None).status.success());

    let output = fixture.verify_signed(&backup, Some(&metrics));
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert!(report["recovery_point_unix"].as_u64().unwrap_or(0) > 1_700_000_000);

    let signals = samples(&metrics);
    assert_eq!(signals.get("loomdb_backup_failures_total"), Some(&0.0));
    assert_eq!(
        signals.get("loomdb_backup_scrub_damaged_objects"),
        Some(&0.0)
    );
    assert!(signals["loomdb_backup_last_verified_timestamp_seconds"] > 1_700_000_000.0);
    assert!(
        signals["loomdb_backup_last_verified_recovery_point_seconds"] > 1_700_000_000.0,
        "verification must report *which* point in time it proved restorable"
    );
    Ok(())
}

/// A receipt is an operational record, not an authenticity claim. Deleting it costs a dashboard
/// number and nothing else — the signature still verifies, and the recovery point is reported as
/// unknown rather than invented.
#[test]
fn a_missing_receipt_leaves_the_recovery_point_unknown_not_wrong(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let backup = fixture.root.join("acme-2026-07-31");
    let metrics = fixture.root.join("verify.prom");
    assert!(fixture.backup_signed(&backup, None).status.success());
    std::fs::remove_file(fixture.root.join("acme-2026-07-31.receipt.json"))?;

    let output = fixture.verify_signed(&backup, Some(&metrics));
    assert!(
        output.status.success(),
        "the signature still verifies: {output:?}"
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert!(report["recovery_point_unix"].is_null());

    let signals = samples(&metrics);
    assert!(
        !signals.contains_key("loomdb_backup_last_verified_recovery_point_seconds"),
        "an unknown recovery point is omitted, never published as a plausible-looking zero"
    );
    assert!(signals.contains_key("loomdb_backup_last_verified_timestamp_seconds"));
    Ok(())
}

/// **The trust-root signature is the authenticity check.** A rewritten receipt cannot make a
/// tampered backup verify, and it cannot lend its timestamp to one it no longer matches.
#[test]
fn a_tampered_backup_fails_verification_and_reports_damage(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let backup = fixture.root.join("acme-2026-07-31");
    let metrics = fixture.root.join("verify.prom");
    assert!(fixture.backup_signed(&backup, None).status.success());

    // Alter a byte of a file the signed manifest allow-lists.
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(backup.join(BACKUP_MANIFEST_FILE))?)?;
    let victim = manifest["files"]
        .as_array()
        .and_then(|files| files.first())
        .and_then(|file| file["path"].as_str())
        .ok_or("the manifest allow-lists at least one file")?
        .to_string();
    let victim = backup.join(&victim);
    let mut bytes = std::fs::read(&victim)?;
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&victim, bytes)?;

    let output = fixture.verify_signed(&backup, Some(&metrics));
    assert!(
        !output.status.success(),
        "tampering must be caught: {output:?}"
    );

    let signals = samples(&metrics);
    assert_eq!(signals.get("loomdb_backup_failures_total"), Some(&1.0));
    assert_eq!(
        signals.get("loomdb_backup_scrub_damaged_objects"),
        Some(&1.0),
        "a backup that fails verification is damage, not merely a failed job"
    );
    Ok(())
}

// ── retention and legal hold ─────────────────────────────────────────────────────────────────────

fn aged_backup(
    root: &Path,
    name: &str,
    created_unix: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = root.join(name);
    std::fs::create_dir_all(&path)?;
    std::fs::write(path.join(BACKUP_MANIFEST_FILE), b"{}")?;
    let receipt = serde_json::json!({
        "schemaVersion": 1,
        "tenant": TENANT,
        "keyId": KEY_ID,
        "manifestBlake3": "0".repeat(64),
        "createdUnix": created_unix,
        "durationSeconds": 1.0,
        "bytes": 1,
        "files": 1,
    });
    std::fs::write(
        root.join(format!("{name}.receipt.json")),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    Ok(())
}

#[test]
fn retention_is_a_dry_run_until_it_is_applied() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let shelf = dir.path().join("backups");
    std::fs::create_dir(&shelf)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    aged_backup(&shelf, "today", now)?;
    aged_backup(&shelf, "ancient", now - 400 * 86_400)?;

    let dry = run(&[
        "backup-prune",
        "--root",
        &text(&shelf),
        "--keep-days",
        "35",
        "--minimum-copies",
        "1",
    ]);
    assert!(dry.status.success(), "{dry:?}");
    let plan: serde_json::Value = serde_json::from_slice(&dry.stdout)?;
    assert_eq!(plan["applied"], false);
    assert!(
        shelf.join("ancient").is_dir(),
        "a dry run must remove nothing"
    );

    let applied = run(&[
        "backup-prune",
        "--root",
        &text(&shelf),
        "--keep-days",
        "35",
        "--minimum-copies",
        "1",
        "--apply",
    ]);
    assert!(applied.status.success(), "{applied:?}");
    assert!(
        !shelf.join("ancient").exists(),
        "--apply removes the expired copy"
    );
    assert!(
        shelf.join("today").is_dir(),
        "the newest copy always survives"
    );
    Ok(())
}

/// **Legal hold overrides retention, at the command boundary.**
#[test]
fn a_held_backup_survives_an_applied_prune() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let shelf = dir.path().join("backups");
    std::fs::create_dir(&shelf)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    aged_backup(&shelf, "today", now)?;
    aged_backup(&shelf, "ancient", now - 400 * 86_400)?;
    aged_backup(&shelf, "under-hold", now - 900 * 86_400)?;

    let holds = dir.path().join("legal-hold.json");
    std::fs::write(
        &holds,
        r#"{"schemaVersion":1,"holds":[{"backup":"under-hold","reason":"litigation 2026-114"}]}"#,
    )?;
    let metrics = dir.path().join("prune.prom");

    let applied = run(&[
        "backup-prune",
        "--root",
        &text(&shelf),
        "--keep-days",
        "35",
        "--minimum-copies",
        "1",
        "--legal-hold-file",
        &text(&holds),
        "--metrics-file",
        &text(&metrics),
        "--apply",
    ]);
    assert!(applied.status.success(), "{applied:?}");
    assert!(
        shelf.join("under-hold").is_dir(),
        "a legal hold outranks every retention rule"
    );
    assert!(!shelf.join("ancient").exists());

    let signals = samples(&metrics);
    assert_eq!(signals.get("loomdb_backup_legal_hold_retained"), Some(&1.0));
    assert_eq!(signals.get("loomdb_backup_pruned_total"), Some(&1.0));
    assert_eq!(signals.get("loomdb_backup_retained_copies"), Some(&2.0));
    Ok(())
}

/// Retention must never be pointed at a database.
#[test]
fn retention_refuses_to_run_inside_a_live_store() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let output = run(&[
        "backup-prune",
        "--root",
        &text(&fixture.store),
        "--keep-days",
        "35",
        "--minimum-copies",
        "1",
        "--apply",
    ]);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("refusing to apply retention to a database"),
        "{output:?}"
    );
    Ok(())
}

// ── the restore rehearsal ────────────────────────────────────────────────────────────────────────

/// **A rehearsal restores beside production and never onto it.** `restore-signed` refuses any
/// destination that already exists, so a rehearsal aimed at a live data directory fails instead of
/// overwriting a tenant's database — and it publishes nothing: activating a restored store is a
/// separate, deliberate act.
#[test]
fn a_rehearsal_restore_cannot_overwrite_a_live_store() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let backup = fixture.root.join("acme-2026-07-31");
    assert!(fixture.backup_signed(&backup, None).status.success());

    let onto_production = run(&[
        "restore-signed",
        "--path",
        &text(&backup),
        "--expected-tenant",
        TENANT,
        "--out",
        &text(&fixture.store),
        "--public-key-file",
        &text(&fixture.public_file),
        "--key-id",
        KEY_ID,
    ]);
    assert!(
        !onto_production.status.success(),
        "a restore must never publish onto an existing store: {onto_production:?}"
    );
    assert!(
        String::from_utf8_lossy(&onto_production.stderr).contains("already exists"),
        "{onto_production:?}"
    );

    // The rehearsal path — a fresh directory — succeeds, and leaves production untouched.
    let rehearsal = fixture.root.join("rehearsal-2026-07-31");
    let output = run(&[
        "restore-signed",
        "--path",
        &text(&backup),
        "--expected-tenant",
        TENANT,
        "--out",
        &text(&rehearsal),
        "--public-key-file",
        &text(&fixture.public_file),
        "--key-id",
        KEY_ID,
    ]);
    assert!(output.status.success(), "{output:?}");
    assert!(rehearsal.is_dir());
    assert!(fixture.store.is_dir(), "production is untouched");

    // And the rehearsed copy is a real, verifiable store rather than a directory of bytes.
    let verified = run(&["verify", "--path", &text(&rehearsal), "--tenant", TENANT]);
    assert!(verified.status.success(), "{verified:?}");
    Ok(())
}

// ── the shelf: how a scheduled job finds its work ────────────────────────────────────────────────

/// **The scheduled flow, end to end.** A writer mints a fresh destination on the shelf; a verifier
/// that runs later, holding only the public trust root, finds the *newest* backup there on its own.
/// Neither is handed a path by the other — they share nothing but the shelf.
#[test]
fn a_shelf_mints_destinations_and_verification_finds_the_newest(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let shelf = fixture.root.join("shelf");
    let metrics = fixture.root.join("verify.prom");

    let first = fixture.backup_signed_to_shelf(&shelf, None);
    assert!(first.status.success(), "{first:?}");
    let first: serde_json::Value = serde_json::from_slice(&first.stdout)?;
    let first_created = first["receipt"]["createdUnix"].as_u64().unwrap_or(0);

    // A second run mints its own destination rather than colliding with the first.
    let entries: Vec<_> = std::fs::read_dir(&shelf)?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .collect();
    assert_eq!(entries.len(), 1, "one backup so far");

    let output = run(&[
        "verify-backup-signed",
        "--root",
        &text(&shelf),
        "--public-key-file",
        &text(&fixture.public_file),
        "--key-id",
        KEY_ID,
        "--metrics-file",
        &text(&metrics),
    ]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["recovery_point_unix"].as_u64(), Some(first_created));
    assert!(samples(&metrics)["loomdb_backup_last_verified_recovery_point_seconds"] > 0.0);
    Ok(())
}

/// **An empty shelf is not a passing verification.** A job that verifies nothing must say so, or a
/// pipeline that silently stopped producing backups reports success forever.
#[test]
fn verifying_an_empty_shelf_is_an_error() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let shelf = fixture.root.join("empty-shelf");
    std::fs::create_dir(&shelf)?;
    let metrics = fixture.root.join("verify.prom");

    let output = run(&[
        "verify-backup-signed",
        "--root",
        &text(&shelf),
        "--public-key-file",
        &text(&fixture.public_file),
        "--key-id",
        KEY_ID,
        "--metrics-file",
        &text(&metrics),
    ]);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not a passing verification"),
        "{output:?}"
    );
    assert_eq!(
        samples(&metrics).get("loomdb_backup_failures_total"),
        Some(&1.0)
    );
    Ok(())
}

/// A rehearsal driven the way the CronJob drives it: newest on the shelf, fresh path under the
/// rehearsal volume, production untouched.
#[test]
fn a_scheduled_rehearsal_restores_the_newest_backup_to_a_fresh_path(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let shelf = fixture.root.join("shelf");
    let rehearsal_root = fixture.root.join("rehearsal");
    assert!(fixture
        .backup_signed_to_shelf(&shelf, None)
        .status
        .success());

    let output = run(&[
        "restore-signed",
        "--root",
        &text(&shelf),
        "--expected-tenant",
        TENANT,
        "--out-root",
        &text(&rehearsal_root),
        "--public-key-file",
        &text(&fixture.public_file),
        "--key-id",
        KEY_ID,
    ]);
    assert!(output.status.success(), "{output:?}");
    let restored: Vec<_> = std::fs::read_dir(&rehearsal_root)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    assert_eq!(restored.len(), 1, "exactly one rehearsed store");
    assert!(fixture.store.is_dir(), "production is untouched");

    let verified = run(&["verify", "--path", &text(&restored[0]), "--tenant", TENANT]);
    assert!(verified.status.success(), "{verified:?}");
    Ok(())
}

/// A backup of one tenant cannot be rehearsed into another tenant's expectation.
#[test]
fn a_rehearsal_refuses_a_backup_from_another_tenant() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let backup = fixture.root.join("acme-2026-07-31");
    assert!(fixture.backup_signed(&backup, None).status.success());

    let output = run(&[
        "restore-signed",
        "--path",
        &text(&backup),
        "--expected-tenant",
        "beta-industries",
        "--out",
        &text(&fixture.root.join("cross-tenant")),
        "--public-key-file",
        &text(&fixture.public_file),
        "--key-id",
        KEY_ID,
    ]);
    assert!(!output.status.success(), "{output:?}");
    assert!(!fixture.root.join("cross-tenant").exists());
    Ok(())
}
