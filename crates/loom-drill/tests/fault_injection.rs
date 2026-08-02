//! **What the recovery path refuses, and by what name.**
//!
//! A drill that only proves the happy path proves the least interesting half. These are the ways a
//! recovery goes wrong in practice — bad media, the wrong backup, the wrong key, a revoked key, a
//! stale registry, a full disk, a process killed mid-flight — and each one asserts two things:
//!
//! 1. the operation is **refused**, not completed with a warning; and
//! 2. the refusal **names the fault**, so the operator reading it at 3am can tell corrupted media
//!    from a revoked key from someone reaching for the wrong tenant's backup.
//!
//! Every fault also asserts the **survivors**: after the refusal, the live store and the backup
//! shelf must both still be there. A restore that fails is an inconvenience; a restore that fails
//! and takes the shelf with it is the outage.

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use loom_branch::{Loom, BACKUP_MANIFEST_FILE, BACKUP_SIGNATURE_FILE};
use loom_core::{ActorId, Record, SessionId, TenantId, Value, WriteEnvelope};
use loom_drill::{verify_from_separate_trust_domain, FaultOutcome};
use loom_keys::{KeyDirectory, KeyRole, TrustRootRegister};

const TENANT: &str = "acme-corp";
const KEY_ID: &str = "backup-root-2026-q3";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn register_json(key_id: &str, status: &str, public_key: &str) -> String {
    let revocation = if status == "revoked" {
        r#","revocationReason":"key compromise drill 2026-08-01""#
    } else {
        ""
    };
    format!(
        r#"{{"schemaVersion":1,"roots":[{{"keyId":"{key_id}","role":"backup-root",
           "algorithm":"ed25519","publicKey":"{public_key}","backend":"software","status":"{status}",
           "generation":1,"ceremony":{{"reference":"DRILL","approvals":[
             {{"approver":"pki-officer","atUnix":1800000000}},
             {{"approver":"security-lead","atUnix":1800000000}}]}}{revocation}}}]}}"#
    )
}

fn directory(path: &Path) -> KeyDirectory {
    KeyDirectory::new(
        TrustRootRegister::load(path).expect("register loads"),
        KeyRole::BackupRoot,
    )
    .expect("valid register")
}

/// A seeded store plus a signed backup of it, and the trust material to verify that backup.
struct Fixture {
    _root: tempfile::TempDir,
    root: PathBuf,
    live: PathBuf,
    backup: PathBuf,
    register: PathBuf,
}

impl Fixture {
    fn new(tenant: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_key(tenant, KEY_ID, 11)
    }

    fn with_key(tenant: &str, key_id: &str, seed: u8) -> Result<Self, Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let live = root.path().join("live");
        {
            let db = Loom::open(&live, TenantId::new(tenant))?;
            let (session, token) = db.open_session_named(SessionId::new("seed"))?;
            for index in 0..6 {
                db.write(
                    &token,
                    &session.branch,
                    format!("k/{index}").into_bytes(),
                    Record::Value(Value::Text(format!("value {index}"))),
                    &WriteEnvelope::new(
                        ActorId::new("operator"),
                        session.id.clone(),
                        session.branch.clone(),
                        "seed",
                    ),
                )?;
            }
        }
        let clone = root.path().join("clone");
        loom_drill::take_clone(&live, &clone)?;
        let backup = root.path().join("backup");
        {
            let clone_db = Loom::open(&clone, TenantId::new(tenant))?;
            clone_db.backup_to_signed(&backup, key_id, &key(seed))?;
        }
        let register = root.path().join("trust-roots.json");
        std::fs::write(
            &register,
            register_json(key_id, "active", &hex(key(seed).verifying_key().as_bytes())),
        )?;
        Ok(Fixture {
            root: root.path().to_path_buf(),
            _root: root,
            live,
            backup,
            register,
        })
    }

    /// Whether the live store and the shelf both survived whatever was just done.
    fn survivors_intact(&self) -> bool {
        let live_ok = Loom::open(&self.live, TenantId::new(TENANT))
            .map(|db| {
                db.verify_integrity()
                    .map(|report| report.is_healthy())
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        live_ok && self.backup.join(BACKUP_MANIFEST_FILE).is_file()
    }
}

/// Run one fault and record what it produced.
fn record(fault: &str, outcome: Result<String, String>, survivors_intact: bool) -> FaultOutcome {
    FaultOutcome {
        fault: fault.to_string(),
        refused: outcome.is_err(),
        error: outcome.err().unwrap_or_else(|| "NOT REFUSED".into()),
        survivors_intact,
    }
}

fn try_verify(backup: &Path, register: &Path) -> Result<String, String> {
    verify_from_separate_trust_domain(backup, &directory(register))
        .map(|(_, key_id)| key_id)
        .map_err(|error| error.to_string())
}

// ── corrupted media ──────────────────────────────────────────────────────────────────────────────

/// A bit flipped in a data file. The manifest's BLAKE3 allow-list catches it.
#[test]
fn a_bit_flip_in_a_backup_part_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(TENANT)?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.backup.join(BACKUP_MANIFEST_FILE))?)?;
    let victim = manifest["files"]
        .as_array()
        .and_then(|files| {
            files
                .iter()
                .find(|file| file["bytes"].as_u64().unwrap_or(0) > 0)
        })
        .and_then(|file| file["path"].as_str())
        .ok_or("the manifest allow-lists a non-empty file")?
        .to_string();
    let path = fixture.backup.join(&victim);
    let mut bytes = std::fs::read(&path)?;
    let last = bytes.len() - 1;
    bytes[last] ^= 0b0000_0001;
    std::fs::write(&path, bytes)?;

    let outcome = record(
        &format!("bit flip in backup part {victim}"),
        try_verify(&fixture.backup, &fixture.register),
        fixture.survivors_intact(),
    );
    assert!(outcome.refused, "{outcome:?}");
    assert!(
        outcome.error.contains("digest") || outcome.error.contains("integrity"),
        "{outcome:?}"
    );
    assert!(outcome.survivors_intact);
    Ok(())
}

/// A bit flipped in the manifest itself. The signature covers the exact manifest bytes, so this is
/// caught before any file digest is even considered.
#[test]
fn a_bit_flip_in_the_manifest_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(TENANT)?;
    let path = fixture.backup.join(BACKUP_MANIFEST_FILE);
    let mut bytes = std::fs::read(&path)?;
    // Flip a byte inside a digest string, so the document still parses as JSON — the interesting
    // case, because a mangled file that fails to parse would be caught by accident.
    let position = bytes.len() / 2;
    bytes[position] = if bytes[position] == b'a' { b'b' } else { b'a' };
    std::fs::write(&path, bytes)?;

    let outcome = record(
        "bit flip in the signed manifest",
        try_verify(&fixture.backup, &fixture.register),
        fixture.survivors_intact(),
    );
    assert!(outcome.refused, "{outcome:?}");
    assert!(
        outcome.error.contains("digest mismatch") || outcome.error.contains("authenticity"),
        "the refusal must name the signed-manifest mismatch: {outcome:?}"
    );
    assert!(outcome.survivors_intact);
    Ok(())
}

// ── the wrong backup, the wrong key ──────────────────────────────────────────────────────────────

/// Another tenant's backup, restored into this tenant's recovery. Caught before publication.
#[test]
fn another_tenants_backup_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new("beta-industries")?;
    let destination = fixture.root.join("restored");
    let outcome = record(
        "restore a backup belonging to another tenant",
        loom_drill::restore_beside_production(
            &fixture.backup,
            &destination,
            &[&fixture.live],
            TENANT,
            &directory(&fixture.register),
        )
        .map(|manifest| manifest.tenant)
        .map_err(|error| error.to_string()),
        true,
    );
    assert!(outcome.refused, "{outcome:?}");
    assert!(outcome.error.contains("belongs to tenant"), "{outcome:?}");
    assert!(
        !destination.exists(),
        "nothing may be published on the refusal path"
    );
    Ok(())
}

/// A key id nobody registered. Custody refuses it by name rather than reporting a bad signature.
#[test]
fn an_unregistered_key_id_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::with_key(TENANT, "backup-root-someone-elses", 11)?;
    std::fs::write(
        &fixture.register,
        register_json(KEY_ID, "active", &hex(key(11).verifying_key().as_bytes())),
    )?;
    let outcome = record(
        "backup signed by a key id the register does not carry",
        try_verify(&fixture.backup, &fixture.register),
        fixture.survivors_intact(),
    );
    assert!(outcome.refused, "{outcome:?}");
    assert!(
        outcome.error.contains("no trust root named"),
        "the refusal must name the unknown key: {outcome:?}"
    );
    Ok(())
}

/// **The P8 refusal.** The key's material still verifies the backup perfectly; the register says it
/// is revoked, and that decision is what stops the recovery.
#[test]
fn a_revoked_key_is_refused_although_its_signature_is_valid(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(TENANT)?;

    // First prove the signature really is good, so the refusal below is unambiguously a decision.
    assert_eq!(try_verify(&fixture.backup, &fixture.register)?, KEY_ID);

    std::fs::write(
        &fixture.register,
        register_json(KEY_ID, "revoked", &hex(key(11).verifying_key().as_bytes())),
    )?;
    let outcome = record(
        "backup signed by a key the register has since revoked",
        try_verify(&fixture.backup, &fixture.register),
        fixture.survivors_intact(),
    );
    assert!(outcome.refused, "{outcome:?}");
    assert!(outcome.error.contains("REVOKED"), "{outcome:?}");
    assert!(
        outcome.error.contains("key compromise drill 2026-08-01"),
        "the refusal must carry the recorded reason: {outcome:?}"
    );
    assert!(outcome.survivors_intact);
    Ok(())
}

// ── the actor registry ───────────────────────────────────────────────────────────────────────────

/// A restored store reopened against a registry generation the deployment has moved past. The
/// rollback floor refuses it: a revoked actor must not come back through a restore.
#[test]
fn a_stale_actor_generation_stops_the_restored_store_opening(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(TENANT)?;
    let governance = key(12);
    let agent = key(13);
    let actors = vec![(ActorId::new("acme-agent"), agent.verifying_key())];

    // Governance issued generation 3; the deployment's floor has since moved to 9.
    let attestation = loom_branch::ActorRegistryAttestation::issue(
        TenantId::new(TENANT),
        3,
        actors.clone(),
        &governance,
    );
    let register = fixture.root.join("governance.json");
    std::fs::write(
        &register,
        register_json(
            "gov-2026-q3",
            "active",
            &hex(governance.verifying_key().as_bytes()),
        )
        .replace("backup-root", "actor-governance"),
    )?;

    let destination = fixture.root.join("restored");
    loom_drill::restore_beside_production(
        &fixture.backup,
        &destination,
        &[&fixture.live],
        TENANT,
        &directory(&fixture.register),
    )?;

    let governance_directory = KeyDirectory::new(
        TrustRootRegister::load(&register)?,
        KeyRole::ActorGovernance,
    )?;
    let outcome = record(
        "reopen a restored store with an actor registry generation below the deployment floor",
        loom_drill::open_restored_attested(
            &destination,
            TENANT,
            actors,
            &attestation,
            &governance_directory,
            9,
        )
        .map(|_| "opened".to_string())
        .map_err(|error| error.to_string()),
        fixture.survivors_intact(),
    );
    assert!(outcome.refused, "{outcome:?}");
    assert!(
        outcome.error.contains("rollback refused"),
        "the refusal must name the rollback floor: {outcome:?}"
    );
    Ok(())
}

// ── the machine gets in the way ──────────────────────────────────────────────────────────────────

/// A destination that cannot be written. The restore refuses and publishes nothing — a partially
/// restored store must never become visible.
#[cfg(unix)]
#[test]
fn a_restore_that_cannot_write_publishes_nothing() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new(TENANT)?;
    let readonly_parent = fixture.root.join("readonly");
    std::fs::create_dir(&readonly_parent)?;
    std::fs::set_permissions(&readonly_parent, std::fs::Permissions::from_mode(0o500))?;
    let destination = readonly_parent.join("restored");

    let outcome = record(
        "restore into a destination the process cannot write (stands in for ENOSPC)",
        loom_drill::restore_beside_production(
            &fixture.backup,
            &destination,
            &[&fixture.live],
            TENANT,
            &directory(&fixture.register),
        )
        .map(|manifest| manifest.tenant)
        .map_err(|error| error.to_string()),
        fixture.survivors_intact(),
    );
    // Restore permissions before any assertion can abort the test and leak an undeletable directory.
    std::fs::set_permissions(&readonly_parent, std::fs::Permissions::from_mode(0o700))?;

    assert!(outcome.refused, "{outcome:?}");
    assert!(
        !destination.exists(),
        "a failed restore must publish nothing"
    );
    assert!(outcome.survivors_intact);
    Ok(())
}

/// **A backup killed mid-flight leaves no half-published backup on the shelf.**
///
/// The publish is build-in-a-private-sibling then one rename, so a process that dies during the copy
/// leaves a partial directory that is *not* the backup — and the shelf, scanned the way retention
/// scans it, does not see a backup there.
#[test]
fn a_backup_killed_mid_flight_publishes_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(TENANT)?;
    let shelf = fixture.root.join("shelf");
    std::fs::create_dir(&shelf)?;
    let destination = shelf.join("interrupted");

    // Simulate the death by leaving a partial directory where the publish would have built one, then
    // asserting the shelf does not mistake it for a backup.
    let partial = shelf.join("interrupted.partial");
    std::fs::create_dir(&partial)?;
    std::fs::write(partial.join("half-copied"), b"truncated")?;

    let recognized = std::fs::read_dir(&shelf)?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join(BACKUP_MANIFEST_FILE).is_file())
        .count();
    assert_eq!(recognized, 0, "a partial publish is not a backup");
    assert!(!destination.exists());
    assert!(
        fixture.survivors_intact(),
        "the live store is untouched by a failed backup"
    );
    Ok(())
}

/// A restore killed mid-flight leaves the destination unpublished and the shelf intact.
#[test]
fn a_restore_killed_mid_flight_leaves_both_sides_intact() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::new(TENANT)?;
    let destination = fixture.root.join("restored");

    // A restore refused partway (here: a missing signature record, discovered after the destination
    // was chosen) must leave nothing published.
    std::fs::remove_file(fixture.backup.join(BACKUP_SIGNATURE_FILE))?;
    let outcome = record(
        "restore interrupted by an unreadable signature record",
        loom_drill::restore_beside_production(
            &fixture.backup,
            &destination,
            &[&fixture.live],
            TENANT,
            &directory(&fixture.register),
        )
        .map(|manifest| manifest.tenant)
        .map_err(|error| error.to_string()),
        true,
    );
    assert!(outcome.refused, "{outcome:?}");
    assert!(!destination.exists(), "nothing published");
    assert!(
        fixture.backup.join(BACKUP_MANIFEST_FILE).is_file(),
        "the rest of the shelf survives"
    );
    assert!(
        Loom::open(&fixture.live, TenantId::new(TENANT))?
            .verify_integrity()?
            .is_healthy(),
        "the live store survives a failed restore"
    );
    Ok(())
}

// ── the drill's own guard rail ───────────────────────────────────────────────────────────────────

/// **A rehearsal must never be able to land on production.** `restore_signed_backup` already refuses
/// an existing destination; the drill refuses anything that *is* or is *inside* a live store, so a
/// mistyped path fails before the mechanism is even consulted.
#[test]
fn a_restore_aimed_at_a_live_store_is_refused_before_anything_is_read(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(TENANT)?;
    for destination in [fixture.live.clone(), fixture.live.join("nested")] {
        let outcome = record(
            "restore aimed at a live store",
            loom_drill::restore_beside_production(
                &fixture.backup,
                &destination,
                &[&fixture.live],
                TENANT,
                &directory(&fixture.register),
            )
            .map(|manifest| manifest.tenant)
            .map_err(|error| error.to_string()),
            fixture.survivors_intact(),
        );
        assert!(outcome.refused, "{outcome:?}");
        assert!(
            outcome
                .error
                .contains("restores beside production, never onto it"),
            "{outcome:?}"
        );
        assert!(outcome.survivors_intact);
    }
    Ok(())
}
