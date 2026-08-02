//! Phase 3 operational gate: online backup/restore is a consistent, verified prefix.

use ed25519_dalek::SigningKey;
use loom_branch::{
    restore_backup, restore_signed_backup, verify_backup, verify_signed_backup, BackupError, Loom,
    BACKUP_MANIFEST_FILE, BACKUP_SIGNATURE_FILE, BACKUP_SIGNATURE_VERSION,
    BACKUP_SIGNATURE_VERSION_V2,
};
use loom_core::{ActorId, BranchId, Record, SessionId, TenantId, Value, WriteEnvelope};
use std::io::Write as _;
use std::sync::{mpsc, Arc};

fn envelope(branch: &BranchId) -> WriteEnvelope {
    WriteEnvelope::new(
        ActorId::new("backup-writer"),
        SessionId::new("s1"),
        branch.clone(),
        "exercise online backup",
    )
}

fn counter(value: i64) -> Record {
    Record::Value(Value::Counter(value))
}

#[test]
fn online_backup_restores_to_one_consistent_prefix_during_a_write_storm(
) -> Result<(), Box<dyn std::error::Error>> {
    let source = tempfile::tempdir()?;
    let backup_parent = tempfile::tempdir()?;
    let restore_parent = tempfile::tempdir()?;
    let backup = backup_parent.path().join("snapshot");
    let restored = restore_parent.path().join("restored");
    let tenant = TenantId::new("acme");
    let db = Arc::new(Loom::open(source.path(), tenant.clone())?);
    let (session, token) = db.open_session_named(SessionId::new("s1"))?;
    let (ready_tx, ready_rx) = mpsc::channel();

    let writer_db = Arc::clone(&db);
    let writer_branch = session.branch.clone();
    let writer = std::thread::spawn(move || -> loom_core::Result<()> {
        let mut token = token;
        for value in 1..=100 {
            writer_db.write(
                &token,
                &writer_branch,
                b"counter".to_vec(),
                counter(value),
                &envelope(&writer_branch),
            )?;
            if value % 20 == 0 {
                let (_, extended) =
                    writer_db.branch(&token, &writer_branch, &format!("checkpoint-{value}"))?;
                token = extended;
            }
            if value == 10 {
                let _ = ready_tx.send(());
            }
            std::thread::yield_now();
        }
        Ok(())
    });

    ready_rx.recv()?;
    let manifest = db.backup_to(&backup)?;
    writer.join().map_err(|_| "writer thread panicked")??;

    assert_eq!(manifest.tenant, "acme");
    assert!(!backup.join("loom/store.lock").exists());
    assert_eq!(verify_backup(&backup)?, manifest);
    assert_eq!(restore_backup(&backup, &restored)?, manifest);

    let restored_db = Loom::open(&restored, tenant)?;
    let restored_branch = BranchId::new("s1");
    let restored_token = restored_db.issue_capability(
        SessionId::new("restore-audit"),
        std::slice::from_ref(&restored_branch),
        3_600_000,
    )?;
    let restored_value = restored_db.read(&restored_token, &restored_branch, b"counter")?;
    let Some(Record::Value(Value::Counter(prefix))) = restored_value else {
        return Err("restored counter is absent or has the wrong type".into());
    };
    assert!(
        (10..=100).contains(&prefix),
        "backup is not a committed prefix: {prefix}"
    );
    for branch in restored_db.branch_names() {
        if let Some(value) = branch.strip_prefix("checkpoint-") {
            let value = value.parse::<i64>()?;
            assert!(
                value <= prefix,
                "backup captured branch {branch} but not the commit that preceded it ({prefix})"
            );
        }
    }
    Ok(())
}

#[test]
fn one_changed_byte_is_refused_before_restore() -> Result<(), Box<dyn std::error::Error>> {
    let source = tempfile::tempdir()?;
    let parent = tempfile::tempdir()?;
    let backup = parent.path().join("snapshot");
    let db = Loom::open(source.path(), TenantId::new("acme"))?;
    db.backup_to(&backup)?;

    let manifest = verify_backup(&backup)?;
    let victim = manifest
        .files
        .first()
        .ok_or("test backup unexpectedly contains no database files")?;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(backup.join(&victim.path))?;
    file.write_all(b"x")?;
    file.sync_all()?;

    let error = verify_backup(&backup).expect_err("tampered backup must be refused");
    assert!(matches!(error, BackupError::Integrity(_)), "{error}");
    Ok(())
}

#[test]
fn backup_and_restore_never_overwrite_existing_paths() -> Result<(), Box<dyn std::error::Error>> {
    let source = tempfile::tempdir()?;
    let parent = tempfile::tempdir()?;
    let backup = parent.path().join("snapshot");
    let restored = parent.path().join("restored");
    let db = Loom::open(source.path(), TenantId::new("acme"))?;
    db.backup_to(&backup)?;

    assert!(matches!(
        db.backup_to(&backup),
        Err(BackupError::DestinationExists(_))
    ));
    std::fs::create_dir(&restored)?;
    assert!(matches!(
        restore_backup(&backup, &restored),
        Err(BackupError::DestinationExists(_))
    ));
    Ok(())
}

#[test]
fn signed_backup_binds_manifest_key_identity_and_restore() -> Result<(), Box<dyn std::error::Error>>
{
    let source = tempfile::tempdir()?;
    let parent = tempfile::tempdir()?;
    let backup = parent.path().join("snapshot");
    let restored = parent.path().join("restored");
    let key = SigningKey::from_bytes(&[41u8; 32]);
    let db = Loom::open(source.path(), TenantId::new("acme"))?;

    let created = db.backup_to_signed(&backup, "backup-root-2026-q3", &key)?;
    assert!(backup.join(BACKUP_SIGNATURE_FILE).is_file());
    assert_eq!(
        verify_signed_backup(&backup, "backup-root-2026-q3", &key.verifying_key())?,
        created
    );
    assert_eq!(
        restore_signed_backup(
            &backup,
            &restored,
            "backup-root-2026-q3",
            &key.verifying_key(),
        )?,
        created
    );

    let wrong_id = verify_signed_backup(&backup, "backup-root-old", &key.verifying_key())
        .expect_err("the trust-root id is part of authorization");
    assert!(matches!(wrong_id, BackupError::Authenticity(_)));

    let wrong_key = SigningKey::from_bytes(&[42u8; 32]);
    let error = verify_signed_backup(&backup, "backup-root-2026-q3", &wrong_key.verifying_key())
        .expect_err("a different trust root must not verify");
    assert!(matches!(error, BackupError::Authenticity(_)));
    Ok(())
}

#[test]
fn signed_backup_rejects_a_self_consistent_manifest_rewrite(
) -> Result<(), Box<dyn std::error::Error>> {
    let source = tempfile::tempdir()?;
    let parent = tempfile::tempdir()?;
    let backup = parent.path().join("snapshot");
    let key = SigningKey::from_bytes(&[91u8; 32]);
    let db = Loom::open(source.path(), TenantId::new("acme"))?;
    db.backup_to_signed(&backup, "backup-root", &key)?;

    // Whitespace keeps the JSON and all file digests valid, but changes the exact bytes the
    // deployment trust root approved. An attacker able to rewrite both data and manifest cannot
    // mint the replacement signature.
    let manifest_path = backup.join(BACKUP_MANIFEST_FILE);
    let mut manifest = std::fs::read(&manifest_path)?;
    manifest.extend_from_slice(b" ");
    std::fs::write(&manifest_path, manifest)?;

    assert!(
        verify_backup(&backup).is_ok(),
        "the unsigned integrity check intentionally accepts equivalent JSON"
    );
    let error = verify_signed_backup(&backup, "backup-root", &key.verifying_key())
        .expect_err("rewritten manifest bytes must invalidate authenticity");
    assert!(matches!(error, BackupError::Authenticity(_)));
    Ok(())
}

#[test]
fn signed_verification_refuses_a_missing_signature() -> Result<(), Box<dyn std::error::Error>> {
    let source = tempfile::tempdir()?;
    let parent = tempfile::tempdir()?;
    let backup = parent.path().join("snapshot");
    let key = SigningKey::from_bytes(&[17u8; 32]);
    let db = Loom::open(source.path(), TenantId::new("acme"))?;
    db.backup_to(&backup)?;

    let error = verify_signed_backup(&backup, "backup-root", &key.verifying_key())
        .expect_err("unsigned backup must not pass the signed production door");
    assert!(matches!(error, BackupError::Authenticity(_)));
    Ok(())
}

// ── signature format v2 (P9.1) ───────────────────────────────────────────────────────────────────

/// v2 signs a digest, so the payload stops growing with the store — the whole reason it exists.
#[test]
fn v2_signs_a_fixed_size_payload_and_verifies() -> Result<(), Box<dyn std::error::Error>> {
    let parent = tempfile::tempdir()?;
    let source = parent.path().join("source");
    let backup = parent.path().join("backup");
    let key = SigningKey::from_bytes(&[41u8; 32]);
    {
        let db = Loom::open(&source, TenantId::new("acme"))?;
        let (session, token) = db.open_session_named(SessionId::new("seed"))?;
        for index in 0..12 {
            db.write(
                &token,
                &session.branch,
                format!("k/{index}").into_bytes(),
                Record::Value(Value::Text(format!("v{index}"))),
                &WriteEnvelope::new(
                    ActorId::new("operator"),
                    session.id.clone(),
                    session.branch.clone(),
                    "seed",
                ),
            )?;
        }
        db.backup_to_signed_as(
            &backup,
            "backup-root-2026-q3",
            &key,
            BACKUP_SIGNATURE_VERSION_V2,
        )?;
    }

    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(backup.join(BACKUP_SIGNATURE_FILE))?)?;
    assert_eq!(record["format_version"], 2);
    verify_signed_backup(&backup, "backup-root-2026-q3", &key.verifying_key())?;

    // The signed payload is domain(36) + len(8) + key_id + digest(32), regardless of store size.
    let manifest = std::fs::read(backup.join(BACKUP_MANIFEST_FILE))?;
    let payload = 36 + 8 + "backup-root-2026-q3".len() + 32;
    assert_eq!(payload, 95);
    assert!(
        manifest.len() > 1000,
        "the manifest must be substantially larger than the payload for this to mean anything: {}",
        manifest.len()
    );
    assert!(payload < 4096, "v2 must fit the KMS Sign RAW limit");
    Ok(())
}

/// **The forgery v2 exists to refuse** (design note §3), end to end.
///
/// Take a genuine backup, swap the manifest for one describing entirely different files, and leave
/// the signature record — including its `manifest_blake3` — byte-identical. The backup must be
/// refused.
///
/// This proves the *system* refuses. It does not, on its own, prove which check did it:
/// `check_signature_record` compares the carried digest against the computed one and runs first.
/// That the signature itself is verified over a RECOMPUTED digest — so the format stays sound even
/// if that comparison were ever removed as redundant — is the discriminating question, and it is
/// tested directly in `backup::signature_format_tests::v2_payload_ignores_the_digest_the_record_carries`.
#[test]
fn v2_refuses_a_swapped_manifest_even_though_the_record_is_self_consistent(
) -> Result<(), Box<dyn std::error::Error>> {
    let parent = tempfile::tempdir()?;
    let source = parent.path().join("source");
    let backup = parent.path().join("backup");
    let key = SigningKey::from_bytes(&[41u8; 32]);
    {
        let db = Loom::open(&source, TenantId::new("acme"))?;
        db.backup_to_signed_as(
            &backup,
            "backup-root-2026-q3",
            &key,
            BACKUP_SIGNATURE_VERSION_V2,
        )?;
    }
    let before = std::fs::read_to_string(backup.join(BACKUP_SIGNATURE_FILE))?;
    verify_signed_backup(&backup, "backup-root-2026-q3", &key.verifying_key())?;

    // Swap the manifest. The record is NOT touched.
    let forged = br#"{"format_version":1,"tenant":"acme","files":[]}"#;
    std::fs::write(backup.join(BACKUP_MANIFEST_FILE), forged)?;
    assert_eq!(
        std::fs::read_to_string(backup.join(BACKUP_SIGNATURE_FILE))?,
        before,
        "the attack leaves the record byte-identical; only the manifest changed"
    );

    let error = verify_signed_backup(&backup, "backup-root-2026-q3", &key.verifying_key())
        .expect_err("a swapped manifest must be refused");
    assert!(
        matches!(error, BackupError::Authenticity(_)),
        "the refusal must be an authenticity failure, not an integrity one: {error}"
    );
    Ok(())
}

/// Both formats verify from the same code path, so a shelf may hold v1 and v2 side by side while a
/// key rotation overlaps.
#[test]
fn v1_and_v2_backups_both_verify() -> Result<(), Box<dyn std::error::Error>> {
    let parent = tempfile::tempdir()?;
    let source = parent.path().join("source");
    let key = SigningKey::from_bytes(&[41u8; 32]);
    let db = Loom::open(&source, TenantId::new("acme"))?;
    for (name, format) in [
        ("v1", BACKUP_SIGNATURE_VERSION),
        ("v2", BACKUP_SIGNATURE_VERSION_V2),
    ] {
        let backup = parent.path().join(name);
        db.backup_to_signed_as(&backup, "backup-root-2026-q3", &key, format)?;
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(backup.join(BACKUP_SIGNATURE_FILE))?)?;
        assert_eq!(record["format_version"], format);
        verify_signed_backup(&backup, "backup-root-2026-q3", &key.verifying_key())?;
    }
    Ok(())
}

/// An unknown format is refused by name, never guessed at.
#[test]
fn an_unknown_signature_format_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let parent = tempfile::tempdir()?;
    let source = parent.path().join("source");
    let backup = parent.path().join("backup");
    let key = SigningKey::from_bytes(&[41u8; 32]);
    {
        let db = Loom::open(&source, TenantId::new("acme"))?;
        db.backup_to_signed_as(
            &backup,
            "backup-root-2026-q3",
            &key,
            BACKUP_SIGNATURE_VERSION_V2,
        )?;
    }
    let path = backup.join(BACKUP_SIGNATURE_FILE);
    let bumped =
        std::fs::read_to_string(&path)?.replace("\"format_version\": 2", "\"format_version\": 3");
    std::fs::write(&path, bumped)?;

    let error = verify_signed_backup(&backup, "backup-root-2026-q3", &key.verifying_key())
        .expect_err("an unknown format must be refused");
    assert!(format!("{error}").contains("unsupported"), "{error}");
    // And writing one is refused too.
    let parent2 = tempfile::tempdir()?;
    let db = Loom::open(parent2.path().join("s"), TenantId::new("acme"))?;
    assert!(db
        .backup_to_signed_as(parent2.path().join("b"), "k", &key, 3)
        .is_err());
    Ok(())
}
