//! Phase 3 operational gate: online backup/restore is a consistent, verified prefix.

use loom_branch::{restore_backup, verify_backup, BackupError, Loom};
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
