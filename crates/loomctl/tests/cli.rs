use loom_branch::Loom;
use loom_core::{ActorId, Record, SessionId, TenantId, Value, WriteEnvelope};
use std::process::{Command, Output};

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_loomctl"))
        .args(arguments)
        .output()
        .expect("loomctl must execute")
}

#[test]
fn operator_can_inspect_verify_backup_and_restore_without_overwriting(
) -> Result<(), Box<dyn std::error::Error>> {
    let parent = tempfile::tempdir()?;
    let source = parent.path().join("source");
    let backup = parent.path().join("backup");
    let restored = parent.path().join("restored");
    let tenant = TenantId::new("acme");
    {
        let db = Loom::open(&source, tenant)?;
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
                "seed operator smoke test",
            ),
        )?;
    }

    let inspect = run(&[
        "inspect",
        "--path",
        source.to_str().ok_or("source path is not UTF-8")?,
        "--tenant",
        "acme",
    ]);
    assert!(inspect.status.success(), "{inspect:?}");
    let inspection: serde_json::Value = serde_json::from_slice(&inspect.stdout)?;
    assert_eq!(inspection["healthy_to_open"], true);
    assert_eq!(inspection["branch_count"], 2);

    let verify = run(&[
        "verify",
        "--path",
        source.to_str().ok_or("source path is not UTF-8")?,
        "--tenant",
        "acme",
    ]);
    assert!(verify.status.success(), "{verify:?}");
    let verification: serde_json::Value = serde_json::from_slice(&verify.stdout)?;
    assert_eq!(verification["healthy"], true);

    let backup_result = run(&[
        "backup",
        "--path",
        source.to_str().ok_or("source path is not UTF-8")?,
        "--tenant",
        "acme",
        "--out",
        backup.to_str().ok_or("backup path is not UTF-8")?,
    ]);
    assert!(backup_result.status.success(), "{backup_result:?}");

    let verify_backup = run(&[
        "verify-backup",
        "--path",
        backup.to_str().ok_or("backup path is not UTF-8")?,
    ]);
    assert!(verify_backup.status.success(), "{verify_backup:?}");

    let wrong_tenant = run(&[
        "restore",
        "--path",
        backup.to_str().ok_or("backup path is not UTF-8")?,
        "--expected-tenant",
        "other",
        "--out",
        restored.to_str().ok_or("restore path is not UTF-8")?,
    ]);
    assert!(!wrong_tenant.status.success());
    assert!(!restored.exists());

    let restore = run(&[
        "restore",
        "--path",
        backup.to_str().ok_or("backup path is not UTF-8")?,
        "--expected-tenant",
        "acme",
        "--out",
        restored.to_str().ok_or("restore path is not UTF-8")?,
    ]);
    assert!(restore.status.success(), "{restore:?}");

    let overwrite = run(&[
        "restore",
        "--path",
        backup.to_str().ok_or("backup path is not UTF-8")?,
        "--expected-tenant",
        "acme",
        "--out",
        restored.to_str().ok_or("restore path is not UTF-8")?,
    ]);
    assert!(!overwrite.status.success());
    Ok(())
}
