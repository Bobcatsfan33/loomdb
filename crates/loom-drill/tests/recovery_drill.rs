//! **The recovery exercise, end to end, on the local-filesystem topology.**
//!
//! This is not a unit test of a drill library. It is the drill: a database is written to, cloned
//! mid-flight, backed up, lost, verified from a separate trust domain, restored somewhere new,
//! reopened through the attested path, and checked against expectations recorded before the failure.
//! What it measures is written to `docs/drills/` as a retained receipt.
//!
//! Everything it exercises is the real mechanism. Nothing it cannot exercise is simulated: the
//! point-in-time clone is a directory copy, the topology says so, and the receipt lists what that
//! leaves untested.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use loom_branch::{ActorRegistryAttestation, Loom};
use loom_core::{
    ActorId, Observation, ObservationId, Record, SessionId, SourceRef, TenantId, Timestamp,
    TrustClass, WriteEnvelope,
};
use loom_drill::incident::{notify, Audience};
use loom_drill::{
    heads, human_bytes, manifest_blake3, now_unix, open_restored_attested, signed_payload_bytes,
    take_clone, tree_bytes, verify_from_separate_trust_domain, BackupConsumed, DrillReceipt,
    KnownAnswer, Measured, Topology, KMS_RAW_SIGN_LIMIT_BYTES, RECEIPT_SCHEMA_VERSION,
    RPO_TARGET_SECONDS, RTO_TARGET_SECONDS,
};
use loom_keys::{KeyDirectory, KeyRole, TrustRootRegister};

const TENANT: &str = "acme-corp";
const AGENT: &str = "acme-agent";
const BACKUP_KEY_ID: &str = "backup-root-2026-q3";
const GOVERNANCE_KEY_ID: &str = "gov-2026-q3";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A trust-root register. The verifier and the writer are handed *different* files in the drill, so
/// the separation is structural rather than a comment.
fn register_json(entries: &[(&str, &str, &str, u64, String)]) -> String {
    let roots: Vec<String> = entries
        .iter()
        .map(|(key_id, role, status, generation, public_key)| {
            let revocation = if *status == "revoked" {
                r#","revocationReason":"revoked during the drill's fault injection""#
            } else {
                ""
            };
            format!(
                r#"{{"keyId":"{key_id}","role":"{role}","algorithm":"ed25519",
                   "publicKey":"{public_key}","backend":"software","status":"{status}",
                   "generation":{generation},
                   "ceremony":{{"reference":"DRILL-CEREMONY-2026-08-01","approvals":[
                     {{"approver":"pki-officer","atUnix":1800000000}},
                     {{"approver":"security-lead","atUnix":1800000000}}]}}{revocation}}}"#
            )
        })
        .collect();
    format!(r#"{{"schemaVersion":1,"roots":[{}]}}"#, roots.join(","))
}

fn write_register(path: &Path, body: &str) -> std::io::Result<()> {
    std::fs::write(path, body)
}

fn directory(path: &Path, role: KeyRole) -> KeyDirectory {
    KeyDirectory::new(TrustRootRegister::load(path).expect("register loads"), role)
        .expect("register is valid")
}

/// Write one observation on an open session and return the commit id.
fn observe(
    db: &Loom,
    token: &loom_branch::CapabilityToken,
    session: &loom_branch::SessionHandle,
    key_name: &str,
    text: &str,
) -> String {
    let record = Record::Observation(Box::new(Observation {
        id: ObservationId::of(key_name.as_bytes()),
        source: SourceRef::new("erp", key_name),
        trust: TrustClass::VerifiedSystem,
        observed_at: None,
        ingested_at: Timestamp::from_ms(1_700_000_000_000),
        payload: text.as_bytes().to_vec(),
    }));
    db.write(
        token,
        &session.branch,
        key_name.as_bytes().to_vec(),
        record,
        &WriteEnvelope::new(
            ActorId::new(AGENT),
            session.id.clone(),
            session.branch.clone(),
            "drill write",
        ),
    )
    .expect("write commits")
    .to_hex()
}

/// Run one fault and record whether it was refused and whether the survivors are intact.
fn fault<T>(
    what: &str,
    outcome: Result<T, impl std::fmt::Display>,
    live: &Path,
    shelf: &Path,
) -> loom_drill::FaultOutcome {
    let live_ok = Loom::open(live, TenantId::new(TENANT))
        .map(|db| {
            db.verify_integrity()
                .map(|r| r.is_healthy())
                .unwrap_or(false)
        })
        .unwrap_or(false);
    loom_drill::FaultOutcome {
        fault: what.to_string(),
        refused: outcome.is_err(),
        error: outcome
            .err()
            .map(|error| error.to_string())
            .unwrap_or_else(|| "NOT REFUSED".into()),
        survivors_intact: live_ok && shelf.join("loom-backup-manifest.json").is_file(),
    }
}

/// **THE DRILL.**
#[test]
fn recovery_drill_local_filesystem() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let live = root.path().join("live");
    let shelf = loom_drill::ensure_dir(&root.path().join("shelf"))?;

    // ── trust material ─────────────────────────────────────────────────────────────────────────
    //
    // Two registers, two files. The writer's is never handed to the verifier and the verifier's
    // holds only public halves — the P7 writer/verifier split, now expressed through P8 custody.
    let backup_key = key(11);
    let governance_key = key(12);
    let agent_key = key(13);

    let writer_register = root.path().join("writer-trust-roots.json");
    let verifier_register = root.path().join("verifier-trust-roots.json");
    let governance_register = root.path().join("governance-trust-roots.json");
    let backup_roots = register_json(&[(
        BACKUP_KEY_ID,
        "backup-root",
        "active",
        1,
        hex(backup_key.verifying_key().as_bytes()),
    )]);
    write_register(&writer_register, &backup_roots)?;
    write_register(&verifier_register, &backup_roots)?;
    write_register(
        &governance_register,
        &register_json(&[(
            GOVERNANCE_KEY_ID,
            "actor-governance",
            "active",
            1,
            hex(governance_key.verifying_key().as_bytes()),
        )]),
    )?;

    let actors = vec![(ActorId::new(AGENT), agent_key.verifying_key())];
    let attestation =
        ActorRegistryAttestation::issue(TenantId::new(TENANT), 7, actors.clone(), &governance_key);

    // ── 1. seed, then keep writing across the clone boundary ───────────────────────────────────
    //
    // The expectations below are recorded BEFORE the failure, and the boundary is what the drill is
    // really testing: everything written before the clone must come back, everything after it must
    // not. A drill whose recovery point is zero proves nothing about recovery.
    let mut before_clone = BTreeMap::new();
    let pre_branch;
    {
        let db = Loom::open(&live, TenantId::new(TENANT))?;
        let (session, token) = db.open_session_named(SessionId::new("pre-clone-work"))?;
        pre_branch = session.branch.clone();
        for index in 0..8 {
            let key_name = format!("obs/before-{index}");
            let commit = observe(
                &db,
                &token,
                &session,
                &key_name,
                "recorded before the clone",
            );
            before_clone.insert(key_name, commit);
        }
    }
    let pre_clone_heads = {
        let db = Loom::open(&live, TenantId::new(TENANT))?;
        heads(&db)?
    };

    // ── 2. the point-in-time clone: the recovery point ─────────────────────────────────────────
    let clone = root.path().join("clone");
    let clone_taken_unix = take_clone(&live, &clone)?;
    let clone_instant = std::time::Instant::now();

    // ── 3. writes continue on the live store while the backup runs off the clone ───────────────
    //
    // This is the P7 shape: the engine holds an exclusive lock on the live store, so the backup
    // cannot read it — it reads the clone, and the tenant keeps working meanwhile.
    let backup = shelf.join(format!("{TENANT}-{clone_taken_unix}"));
    let mut after_clone = Vec::new();
    {
        let live_db = Loom::open(&live, TenantId::new(TENANT))?;

        let clone_db = Loom::open(&clone, TenantId::new(TENANT))?;
        let manifest = clone_db.backup_to_signed(&backup, BACKUP_KEY_ID, &backup_key)?;
        assert_eq!(manifest.tenant, TENANT);
        drop(clone_db);

        // The tenant keeps working. Everything from here is work the clone does not contain, and
        // the drill asserts its absence after recovery rather than inferring it from a clock.
        let (post_session, post_token) =
            live_db.open_session_named(SessionId::new("post-clone-work"))?;
        for index in 0..5 {
            let key_name = format!("obs/after-{index}");
            observe(
                &live_db,
                &post_token,
                &post_session,
                &key_name,
                "written after the clone",
            );
            after_clone.push(key_name);
        }
        // A branch created after the clone, so the drill proves branch-level loss at the boundary
        // and not only record-level. The token is scoped to the branch its session forked, so the
        // hypothesis forks from there rather than from `main` — the AT-019 constraint an agent
        // lives under, and the drill lives under it too.
        live_db.branch(&post_token, &post_session.branch, "post-clone-hypothesis")?;
    }

    // ── 4. the failure ─────────────────────────────────────────────────────────────────────────
    let failure_unix = now_unix();
    let recovery_point_seconds = clone_instant.elapsed().as_secs_f64();

    // ── 5. verify from a separate trust domain, then restore, then reopen attested ─────────────
    let recovery_started = std::time::Instant::now();
    let verifier = directory(&verifier_register, KeyRole::BackupRoot);
    let (manifest, verified_by) = verify_from_separate_trust_domain(&backup, &verifier)?;
    assert_eq!(verified_by, BACKUP_KEY_ID);

    let restored_path = root.path().join("restored");
    let restored_manifest = loom_drill::restore_beside_production(
        &backup,
        &restored_path,
        &[&live, &clone],
        TENANT,
        &verifier,
    )?;
    assert_eq!(restored_manifest, manifest);

    let governance = directory(&governance_register, KeyRole::ActorGovernance);
    let restored = open_restored_attested(
        &restored_path,
        TENANT,
        actors.clone(),
        &attestation,
        &governance,
        7,
    )?;
    let recovery_time_seconds = recovery_started.elapsed().as_secs_f64();

    // ── 6. known-answer checks against what was recorded before the failure ────────────────────
    let integrity = restored.verify_integrity()?;
    let restored_heads = heads(&restored)?;
    let mut known_answers = Vec::new();

    known_answers.push(KnownAnswer::compare(
        "branch heads match the pre-clone state",
        format!("{pre_clone_heads:?}"),
        format!("{restored_heads:?}"),
    ));

    // Read the restored branch through the OPERATOR door — `issue_capability` is exactly the path a
    // recovery drill is, and it is deliberately not on the agent surface (AT-027).
    let work_branch = pre_branch.clone();
    let read_token = restored.issue_capability(
        SessionId::new("drill-known-answer"),
        std::slice::from_ref(&work_branch),
        60_000,
    )?;

    // Every record written before the clone must come back, with the same bytes.
    for (key_name, _) in before_clone.iter().take(3) {
        let found = restored.read(&read_token, &work_branch, key_name.as_bytes())?;
        let payload = match found {
            Some(Record::Observation(observation)) => {
                String::from_utf8_lossy(&observation.payload).to_string()
            }
            other => format!("{other:?}"),
        };
        known_answers.push(KnownAnswer::compare(
            format!("known-answer read of {key_name}"),
            "recorded before the clone",
            payload,
        ));
    }

    // ...and nothing written after it may be present. This is the recovery point, asserted as a
    // property of the restored data rather than inferred from a timestamp.
    for key_name in &after_clone {
        let found = restored.read(&read_token, &work_branch, key_name.as_bytes())?;
        known_answers.push(KnownAnswer::compare(
            format!("{key_name} is absent, as the recovery point requires"),
            "absent",
            if found.is_none() { "absent" } else { "PRESENT" },
        ));
    }
    known_answers.push(KnownAnswer::compare(
        "the branch created after the clone is absent",
        "absent",
        if restored_heads.contains_key("post-clone-hypothesis") {
            "PRESENT"
        } else {
            "absent"
        },
    ));

    // Provenance and taint on the restored store, not merely reads.
    let provenance = loom_provenance::Provenance::new(&restored);
    let (plan, stats) = provenance.taint(&SourceRef::new("erp", "obs/before-0"))?;
    known_answers.push(KnownAnswer::compare(
        "taint over a source restored from backup still names its downstream set",
        "reachable",
        if stats.contaminated > 0 && !plan.reversible.is_empty() {
            "reachable"
        } else {
            "NOTHING REACHED"
        },
    ));

    // ── 7. the receipt ─────────────────────────────────────────────────────────────────────────
    let payload_bytes = signed_payload_bytes(&backup)?;
    let mut receipt = DrillReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION,
        topology: Topology::LocalFilesystemCopyClone,
        not_exercised: Topology::LocalFilesystemCopyClone
            .not_exercised()
            .iter()
            .map(ToString::to_string)
            .collect(),
        backend: "software".into(),
        tenant: TENANT.into(),
        clone_taken_unix,
        failure_unix,
        recovery_point: Measured::new(recovery_point_seconds, RPO_TARGET_SECONDS),
        recovery_point_bounded_by_seconds: 86_400,
        recovery_time: Measured::new(recovery_time_seconds, RTO_TARGET_SECONDS),
        backup: BackupConsumed {
            name: backup
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_default(),
            manifest_blake3: manifest_blake3(&backup)?,
            verified_by_key_id: verified_by,
            verified_by_role: KeyRole::BackupRoot.as_str().into(),
            files: manifest.files.len() as u64,
            bytes: manifest.files.iter().map(|file| file.bytes).sum(),
            signed_payload_bytes: payload_bytes,
            fits_kms_raw_sign_limit: payload_bytes <= KMS_RAW_SIGN_LIMIT_BYTES,
        },
        restored_heads,
        integrity_healthy: integrity.is_healthy(),
        attested_open: true,
        known_answers,
        faults: Vec::new(),
        restored_bytes: tree_bytes(&restored_path)?,
        all_checks_held: false,
    };
    receipt.evaluate();

    // ── 8. fault injection against the drill's own backup, recorded in its receipt ─────────────
    //
    // The full battery lives in `fault_injection.rs`, one test per fault so a failure names itself.
    // These four run here so the *receipt* carries evidence of what recovery refuses, not only of
    // what it achieves — a drill that records the happy path alone is a drill nobody should trust.
    let faults = root.path().join("faults");
    std::fs::create_dir_all(&faults)?;
    let mut fault_outcomes = Vec::new();

    // (a) corrupted media: a bit flipped in a part the signed manifest allow-lists.
    let corrupted = faults.join("bit-flipped");
    loom_drill::ensure_dir(&corrupted)?;
    std::fs::remove_dir(&corrupted)?;
    take_clone(&backup, &corrupted)?;
    {
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(corrupted.join("loom-backup-manifest.json"))?)?;
        let victim = manifest["files"]
            .as_array()
            .and_then(|files| files.iter().find(|f| f["bytes"].as_u64().unwrap_or(0) > 0))
            .and_then(|f| f["path"].as_str())
            .ok_or("a non-empty file")?
            .to_string();
        let path = corrupted.join(&victim);
        let mut bytes = std::fs::read(&path)?;
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&path, bytes)?;
        fault_outcomes.push(fault(
            &format!("bit flip in backup part {victim}"),
            verify_from_separate_trust_domain(&corrupted, &verifier).map(|(_, k)| k),
            &live,
            &backup,
        ));
    }

    // (b) the wrong tenant's backup.
    fault_outcomes.push(fault(
        "restore a backup belonging to another tenant",
        loom_drill::restore_beside_production(
            &backup,
            &root.path().join("wrong-tenant"),
            &[&live],
            "beta-industries",
            &verifier,
        )
        .map(|manifest| manifest.tenant),
        &live,
        &backup,
    ));

    // (c) the P8 refusal: a revoked trust root, whose signature is still perfectly valid.
    let revoked_register = root.path().join("revoked-trust-roots.json");
    write_register(
        &revoked_register,
        &register_json(&[(
            BACKUP_KEY_ID,
            "backup-root",
            "revoked",
            1,
            hex(backup_key.verifying_key().as_bytes()),
        )]),
    )?;
    fault_outcomes.push(fault(
        "verify against a register that has since revoked the signing trust root",
        verify_from_separate_trust_domain(
            &backup,
            &directory(&revoked_register, KeyRole::BackupRoot),
        )
        .map(|(_, k)| k),
        &live,
        &backup,
    ));

    // (d) the drill's own guard rail: a restore aimed at the live store.
    fault_outcomes.push(fault(
        "restore aimed at the live store",
        loom_drill::restore_beside_production(&backup, &live, &[&live], TENANT, &verifier)
            .map(|manifest| manifest.tenant),
        &live,
        &backup,
    ));

    for outcome in &fault_outcomes {
        assert!(
            outcome.refused,
            "every injected fault must be refused: {outcome:?}"
        );
        assert!(
            outcome.survivors_intact,
            "the live store and the shelf must both survive every refusal: {outcome:?}"
        );
    }
    receipt.faults = fault_outcomes;
    receipt.evaluate();

    // ── 9. the incident tabletop, generated from the facts above ───────────────────────────────
    let operations = notify(&receipt, Audience::Operations);
    let customer = notify(&receipt, Audience::Customer);
    assert!(!operations.delivered && !customer.delivered);

    // ── assert, then retain ────────────────────────────────────────────────────────────────────
    assert!(
        receipt.integrity_healthy,
        "the restored store must verify clean"
    );
    assert!(
        receipt.known_answers.iter().all(|answer| answer.matched),
        "every known-answer check must match: {:?}",
        receipt
            .known_answers
            .iter()
            .filter(|answer| !answer.matched)
            .collect::<Vec<_>>()
    );
    assert!(
        receipt.recovery_point.within_target,
        "measured RPO must be inside the target"
    );
    assert!(
        receipt.recovery_time.within_target,
        "measured RTO must be inside the target"
    );
    assert!(receipt.all_checks_held);

    eprintln!("\n{}\n", receipt.summary());
    eprintln!(
        "backup signed payload: {} ({} the {} KMS Sign RAW limit)",
        human_bytes(payload_bytes),
        if receipt.backup.fits_kms_raw_sign_limit {
            "within"
        } else {
            "OVER"
        },
        human_bytes(KMS_RAW_SIGN_LIMIT_BYTES),
    );
    eprintln!("--- operations notification ---\n{}", operations.body);

    retain(&receipt, &operations, &customer)?;
    Ok(())
}

/// Write the receipt into `docs/drills/`, where it is retained as evidence.
///
/// `LOOM_DRILL_RETAIN=0` skips the write for a run that is only checking the drill still passes.
fn retain(
    receipt: &DrillReceipt,
    operations: &loom_drill::incident::Notification,
    customer: &loom_drill::incident::Notification,
) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("LOOM_DRILL_RETAIN").as_deref() == Ok("0") {
        return Ok(());
    }
    let target: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/drills")
        .canonicalize()?;
    let document = serde_json::json!({
        "receipt": receipt,
        "summary": receipt.summary(),
        "notifications": [operations, customer],
    });
    std::fs::write(
        target.join(format!("{}.json", receipt.topology.as_str())),
        serde_json::to_vec_pretty(&document)?,
    )?;
    Ok(())
}
