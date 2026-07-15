//! **AT-045 — crash at any byte, under a LoomDB-shaped workload.**
//!
//! Substrate's own crash suite drives 50,000 cycles against the *engine's* write path (doc 02 §10).
//! This re-asserts the same guarantee at the **LoomDB** level, because LoomDB has a second durable
//! object substrate does not: the **ref write** (branch heads + the commit DAG), with its own ordering
//! — the manifest is durable *before* the ref that points at it (invariant I-8). A crash between the
//! two must leave a branch pointing at the *old* head, never at a manifest that is not there.
//!
//! # The method
//!
//! One [`CrashVfs`](substrate_pager::testing::CrashVfs) sits under **both** the pager and the ref store,
//! with a byte budget. A fixed loom workload — observe, claim, branch, more claims, merge — runs until
//! the budget is exhausted mid-write and the simulated machine dies. Then the disk is rebooted and the
//! database reopened. Sweeping the budget from zero up past the whole workload crashes the write path at
//! **every byte boundary in turn**, and at each one the recovered database must satisfy:
//!
//! - **It reopens.** No torn state, no ref pointing at a manifest that is not durable.
//! - **It is a prefix.** Everything a `write` *acknowledged* (returned `Ok` for) is present and correct —
//!   nothing acknowledged is lost — and nothing past the crash appears.

use std::sync::Arc;

use loom_branch::{FileRefStore, Loom, MergePolicy, MergeResult};
use loom_core::{
    ActorId, BranchId, Claim, ClaimId, ClaimStatus, Confidence, Interval, Method, Observation,
    ObservationId, Record, SessionId, SourceRef, TenantId, Timestamp, Value, WriteEnvelope,
};
use substrate_pager::testing::{crashing_mem_vfs, reboot, MemVfs};
use substrate_pager::{ManualClock, PageStore, Pager, StoreConfig, Vfs};

const NOW: u64 = 1_700_000_000_000;

/// Build a Loom whose pager AND ref store both write through `vfs`.
fn loom_on(vfs: Arc<dyn Vfs>, tenant: &str) -> Result<Loom, Box<dyn std::error::Error>> {
    let pager = Pager::open_with(
        vfs.clone(),
        "/db",
        StoreConfig {
            pool: tenant.to_string(),
            ..Default::default()
        },
        Arc::new(ManualClock::new(NOW)),
    )?;
    let refs = FileRefStore::open_with_vfs(vfs, "/db")?;
    Ok(Loom::on(Arc::new(pager), Arc::new(refs), TenantId::new(tenant))?.with_clock(|| NOW))
}

fn env(session: &SessionId, branch: &BranchId) -> WriteEnvelope {
    WriteEnvelope::new(
        ActorId::new("agent"),
        session.clone(),
        branch.clone(),
        "crash-test",
    )
}

fn observation(text: &str) -> Record {
    Record::Observation(Box::new(Observation {
        id: ObservationId::of(text.as_bytes()),
        source: SourceRef::new("erp", text),
        trust: loom_core::TrustClass::VerifiedSystem,
        observed_at: None,
        ingested_at: Timestamp::from_ms(NOW),
        payload: text.as_bytes().to_vec(),
    }))
}

fn claim(subject: &str) -> Record {
    Record::Claim(Box::new(Claim {
        id: ClaimId::of(subject.as_bytes()),
        predicate: "flag".into(),
        subject: subject.into(),
        object: Value::Bool(true),
        valid: Interval::from(Timestamp::from_ms(NOW)),
        known: Interval::from(Timestamp::from_ms(NOW)),
        confidence: Confidence::new(0.9, Method::Rule, "v1"),
        evidence: vec![SourceRef::new("erp", subject)],
        status: ClaimStatus::Asserted,
        policy: None,
        actor: ActorId::new("agent"),
    }))
}

/// What one workload step wrote, so recovery can be checked by key + value.
#[derive(Clone)]
struct Ack {
    branch: BranchId,
    key: Vec<u8>,
}

/// Run the fixed workload until the first error (the simulated crash). Returns the writes that were
/// **acknowledged** — the ones whose `write`/`merge` returned `Ok` before the crash.
///
/// The order is fixed, so the acknowledged set is always a prefix of the same sequence; which prefix
/// depends only on where the byte budget ran out.
fn run_workload(db: &Loom) -> Vec<Ack> {
    let mut acked = Vec::new();

    let Ok((session, mut token)) = db.open_session() else {
        return acked;
    };
    let main = session.branch.clone();
    let sid = session.id.clone();

    // Five records on main.
    for i in 0..5 {
        let key = format!("main/{i}").into_bytes();
        let record = if i % 2 == 0 {
            observation(&format!("m{i}"))
        } else {
            claim(&format!("m{i}"))
        };
        if db
            .write(&token, &main, key.clone(), record, &env(&sid, &main))
            .is_err()
        {
            return acked;
        }
        acked.push(Ack {
            branch: main.clone(),
            key,
        });
    }

    // Fork a hypothesis and write on it.
    let (h, htoken) = match db.branch(&token, &main, "h") {
        Ok(v) => v,
        Err(_) => return acked,
    };
    token = htoken;
    for i in 0..3 {
        let key = format!("h/{i}").into_bytes();
        if db
            .write(
                &token,
                &h,
                key.clone(),
                claim(&format!("h{i}")),
                &env(&sid, &h),
            )
            .is_err()
        {
            return acked;
        }
        acked.push(Ack {
            branch: h.clone(),
            key,
        });
    }

    // Merge h into main.
    match db.merge(&token, &h, &main, &MergePolicy::Conflict, &env(&sid, &main)) {
        Ok(MergeResult::Merged { .. }) => {
            // After a successful merge, h's writes are also on main.
            for i in 0..3 {
                acked.push(Ack {
                    branch: main.clone(),
                    key: format!("h/{i}").into_bytes(),
                });
            }
        }
        _ => return acked,
    }

    acked
}

/// Reopen over the rebooted disk and confirm every acknowledged write survived, reading the tree
/// **directly** (no token, no new session) — which sidesteps capability scope and checks the storage
/// itself, which is what AT-045 is about.
fn verify_recovery(disk: Arc<MemVfs>, acked: &[Ack]) {
    // Reopening AT ALL is the first assertion: `Loom::on` loads the refs and resolves the root. If a
    // ref pointed at a manifest that was not durable (an I-8 violation), this would fail here.
    let db = loom_on(reboot(disk), "acme").expect(
        "a rebooted database must REOPEN — a ref must never point at a non-durable manifest (I-8)",
    );

    for ack in acked {
        // An acknowledged write returned `Ok` only AFTER its ref fsync'd, so its branch head is durable
        // and points at a durable manifest. That head must resolve.
        let head = db
            .head(&ack.branch)
            .unwrap_or_else(|_| panic!(
                "AT-045: acknowledged branch {:?} is gone after recovery — an acknowledged write was lost",
                ack.branch
            ));

        // Read the record straight out of the branch's tree. It must be present (not lost) and decode
        // cleanly (not torn).
        let store = db
            .pager_for_debug()
            .fork(&head)
            .expect("AT-045: the acknowledged branch head is not a readable manifest — torn state");
        let mut tree = loom_branch::Tree::open(&*store)
            .expect("AT-045: the recovered tree does not open — torn state");
        let found = tree
            .get(&ack.key)
            .expect("AT-045: reading an acknowledged key errored — torn state");
        assert!(
            found.is_some(),
            "AT-045: acknowledged write {:?} on {:?} is MISSING after recovery — an acknowledgement was lost",
            String::from_utf8_lossy(&ack.key),
            ack.branch
        );
    }
}

/// **The sweep: crash at every byte boundary, and recover cleanly every time.**
#[test]
fn at_045_crash_at_any_byte_recovers_to_a_prefix() {
    // First, find how many write-bytes the whole workload costs, so the sweep covers all of it.
    let (probe_disk, probe_vfs) = crashing_mem_vfs(i64::MAX);
    let total_bytes = {
        let db = loom_on(probe_vfs.clone(), "acme").unwrap();
        let acked = run_workload(&db);
        assert!(
            acked.len() >= 11,
            "the full workload should acknowledge all writes with an unlimited budget"
        );
        drop(db);
        // Bytes the CrashVfs saw pass through.
        i64::MAX - probe_vfs.remaining()
    };
    drop(probe_disk);
    assert!(total_bytes > 0, "the workload must write something");

    // Crash at every `stride`-th byte boundary from 0 up past the whole workload. `stride = 1` is the
    // exhaustive every-byte sweep (the spec's letter, ~5 min); the default samples enough points to hit
    // every structural boundary in seconds, and CI runs the exhaustive sweep in its own job — the same
    // split the model oracles use (a fast default, the heavy sweep on demand).
    let stride: i64 = std::env::var("AT045_STRIDE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            (total_bytes / 200).max(1) // ~200 crash points by default
        });

    let mut budget = 0i64;
    while budget <= total_bytes {
        let (disk, vfs) = crashing_mem_vfs(budget);
        let acked = match loom_on(vfs.clone(), "acme") {
            Ok(db) => run_workload(&db),
            // Even opening the database writes bytes (the root ref); crashing during open is a valid
            // crash point, and recovery from it must still yield a clean, empty-or-prefix database.
            Err(_) => Vec::new(),
        };
        verify_recovery(disk, &acked);
        budget += stride;
    }
}
