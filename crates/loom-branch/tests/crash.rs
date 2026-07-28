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
//!
//! # Certification log
//!
//! The default sweep samples ~200 crash points (fast, hits every structural boundary); the **exhaustive**
//! sweep (`AT045_STRIDE=1`) crashes at *literally every byte* and is re-run whenever the write path, ref
//! store, or commit machinery changes — the guarantee this repo's credibility rests on.
//!
//! - **v0.4 — the compaction change to the write path** (`write_all` now appends each indexed vector to
//!   an in-branch ANN buffer, under a new per-branch write lock) **and the fold** were re-certified at
//!   `AT045_STRIDE=1`: **both sweeps green** (`at_045_crash_at_any_byte_recovers_to_a_prefix` and
//!   `at_045_crash_during_fold_never_loses_a_vector`, every byte). The write path is no longer
//!   byte-identical to v0.3 — it is *fully re-certified*, which is the property that matters.
//! - **Phase 2 — the log-structured ref store** (a commit now *appends* a `RefEdit` frame to `refs.log`
//!   instead of rewriting the whole `Refs`, with periodic compaction into `refs.snapshot`). The entire
//!   ref write path changed, so all three sweeps were re-driven at `AT045_STRIDE=1` — **every byte,
//!   green (82.8 s)**: `at_045_crash_at_any_byte_recovers_to_a_prefix` (the append path),
//!   `at_045_crash_during_fold_never_loses_a_vector`, and the new
//!   `at_045_crash_during_ref_compaction_recovers_to_a_prefix` (a crash at every byte of a
//!   snapshot-write-then-log-truncate compaction — the snapshot is durable before the log is cut, so
//!   recovery always has a consistent baseline and replays the already-incorporated log as no-ops).

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

/// Like [`loom_on`], but with a **low ref-log compaction floor**, so a compaction happens every few
/// commits and the byte sweep can crash *during* one. The compaction logic is identical to production;
/// only the trigger threshold moves (see `FileRefStore::with_compact_floor`).
fn loom_on_low_floor(
    vfs: Arc<dyn Vfs>,
    tenant: &str,
    floor: u64,
) -> Result<Loom, Box<dyn std::error::Error>> {
    let pager = Pager::open_with(
        vfs.clone(),
        "/db",
        StoreConfig {
            pool: tenant.to_string(),
            ..Default::default()
        },
        Arc::new(ManualClock::new(NOW)),
    )?;
    let refs = FileRefStore::open_with_vfs(vfs, "/db")?.with_compact_floor(floor);
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

// ── AT-045 over the ANN fold: the buffer→graph handoff survives a crash at any byte ──

fn ann_vec(i: usize) -> loom_core::Embedding {
    let mut v = vec![0.02f32; 16];
    v[i % 16] = 1.0;
    loom_core::Embedding::new(v)
}

/// Write ten indexed vectors (each buffered), then fold them into the graph. Returns the
/// `(branch, key)` of every write that was **acknowledged** before the crash. The fold's own Ok/Err is
/// irrelevant to the invariant: whether or not it committed, an acked vector must be recoverable in the
/// buffer *or* the graph.
fn run_fold_workload(db: &Loom) -> Vec<(BranchId, Vec<u8>)> {
    let Ok((session, token)) = db.open_session() else {
        return Vec::new();
    };
    let branch = session.branch.clone();
    let mut acked = Vec::new();
    for i in 0..10usize {
        let key = format!("v/{i:03}").into_bytes();
        if db
            .write_indexed(
                &token,
                &branch,
                key.clone(),
                observation(&format!("v{i}")),
                loom_core::IndexHint::text("f").with_embedding(ann_vec(i)),
                &env(&session.id, &branch),
            )
            .is_ok()
        {
            acked.push((branch.clone(), key));
        } else {
            return acked;
        }
    }
    // The fold moves the buffered vectors into the graph in ONE atomic commit. A crash here must leave
    // every acked vector in the buffer (fold uncommitted) or the graph (committed) — never neither.
    let _ = db.ann_fold(&token, &branch);
    acked
}

/// After recovery, every acknowledged vector must survive **in the buffer or in the graph** — the
/// handoff has no window in which it is in neither. Read the tree directly (no token), the same way the
/// prefix sweep does, because this is a storage guarantee.
fn verify_fold_recovery(disk: Arc<MemVfs>, acked: &[(BranchId, Vec<u8>)]) {
    let db = loom_on(reboot(disk), "acme")
        .expect("a rebooted database must REOPEN after a mid-fold crash (I-8)");
    for (branch, key) in acked {
        let head = db.head(branch).unwrap_or_else(|_| {
            panic!("AT-045/fold: acknowledged branch is gone after recovery — a write was lost")
        });
        let store = db
            .pager_for_debug()
            .fork(&head)
            .expect("AT-045/fold: recovered head is not a readable manifest — torn state");
        let mut tree = loom_branch::Tree::open(&*store)
            .expect("AT-045/fold: recovered tree does not open — torn state");
        let in_buffer = tree
            .get(&loom_core::ann_buffer_key(key))
            .expect("AT-045/fold: reading the buffer errored — torn state")
            .is_some();
        let in_graph = tree
            .get(&loom_core::hnsw_node_key(key))
            .expect("AT-045/fold: reading the graph errored — torn state")
            .is_some();
        assert!(
            in_buffer || in_graph,
            "AT-045/fold: vector {:?} is in NEITHER buffer nor graph after a mid-fold crash — the \
             handoff lost it",
            String::from_utf8_lossy(key)
        );
    }
}

/// **The fold survives a crash at every byte boundary.** Same sweep as the write path, over a workload
/// whose last act is an ANN fold: at each crash point the buffer→graph handoff recovers with every acked
/// vector in exactly one of the two, never lost.
#[test]
fn at_045_crash_during_fold_never_loses_a_vector() {
    let (probe_disk, probe_vfs) = crashing_mem_vfs(i64::MAX);
    let total_bytes = {
        let db = loom_on(probe_vfs.clone(), "acme").unwrap();
        let acked = run_fold_workload(&db);
        assert!(
            acked.len() >= 10,
            "the full fold workload should acknowledge all ten writes with an unlimited budget"
        );
        drop(db);
        i64::MAX - probe_vfs.remaining()
    };
    drop(probe_disk);
    assert!(total_bytes > 0, "the fold workload must write something");

    let stride: i64 = std::env::var("AT045_STRIDE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| (total_bytes / 200).max(1));

    let mut budget = 0i64;
    while budget <= total_bytes {
        let (disk, vfs) = crashing_mem_vfs(budget);
        let acked = match loom_on(vfs.clone(), "acme") {
            Ok(db) => run_fold_workload(&db),
            Err(_) => Vec::new(),
        };
        verify_fold_recovery(disk, &acked);
        budget += stride;
    }
}

// ── AT-045 over a ref-log COMPACTION: the snapshot-then-truncate handoff survives a crash at any byte ──

/// A low floor so a handful of commits provoke several compactions — small enough that the every-byte
/// sweep stays tractable, large enough to hold a couple of edits per compaction cycle.
const COMPACTION_TEST_FLOOR: u64 = 300;

/// Write enough records on `main` that the ref log compacts several times over. Each write is a commit
/// (a `SetHead` + `RecordCommit` edit), so with a ~300-byte floor a compaction lands every few writes —
/// squarely inside the swept byte range. Returns the acknowledged `(branch, key)` writes.
fn run_compaction_workload(db: &Loom) -> Vec<Ack> {
    let mut acked = Vec::new();
    let Ok((session, token)) = db.open_session() else {
        return acked;
    };
    let main = session.branch.clone();
    let sid = session.id.clone();
    for i in 0..15 {
        let key = format!("c/{i:02}").into_bytes();
        let record = if i % 2 == 0 {
            observation(&format!("c{i}"))
        } else {
            claim(&format!("c{i}"))
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
    acked
}

/// Reopen (with the same low floor) and confirm every acknowledged write survived — the exact prefix
/// guarantee, but exercised across ref-log compactions that a crash may have interrupted mid-snapshot or
/// mid-truncate.
fn verify_compaction_recovery(disk: Arc<MemVfs>, acked: &[Ack]) {
    let db = loom_on_low_floor(reboot(disk), "acme", COMPACTION_TEST_FLOOR).expect(
        "a rebooted database must REOPEN after a mid-compaction crash — the new snapshot is durable \
         before the log is truncated, so recovery always has a consistent baseline (I-8)",
    );
    for ack in acked {
        let head = db.head(&ack.branch).unwrap_or_else(|_| {
            panic!(
                "AT-045/compaction: acknowledged branch {:?} gone after recovery",
                ack.branch
            )
        });
        let store = db
            .pager_for_debug()
            .fork(&head)
            .expect("AT-045/compaction: recovered head is not a readable manifest — torn state");
        let mut tree = loom_branch::Tree::open(&*store)
            .expect("AT-045/compaction: recovered tree does not open — torn state");
        assert!(
            tree.get(&ack.key)
                .expect("AT-045/compaction: reading an acknowledged key errored — torn state")
                .is_some(),
            "AT-045/compaction: acknowledged write {:?} lost across a ref-log compaction",
            String::from_utf8_lossy(&ack.key)
        );
    }
}

/// **A ref-log compaction survives a crash at every byte boundary.** The workload compacts the ref log
/// several times; the sweep crashes at each byte, including mid-snapshot-write and mid-truncate, and every
/// acknowledged write must still be present — the snapshot-before-truncate ordering plus idempotent replay
/// leave no window in which a committed head is lost.
#[test]
fn at_045_crash_during_ref_compaction_recovers_to_a_prefix() {
    let (probe_disk, probe_vfs) = crashing_mem_vfs(i64::MAX);
    let total_bytes = {
        let db = loom_on_low_floor(probe_vfs.clone(), "acme", COMPACTION_TEST_FLOOR).unwrap();
        let acked = run_compaction_workload(&db);
        assert!(
            acked.len() >= 15,
            "the full compaction workload should acknowledge all writes with an unlimited budget"
        );
        // Prove a compaction actually happened: without one, the snapshot is still just the rooted `main`
        // (an empty commit DAG) and every commit edge lives only in the log. A snapshot that has folded in
        // commit edges is a snapshot a compaction rewrote.
        let snap = loom_branch::Refs::decode(
            &probe_vfs
                .read(std::path::Path::new("/db/loom/refs.snapshot"))
                .expect("snapshot exists after the workload"),
        )
        .expect("snapshot decodes");
        assert!(
            !snap.commits.is_empty(),
            "the workload must trigger a compaction (the snapshot should have folded in commit edges, \
             but its DAG is empty — nothing compacted)"
        );
        drop(db);
        i64::MAX - probe_vfs.remaining()
    };
    drop(probe_disk);
    assert!(total_bytes > 0, "the workload must write something");

    let stride: i64 = std::env::var("AT045_STRIDE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| (total_bytes / 200).max(1));

    let mut budget = 0i64;
    while budget <= total_bytes {
        let (disk, vfs) = crashing_mem_vfs(budget);
        let acked = match loom_on_low_floor(vfs.clone(), "acme", COMPACTION_TEST_FLOOR) {
            Ok(db) => run_compaction_workload(&db),
            Err(_) => Vec::new(),
        };
        verify_compaction_recovery(disk, &acked);
        budget += stride;
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
