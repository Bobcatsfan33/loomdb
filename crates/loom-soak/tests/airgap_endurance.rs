//! **Soak A — airgap endurance.** The regulated-market promise, run as a property over a long window.
//!
//! docs/04 L5 names four things an air-gapped enclave must survive, and one bar it must clear:
//!
//! 1. **A 120-day accelerated clock** — a run compresses 120 days of wall-clock into its iterations.
//! 2. **±30-day wall-clock jumps mid-run** — an operator corrects a drifting clock, or tries to defeat
//!    the license by setting it back. Either way the high-water clock must never run backwards.
//! 3. **License expiry mid-run — reads and writes MUST NOT STOP.** The license going `Degraded` turns
//!    off fleet administration, never data. This is the load-bearing assertion of the whole soak.
//! 4. **Storage exhaustion — clean backpressure, never corruption.** A full store returns an error and
//!    the database stays consistent; it does not tear. (The behavior loom-bench's disk guard already
//!    models, asserted here as an engine property.)
//!
//! The bar (docs/04 §5): **zero errors AND flat memory across the window.** A leak fails the run
//! ([`loom_soak::FlatMemory`]) — a slow leak in a process meant to stay up for a year is a guaranteed
//! outage.
//!
//! It runs **airgapped**: an in-memory store, a local license, a virtual clock — no network, so it
//! passes under `--no-default-features --features airgap` and in a `--network none` container.
//!
//! Env-scaled (`LOOM_SOAK_ITERS`): a few thousand iterations by default so the fast path is CI-seconds;
//! the nightly headroom host sets it high so the flat-memory measurement spans a real run.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use loom_branch::{FileRefStore, Loom, Tree};
use loom_core::{
    ActorId, BranchId, Claim, ClaimId, ClaimStatus, Confidence, Interval, Method, Observation,
    ObservationId, Record, SessionId, SourceRef, TenantId, Timestamp, Value, WriteEnvelope,
};
use loom_soak::{scale::env_usize, FlatMemory};
use substrate_pager::testing::{crashing_mem_vfs, reboot, MemVfs};
use substrate_pager::{ManualClock, PageStore, Pager, StoreConfig, Vfs};
use substrate_security::license::{Enforcement, License, LicenseClaims, Status};

const DAY_MS: u64 = 86_400_000;
/// The database's own timestamp clock is held fixed; the *license* clock is what advances. The two are
/// independent on purpose — that independence is the never-hard-stop guarantee, made structural.
const NOW: u64 = 1_700_000_000_000;

// ---- construction (mirrors loom-branch/tests/crash.rs: a Loom whose pager AND refs share one vfs) ----

fn loom_on(
    vfs: Arc<dyn Vfs>,
    tenant: &str,
) -> std::result::Result<Loom, Box<dyn std::error::Error>> {
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
        "soak",
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

// ---- the endurance run ----

#[test]
fn soak_a_airgap_endurance_never_stops_serving_and_does_not_leak() {
    // The window: 120 accelerated days, crossed over `iters` steps. This test runs in the ordinary PR
    // `test` job at its default, so the default is small (fast path, ~seconds); the nightly headroom host
    // sets LOOM_SOAK_ITERS high so the flat-memory measurement spans a real, long run. Each read forks a
    // manifest and opens a tree, so the cost is in the reads — keep READS_PER_STEP low on the fast path.
    let iters = env_usize("LOOM_SOAK_ITERS", 300).max(200);
    const READS_PER_STEP: usize = 4;
    let window_ms: u64 = 120 * DAY_MS;
    let step_ms = window_ms / iters as u64;

    // A local, signed license that EXPIRES a third of the way through the window, with 30 days of grace
    // — so partway through the run it goes Ok → Warning (grace) → Degraded, all while the database keeps
    // serving. Everything here is offline: the key is generated in-process, nothing is fetched.
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let verifying = key.verifying_key();
    let not_before = NOW;
    let not_after = NOW + window_ms / 3; // expires ~day 40
    let license = License::sign(
        LicenseClaims {
            licensee: "airgapped-enclave".into(),
            features: vec!["fleet-admin".into()],
            not_before,
            not_after,
            grace_days: 30,
        },
        &key,
    )
    .expect("sign the local license");
    let enforcement = Enforcement::new(verifying, 0);

    // The database under test: unbounded in-memory store (no disk risk, no network).
    let db = loom_on(MemVfs::new(), "acme").expect("open the in-memory database");
    let (session, token) = db.open_session().expect("open a session");
    let main = session.branch.clone();
    let sid = session.id.clone();

    // A fixed working set, written up front. The endurance phase reads these and makes only a bounded
    // number of probe writes — so durable data does NOT grow with the iteration count, and any RSS
    // growth over the run is a real leak, not the store legitimately getting bigger.
    const WORKING_SET: usize = 256;
    for i in 0..WORKING_SET {
        let rec = if i % 2 == 0 {
            observation(&format!("seed{i}"))
        } else {
            claim(&format!("seed{i}"))
        };
        db.write(
            &token,
            &main,
            format!("k{i}").into_bytes(),
            rec,
            &env(&sid, &main),
        )
        .expect("seed write");
    }

    // Warm up (cycle reads over the bounded working set on the main session) so allocator arenas and
    // caches reach steady state before we start measuring — otherwise warm-up growth looks like a leak.
    // We reuse ONE session on purpose: the engine keeps a read-set per session and captures reads into
    // it with set-insert (deduped), so re-reading a bounded key set keeps that set — and RSS — flat. A
    // fresh session per iteration would instead accumulate branches and read-set entries, which is a
    // real leak of the *caller's* making, not the engine's, and would drown the signal we are after.
    for round in 0..100 {
        for i in 0..READS_PER_STEP {
            let idx = (round + i) % WORKING_SET;
            db.read(&token, &main, format!("k{idx}").into_bytes().as_slice())
                .expect("warm-up read");
        }
    }
    // Tolerance: generous enough for allocator noise + the bounded probe writes, tight enough that a
    // per-iteration leak (a session/token/read-set never freed) blows past it over the full window.
    let mut gate = FlatMemory::new("soak-a", 64 * 1024 * 1024);
    gate.mark_steady_state();

    // Jumps scheduled at fixed fractions of the run (deterministic — no wall-clock/RNG in the soak).
    let jump_back_at = iters / 4; // an operator sets the clock back 30 days
    let jump_fwd_at = iters / 2; // and later a correction lurches it 30 days forward
                                 // Probe-write milestones — the moments the "writes must not stop" claim has to hold at.
    let probe_after_expiry = (iters * 45) / 100; // just after not_after (~day 40)
    let probe_after_degraded = (iters * 80) / 100; // well past not_after + grace (~day 90)

    let mut prev_high_water = enforcement.high_water_ms();
    let mut reads_ok = 0u64;
    let mut writes_ok = 0u64;
    let mut probe_writes = 0u64;
    let mut ever_degraded = false;
    let mut degraded_but_still_served = false;

    for i in 0..iters {
        // The virtual wall clock for this step, with the two jumps injected.
        let mut wall = NOW + (i as u64) * step_ms;
        if i >= jump_back_at && i < jump_fwd_at {
            // The operator has set the clock back 30 days. The high-water clock must ignore it.
            wall = wall.saturating_sub(30 * DAY_MS);
        } else if i >= jump_fwd_at {
            wall = wall.saturating_add(30 * DAY_MS);
        }

        // Evaluate the license against the (possibly tampered) wall clock. This ratchets the high-water
        // mark. NONE of its return values may stop the database.
        let status = enforcement.evaluate(Some(&license), wall);

        // (2) The high-water clock never runs backwards — not across the −30-day jump, not ever. This is
        // "set the clock back and the license does not un-expire", asserted every step.
        let high_water = enforcement.high_water_ms();
        assert!(
            high_water >= prev_high_water,
            "the high-water clock ran BACKWARDS at step {i}: {prev_high_water} → {high_water}"
        );
        prev_high_water = high_water;

        if status.is_degraded() {
            ever_degraded = true;
        }

        // (3) Reads must not stop — under Ok, Warning, or Degraded. Cycle the bounded working set on the
        // main session (deduped read-set → flat RSS; see the warm-up note).
        for j in 0..READS_PER_STEP {
            let idx = (i + j) % WORKING_SET;
            let got = db
                .read(&token, &main, format!("k{idx}").into_bytes().as_slice())
                .expect("a READ must never stop, regardless of licence state (never-hard-stop)");
            assert!(got.is_some(), "seeded key k{idx} vanished mid-run");
            reads_ok += 1;
        }

        // (3, writes) Probe writes at the moments that matter: just after expiry, and well past grace
        // when the licence is Degraded. A write returning Ok here is the promise in a test.
        if i == probe_after_expiry || i == probe_after_degraded {
            db.write(
                &token,
                &main,
                format!("probe{i}").into_bytes(),
                observation(&format!("probe-at-{i}")),
                &env(&sid, &main),
            )
            .expect(
                "a WRITE must never stop, even with the licence EXPIRED/Degraded (never-hard-stop)",
            );
            writes_ok += 1;
            probe_writes += 1;
            if status.is_degraded() {
                degraded_but_still_served = true;
            }
        }

        // Narrate the status transition once, so the CI log tells the story a buyer can read.
        if i == probe_after_expiry
            || i == probe_after_degraded
            || i == jump_back_at
            || i == jump_fwd_at
        {
            eprintln!("[soak-a] step {i}/{iters}: licence status = {status}");
        }
        let _ = &status; // status is advisory; the database never consulted it to serve the reads above.
    }

    // (1) We actually crossed the whole window and the licence actually expired past grace.
    assert!(
        ever_degraded,
        "the run never reached Degraded — the accelerated clock did not cross not_after + grace, so the \
         never-hard-stop-past-expiry property was not actually exercised"
    );
    // The load-bearing assertion: the database served a write while the licence was Degraded.
    assert!(
        degraded_but_still_served,
        "no write was proven to succeed while the licence was Degraded — the central promise is untested"
    );
    assert_eq!(probe_writes, 2, "both probe writes must have run");
    assert!(reads_ok > 0 && writes_ok > 0);

    // Sanity: the licence really is Degraded at the end (so is_ok would be false), and the final status
    // is not Ok — reads still worked throughout regardless.
    let final_status = enforcement.evaluate(Some(&license), NOW + window_ms + 30 * DAY_MS);
    assert!(
        matches!(final_status, Status::Degraded { .. }),
        "at the end of the window the licence should be Degraded, was {final_status}"
    );

    // (The bar) Flat memory — a leak fails the run.
    gate.verdict().expect("flat-memory gate");

    eprintln!(
        "[soak-a] OK: {reads_ok} reads + {writes_ok} writes across {iters} steps (120 accelerated days), \
         licence crossed Ok→grace→Degraded, high-water clock monotonic through ±30-day jumps, memory flat."
    );

    // (4) Storage exhaustion is its own scenario, below.
    storage_exhaustion_backpressures_cleanly_and_never_corrupts();
    disk_guard_refuses_an_oversized_run_cleanly();
}

/// (4) A bounded store fills, the write that would overflow returns an **error** (not a panic, not a
/// torn page), and the database is still fully consistent afterward: it reopens and every acknowledged
/// write is intact. This is the AT-045 backpressure property extended to "the disk is full" rather than
/// "the machine died".
fn storage_exhaustion_backpressures_cleanly_and_never_corrupts() {
    // A small write budget: enough for some records, not for unbounded growth. CrashVfs returns an I/O
    // error once the budget is spent — which, handled as backpressure rather than a crash, IS storage
    // exhaustion: the process keeps running and the store refuses further writes cleanly.
    let (disk, vfs) = crashing_mem_vfs(256 * 1024);
    let db = loom_on(vfs, "acme").expect("open the bounded database");
    let (session, token) = db.open_session().expect("session");
    let main = session.branch.clone();
    let sid = session.id.clone();

    let mut acked: Vec<Vec<u8>> = Vec::new();
    let mut hit_backpressure = false;
    for i in 0..100_000 {
        let key = format!("fill{i}").into_bytes();
        match db.write(
            &token,
            &main,
            key.clone(),
            claim(&format!("fill{i}")),
            &env(&sid, &main),
        ) {
            Ok(_) => acked.push(key),
            Err(_) => {
                // Clean backpressure: an Err, not a panic, not a partial write we lied about acking.
                hit_backpressure = true;
                break;
            }
        }
    }
    assert!(
        hit_backpressure,
        "the bounded store never returned backpressure — the budget was too large to exercise exhaustion"
    );
    assert!(
        !acked.is_empty(),
        "nothing was written before exhaustion — budget too small to be a test"
    );

    // Never corrupts: reopen over the same disk and confirm every ACKNOWLEDGED write is present and
    // decodes. An ack returned Ok only after its ref fsync'd, so it must survive.
    let reopened = loom_on(reboot(disk), "acme").expect(
        "a store that hit backpressure must still REOPEN — exhaustion must not corrupt (I-8)",
    );
    for key in &acked {
        let head = reopened
            .head(&main)
            .expect("main branch is gone after storage exhaustion — corruption");
        let store = reopened
            .pager_for_debug()
            .fork(&head)
            .expect("the head is not a readable manifest after exhaustion — torn state");
        let mut tree =
            Tree::open(&*store).expect("the tree does not open after exhaustion — torn state");
        let found = tree
            .get(key)
            .expect("reading an acknowledged key errored after exhaustion — torn");
        assert!(
            found.is_some(),
            "acknowledged write {:?} vanished after storage exhaustion — an ack was lost",
            String::from_utf8_lossy(key)
        );
    }
    eprintln!(
        "[soak-a] OK: storage exhaustion backpressured cleanly after {} acked writes; all survived reopen.",
        acked.len()
    );
}

/// (4, the harness-guard property the roadmap points at) loom-bench's disk guard refuses a run larger
/// than free space, cleanly and by naming the shortfall — the same clean-backpressure behavior, at the
/// harness boundary, so a benchmark can never DoS its host the way the incident that created that crate did.
fn disk_guard_refuses_an_oversized_run_cleanly() {
    // A run needs records × ~370 bytes PLUS a fixed safety headroom (loom_bench::SAFETY_HEADROOM_BYTES,
    // ~512 MiB) — the guard keeps that headroom free so a run never fills the host to zero (the incident
    // that created the crate). So "fits" must clear the headroom, and "does not fit" must exceed it.
    let tiny_free = 1024 * 1024; // 1 MiB — below the headroom, so even a small run is refused
    let huge = 10_000_000u64; // ~3.7 GB estimated — refused against any sane free space
    assert!(
        loom_bench::check(huge, tiny_free).is_err(),
        "the disk guard accepted a run that does not fit — it must refuse cleanly, naming the shortfall"
    );
    // A run that clears the headroom is allowed.
    let ample_free = loom_bench::SAFETY_HEADROOM_BYTES + 64 * 1024 * 1024;
    assert!(
        loom_bench::check(10, ample_free).is_ok(),
        "the disk guard rejected a run that comfortably fits above the safety headroom"
    );
    eprintln!("[soak-a] OK: disk guard refuses an oversized run cleanly (clean backpressure at the harness).");
}
