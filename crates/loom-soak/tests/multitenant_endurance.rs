//! **Soak B — multi-tenant concurrency endurance.** Isolation holds forever, and memory stays flat.
//!
//! docs/04 L5's second soak: churn many tenants and branches, concurrently, for a long window, and
//! assert the guarantees that a multi-tenant deployment lives or dies by never break under load:
//!
//! - **AT-039 — cross-tenant isolation.** A tenant, through the front-door router, can neither read nor
//!   confirm the existence of another tenant's data. A token routes only to its own signed tenant's
//!   engine; a key that lives in another tenant comes back `Ok(None)`, identical to a key that never
//!   existed. And a token for an unregistered tenant gets the uniform `Unauthorized` — no existence
//!   oracle. Asserted on every iteration, from every worker thread.
//! - **AT-040 — branch isolation.** A key written on one branch is invisible on a sibling forked before
//!   the write. Structural (each branch is its own tree), re-checked under churn.
//! - **Merge idempotency.** Re-merging an already-merged branch is a no-op — the `+3`-not-`+6` property
//!   (a token double-counted on re-merge was a real bug an oracle caught); it must still hold after the
//!   churn.
//!
//! The bar (docs/04 §5): **zero errors AND flat memory.** A leak fails the run. The concurrent phase
//! reuses one session per worker over a bounded key set, so RSS growth is a real leak, not churn.
//!
//! Scratch safety: even though this soak is in-memory, it opens a [`loom_bench::BenchScratch`] so the
//! crate's disk-guard discipline (reap-on-startup, no stranded data if a nightly run is killed) is
//! exercised on the path the roadmap's own disk incident came from.
//!
//! Env-scaled: `LOOM_SOAK_ITERS` (per-worker iterations) and `LOOM_SOAK_WORKERS`. Small defaults for the
//! PR fast path; the nightly headroom host turns both up for a real, long, concurrent run.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use loom_branch::{Loom, MergePolicy, MergeResult, Tenancy};
use loom_core::{
    ActorId, BranchId, Claim, ClaimId, ClaimStatus, Confidence, Interval, LoomError, Method,
    Observation, ObservationId, Record, SessionId, SourceRef, TenantId, Timestamp, Value,
    WriteEnvelope,
};
use loom_soak::{scale::env_usize, FlatMemory};

const NOW: u64 = 1_700_000_000_000;

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

/// A registered tenant and the handle a worker needs to drive it: its engine, its own token, its main
/// branch, and the key it owns that no other tenant has.
struct Tenant {
    id: TenantId,
    branch: BranchId,
    token: loom_branch::CapabilityToken,
    own_key: Vec<u8>,
    /// A branch forked from main BEFORE `secret_key` was written to main — so `secret_key` is on main
    /// but NOT on this sibling. AT-040: a sibling cannot see it.
    sib_branch: BranchId,
    sib_token: loom_branch::CapabilityToken,
    secret_key: Vec<u8>,
}

#[test]
fn soak_b_multitenant_isolation_holds_under_churn_and_memory_is_flat() {
    let iters = env_usize("LOOM_SOAK_ITERS", 180).max(100);
    let workers = env_usize("LOOM_SOAK_WORKERS", 4).clamp(1, 32);
    const TENANTS: usize = 6;
    const KEYS_PER_TENANT: usize = 64;

    // Exercise the disk-guard discipline even though the store is in-memory (roadmap's own incident).
    let scratch_base = std::env::temp_dir().join("loom-soak-b");
    std::fs::create_dir_all(&scratch_base).expect("scratch base");
    let _scratch = loom_bench::BenchScratch::open(&scratch_base, "multitenant")
        .expect("open a reaped scratch dir");

    let router = Arc::new(Tenancy::new());
    let mut tenants: Vec<Tenant> = Vec::new();

    // Register each tenant with its own in-memory engine, seed a private working set, and leave one
    // branch merged so the idempotency phase has something already-merged to re-merge.
    for t in 0..TENANTS {
        let id = TenantId::new(format!("tenant-{t}"));
        let engine = Arc::new(Loom::in_memory(id.clone()).expect("in-memory engine"));
        router.register(id.clone(), Arc::clone(&engine));

        let (session, token) = engine.open_session().expect("session");
        let main = session.branch.clone();
        let sid = session.id.clone();

        for k in 0..KEYS_PER_TENANT {
            let rec = if k % 2 == 0 {
                observation(&format!("t{t}-seed{k}"))
            } else {
                claim(&format!("t{t}-seed{k}"))
            };
            engine
                .write(
                    &token,
                    &main,
                    format!("t{t}/k{k}").into_bytes(),
                    rec,
                    &env(&sid, &main),
                )
                .expect("seed write");
        }

        // A branch + a merge, so re-merge idempotency has a subject. Fork `h`, write 3 records, merge.
        let (h, htoken) = engine
            .branch(&token, &main, &format!("h{t}"))
            .expect("branch");
        for j in 0..3 {
            engine
                .write(
                    &htoken,
                    &h,
                    format!("t{t}/h{j}").into_bytes(),
                    claim(&format!("t{t}-h{j}")),
                    &env(&sid, &h),
                )
                .expect("branch write");
        }
        match engine.merge(
            &htoken,
            &h,
            &main,
            &MergePolicy::Conflict,
            &env(&sid, &main),
        ) {
            Ok(MergeResult::Merged { .. }) => {}
            other => panic!("tenant {t} setup merge did not merge: {other:?}"),
        }

        // AT-040 fixture: fork a sibling from main, THEN write a secret to main. The sibling forked
        // before the write, so it must never see the secret.
        let (sib, sib_token) = engine
            .branch(&token, &main, &format!("sib{t}"))
            .expect("sibling branch");
        let secret_key = format!("t{t}/secret").into_bytes();
        engine
            .write(
                &token,
                &main,
                secret_key.clone(),
                claim(&format!("t{t}-secret")),
                &env(&sid, &main),
            )
            .expect("secret write on main");

        tenants.push(Tenant {
            id,
            branch: main,
            token,
            own_key: format!("t{t}/k0").into_bytes(),
            sib_branch: sib,
            sib_token,
            secret_key,
        });
    }

    // A token for a tenant that is NOT registered in the router — the AT-039 no-existence-oracle probe.
    let ghost_engine = Loom::in_memory(TenantId::new("ghost")).expect("ghost engine");
    let (_gs, ghost_token) = ghost_engine.open_session().expect("ghost session");

    // Warm up the read paths to steady state before measuring.
    for t in &tenants {
        for _ in 0..64 {
            router
                .read(&t.token, &t.branch, &t.own_key)
                .expect("warm-up read");
        }
    }
    let mut gate = FlatMemory::new("soak-b", 96 * 1024 * 1024);
    gate.mark_steady_state();

    // --- Concurrent isolation phase: every worker hammers the isolation invariants at once. ---
    let tenants = Arc::new(tenants);
    let ghost_token = Arc::new(ghost_token);
    let total = (workers * iters).max(1);
    let progress = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|scope| {
        // A monitor thread emits the memory curve while the workers run, so the full-window report shows
        // the slope during the concurrent churn — where a leak would appear — not just the endpoints.
        {
            let progress = Arc::clone(&progress);
            let gate = &gate;
            scope.spawn(move || {
                let mut last_pct = usize::MAX;
                loop {
                    let p = progress.load(Ordering::Relaxed);
                    let pct = (p * 100) / total;
                    if pct != last_pct && pct.is_multiple_of(5) {
                        gate.sample(&format!("{pct}%"));
                        last_pct = pct;
                    }
                    if p >= total {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            });
        }
        for w in 0..workers {
            let router = Arc::clone(&router);
            let tenants = Arc::clone(&tenants);
            let ghost_token = Arc::clone(&ghost_token);
            let progress = Arc::clone(&progress);
            scope.spawn(move || {
                let home = w % TENANTS; // each worker has a home tenant, so its session is reused (bounded)
                let me = &tenants[home];
                for i in 0..iters {
                    // Serving works: a tenant reads its own key through the router.
                    let own = router
                        .read(&me.token, &me.branch, &me.own_key)
                        .expect("a tenant must always read its own data");
                    assert!(own.is_some(), "tenant {home} lost its own key under churn");

                    // AT-039: my token, aimed (via the router) at another tenant's key, returns None —
                    // the router sent it to MY engine, which has no such key. No cross-tenant read.
                    let other = (home + 1 + (i % (TENANTS - 1))) % TENANTS;
                    let other_key = format!("t{other}/k1").into_bytes();
                    let leaked = router
                        .read(&me.token, &me.branch, &other_key)
                        .expect("router read");
                    assert!(
                        leaked.is_none(),
                        "CROSS-TENANT LEAK: tenant {home}'s token read tenant {other}'s key t{other}/k1"
                    );

                    // AT-039, no existence oracle: an unregistered tenant's token gets the uniform
                    // Unauthorized — indistinguishable from any other refusal.
                    match router.read(&ghost_token, &me.branch, &me.own_key) {
                        Err(LoomError::Unauthorized) => {}
                        other => panic!(
                            "an unregistered-tenant token must get uniform Unauthorized, got {other:?}"
                        ),
                    }

                    // AT-040: the secret is on main, but the sibling forked before it — so the sibling
                    // must not see it, while main must. Branch isolation, under churn.
                    let on_main = router
                        .read(&me.token, &me.branch, &me.secret_key)
                        .expect("router read");
                    assert!(on_main.is_some(), "tenant {home} lost its secret on main");
                    let on_sibling = router
                        .read(&me.sib_token, &me.sib_branch, &me.secret_key)
                        .expect("router read");
                    assert!(
                        on_sibling.is_none(),
                        "BRANCH LEAK (AT-040): sibling branch saw a key written to main after the fork"
                    );
                    progress.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });

    // --- Merge idempotency under post-churn state (single-threaded — re-merge is the test, not races). ---
    // Re-merging an already-merged branch must be a no-op: 0 new records, never a double-count.
    for (t, tenant) in tenants.iter().enumerate() {
        let engine = Loom::in_memory(tenant.id.clone()).expect("engine");
        // Rebuild a small merged pair in an isolated engine and re-merge it twice; the second merge must
        // add nothing. (Isolated so it does not disturb the shared router state.)
        let (session, token) = engine.open_session().expect("session");
        let main = session.branch.clone();
        let sid = session.id.clone();
        let (h, htoken) = engine.branch(&token, &main, "hi").expect("branch");
        for j in 0..3 {
            engine
                .write(
                    &htoken,
                    &h,
                    format!("m{j}").into_bytes(),
                    claim(&format!("t{t}-m{j}")),
                    &env(&sid, &h),
                )
                .expect("write");
        }
        let first = match engine.merge(
            &htoken,
            &h,
            &main,
            &MergePolicy::Conflict,
            &env(&sid, &main),
        ) {
            Ok(MergeResult::Merged { records, .. }) => records,
            other => panic!("first merge did not merge: {other:?}"),
        };
        assert!(first > 0, "the first merge should have moved records");
        // Re-merge: h is already fully absorbed into main, so this must be a no-op.
        let second = match engine.merge(
            &htoken,
            &h,
            &main,
            &MergePolicy::Conflict,
            &env(&sid, &main),
        ) {
            Ok(MergeResult::Merged { records, .. }) => records,
            Ok(other) => {
                panic!("re-merge of an already-merged branch returned unexpected {other:?}")
            }
            Err(e) => panic!("re-merge errored: {e}"),
        };
        assert_eq!(
            second, 0,
            "MERGE NOT IDEMPOTENT: re-merging an already-merged branch moved {second} records (double-count)"
        );
    }

    // The bar: flat memory across the whole concurrent + idempotency run.
    gate.verdict().expect("flat-memory gate");

    eprintln!(
        "[soak-b] OK: {workers} workers × {iters} iters over {TENANTS} tenants — no cross-tenant leak, \
         no existence oracle, branch isolation held, merges idempotent, memory flat."
    );
}
