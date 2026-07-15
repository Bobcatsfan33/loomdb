//! **AT-003, AT-016, AT-039 — the remaining scoreboard entries for the tag.**


use loom_branch::{Loom, MergePolicy, MergeResult};
use loom_core::{
    ActorId, BranchId, Claim, ClaimId, ClaimStatus, Confidence, IndexHint, Interval, Key, Method,
    Observation, ObservationId, Record, SessionId, SourceRef, TenantId, Timestamp, TrustClass,
    Value, WriteEnvelope,
};
use loom_query::{AsOf, AsOfQuery};

const NOW: u64 = 1_700_000_000_000;

fn env(session: &SessionId, branch: &BranchId) -> WriteEnvelope {
    WriteEnvelope::new(
        ActorId::new("agent"),
        session.clone(),
        branch.clone(),
        "work",
    )
}

/// **AT-003 — an observation is not a claim. Ingesting one infers nothing.**
#[test]
fn at_003_an_observation_is_not_a_claim() {
    let db = Loom::in_memory(TenantId::new("acme"))
        .unwrap()
        .with_clock(|| NOW);
    let (session, token) = db.open_session().unwrap();
    let branch = session.branch.clone();

    // Ingest an observation about a subject.
    db.write_indexed(
        &token,
        &branch,
        b"obs/x".to_vec(),
        Record::Observation(Box::new(Observation {
            id: ObservationId::of(b"x"),
            source: SourceRef::new("web", "page"),
            trust: TrustClass::Untrusted,
            observed_at: None,
            ingested_at: Timestamp::from_ms(NOW),
            payload: b"user-7 might be risky".to_vec(),
        })),
        IndexHint::text("user-7 might be risky"),
        &env(&session.id, &branch),
    )
    .unwrap();

    // Query for a CLAIM about that subject: there is none. Nothing turned the observation into a
    // belief — an observation is what a source SAID, not what we believe.
    let q = AsOfQuery::new(&db);
    let answer = q
        .as_of(
            &token,
            &branch,
            "user-7",
            "status",
            AsOf::at(Timestamp::from_ms(NOW)),
        )
        .unwrap();
    assert!(
        answer.claim.is_none(),
        "AT-003: ingesting an observation must not create a claim. The observation is not a belief."
    );
}

/// **AT-016 — policy is re-evaluated at merge time, against the world as it is now.**
#[test]
fn at_016_merge_re_evaluates_policy_at_merge_time() {
    let db = Loom::in_memory(TenantId::new("acme"))
        .unwrap()
        .with_clock(|| NOW);
    let (session, token) = db.open_session().unwrap();
    let main = session.branch.clone();

    // A hypothesis branch writes a claim that is allowed *now*.
    let (h, htoken) = db.branch(&token, &main, "h").unwrap();
    let claim = Claim {
        id: ClaimId::of(b"c"),
        predicate: "flag".into(),
        subject: "acct".into(),
        object: Value::Bool(true),
        valid: Interval::from(Timestamp::from_ms(NOW)),
        known: Interval::from(Timestamp::from_ms(NOW)),
        confidence: Confidence::new(0.9, Method::Rule, "v1"),
        evidence: vec![SourceRef::new("erp", "r")],
        status: ClaimStatus::Asserted,
        policy: None,
        actor: ActorId::new("agent"),
    };
    db.write_indexed(
        &htoken,
        &h,
        b"claim/flag".to_vec(),
        Record::Claim(Box::new(claim)),
        IndexHint::text("flagged"),
        &env(&session.id, &h),
    )
    .unwrap();

    // Policy has since CHANGED: merging anything with key "claim/flag" onto main is now forbidden.
    // (In a real deployment the predicate wraps the policy engine; here it is the changed rule.)
    let forbid_flag = |key: &Key, _r: &Record| -> Option<String> {
        if key == b"claim/flag" {
            Some(
                "policy changed since the branch forked: this claim may no longer land on main"
                    .into(),
            )
        } else {
            None
        }
    };

    let result = db
        .merge_checked(
            &htoken,
            &h,
            &main,
            &MergePolicy::Conflict,
            &env(&session.id, &main),
            &forbid_flag,
        )
        .unwrap();
    assert!(
        matches!(result, MergeResult::PolicyRefused { .. }),
        "AT-016: the merge must be refused by the policy as it is NOW, not as it was at fork. Got: {result:?}"
    );

    // And nothing landed on main — a refused merge writes nothing.
    assert!(
        db.read(&token, &main, b"claim/flag").unwrap().is_none(),
        "a policy-refused merge must leave the target untouched"
    );
}

/// **AT-039 — a tenant cannot name, reach, or confirm the existence of another tenant's data.**
///
/// LoomDB is one tenant per store (the tenant *is* the substrate pool), so cross-tenant access is
/// structurally impossible: tenant A holds no handle to tenant B's engine, and A's capability token is
/// meaningless against B's. The strongest form of "cannot confirm existence" is that there is no shared
/// surface on which to even ask — a known-good identifier of B's is, from A, indistinguishable from one
/// that was never created, because A queries a different pool entirely.
#[test]
fn at_039_a_tenant_cannot_confirm_another_tenants_identifiers() {
    // Tenant B, with a real record under a known-good key.
    let db_b = Loom::in_memory(TenantId::new("tenant-b"))
        .unwrap()
        .with_clock(|| NOW);
    let (sb, tb) = db_b.open_session().unwrap();
    db_b.write_indexed(
        &tb,
        &sb.branch,
        b"secret/exists".to_vec(),
        Record::Observation(Box::new(Observation {
            id: ObservationId::of(b"s"),
            source: SourceRef::new("erp", "b-secret"),
            trust: TrustClass::VerifiedSystem,
            observed_at: None,
            ingested_at: Timestamp::from_ms(NOW),
            payload: b"exists".to_vec(),
        })),
        IndexHint::text("b's secret"),
        &env(&sb.id, &sb.branch),
    )
    .unwrap();

    // Tenant A, a completely separate engine.
    let db_a = Loom::in_memory(TenantId::new("tenant-a"))
        .unwrap()
        .with_clock(|| NOW);
    let (sa, ta) = db_a.open_session().unwrap();

    // From A, ask for B's known-good key, and for a key that never existed anywhere. A queries its OWN
    // pool — it has no handle to B's — so both come back the SAME: not found. A cannot tell that B's
    // identifier exists, because A is looking in a different place entirely.
    let b_known_good = db_a.read(&ta, &sa.branch, b"secret/exists").unwrap();
    let never_existed = db_a.read(&ta, &sa.branch, b"secret/never").unwrap();
    assert!(
        b_known_good.is_none(),
        "B's identifier must be invisible to A"
    );
    assert!(never_existed.is_none());
    assert_eq!(
        b_known_good.is_none(),
        never_existed.is_none(),
        "AT-039: 'B's real key' and 'a key that never existed' must be INDISTINGUISHABLE from tenant A — \
         a different error for 'exists but forbidden' would be an oracle that confirms existence"
    );

    // And B's capability token is meaningless against A's engine — cross-tenant tokens do not transfer.
    let cross = db_a.read(&tb, &sa.branch, b"secret/exists");
    assert!(
        cross.is_err(),
        "a token from another tenant must not authorize anything here"
    );
}
