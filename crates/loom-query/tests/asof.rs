//! **AT-004, AT-005, AT-006, AT-009 — the bitemporal as-of query.**
//!
//! A claim carries two intervals: *valid* (when it holds in the world) and *known* (when we believed
//! it). Asserting the same `(subject, predicate)` again closes the prior belief's known interval and
//! opens a new one — never an overwrite — so every past belief stays answerable. These tests drive the
//! real engine and query it as of specific coordinates.

use loom_branch::Loom;
use loom_core::{
    ActorId, BranchId, Claim, ClaimId, ClaimStatus, Confidence, IndexHint, Interval, Method,
    Record, SessionId, SourceRef, TenantId, Timestamp, Value, WriteEnvelope,
};
use loom_query::{AsOf, AsOfQuery};

const WEEK: u64 = 7 * 24 * 3_600_000;
const T_LAST_WEEK: u64 = 1_700_000_000_000 - WEEK;
const T_NOW: u64 = 1_700_000_000_000;
const T_LATER: u64 = 1_700_000_000_000 + WEEK;

fn env(session: &SessionId, branch: &BranchId) -> WriteEnvelope {
    WriteEnvelope::new(
        ActorId::new("agent"),
        session.clone(),
        branch.clone(),
        "assert",
    )
}

/// A claim with explicit valid and known intervals — the two time axes, under the test's control.
fn claim(subject: &str, object: bool, valid: Interval, known: Interval) -> Claim {
    Claim {
        id: ClaimId::of(format!("{subject}-{object}-{:?}", known.start).as_bytes()),
        predicate: "status".into(),
        subject: subject.into(),
        object: Value::Bool(object),
        valid,
        known,
        confidence: Confidence::new(0.9, Method::Rule, "v1"),
        evidence: vec![SourceRef::new("erp", "r1")],
        status: ClaimStatus::Asserted,
        policy: None,
        actor: ActorId::new("agent"),
    }
}

fn assert_claim(
    db: &Loom,
    token: &loom_branch::CapabilityToken,
    branch: &BranchId,
    sid: &SessionId,
    key: &str,
    c: Claim,
) {
    db.write_indexed(
        token,
        branch,
        key.as_bytes().to_vec(),
        Record::Claim(Box::new(c)),
        IndexHint::text("a claim"),
        &env(sid, branch),
    )
    .unwrap();
}

/// **AT-004 — late arrival. The two axes are independent.**
#[test]
fn at_004_a_late_arriving_fact_is_excluded_by_known_at_but_included_by_valid_at() {
    let db = Loom::in_memory(TenantId::new("acme"))
        .unwrap()
        .with_clock(|| T_NOW);
    let (session, token) = db.open_session().unwrap();
    let branch = session.branch.clone();

    // TODAY, we ingest a claim that HELD last week (valid from last week) — we only KNOW it now.
    assert_claim(
        &db,
        &token,
        &branch,
        &session.id,
        "user-1",
        claim(
            "user-1",
            true,
            Interval::from(Timestamp::from_ms(T_LAST_WEEK)), // valid: since last week
            Interval::from(Timestamp::from_ms(T_NOW)),       // known: since today
        ),
    );

    let q = AsOfQuery::new(&db);

    // "What did we KNOW last week?" — nothing, we had not learned it yet.
    let as_known_last_week = q
        .as_of(
            &token,
            &branch,
            "user-1",
            "status",
            AsOf {
                valid_at: Timestamp::from_ms(T_LAST_WEEK),
                known_at: Timestamp::from_ms(T_LAST_WEEK),
            },
        )
        .unwrap();
    assert!(
        as_known_last_week.claim.is_none(),
        "AT-004: as of what we knew last week, this late-arriving fact must be EXCLUDED"
    );

    // "What HELD last week, as of what we know TODAY?" — it did, and now we know.
    let as_known_today = q
        .as_of(
            &token,
            &branch,
            "user-1",
            "status",
            AsOf {
                valid_at: Timestamp::from_ms(T_LAST_WEEK),
                known_at: Timestamp::from_ms(T_NOW),
            },
        )
        .unwrap();
    assert!(
        as_known_today.claim.is_some(),
        "AT-004: valid last week + known today must INCLUDE it — the two axes are independent"
    );
}

/// **AT-005 — a correction closes the prior belief, it does not overwrite it.**
#[test]
fn at_005_correction_preserves_the_old_belief_forever() {
    let db = Loom::in_memory(TenantId::new("acme"))
        .unwrap()
        .with_clock(|| T_NOW);
    let (session, token) = db.open_session().unwrap();
    let branch = session.branch.clone();

    // We believed `false`, starting now.
    assert_claim(
        &db,
        &token,
        &branch,
        &session.id,
        "acct-9",
        claim(
            "acct-9",
            false,
            Interval::unknown(),
            Interval::from(Timestamp::from_ms(T_NOW)),
        ),
    );
    // Later we correct it to `true`, starting later.
    assert_claim(
        &db,
        &token,
        &branch,
        &session.id,
        "acct-9",
        claim(
            "acct-9",
            true,
            Interval::unknown(),
            Interval::from(Timestamp::from_ms(T_LATER)),
        ),
    );

    let q = AsOfQuery::new(&db);

    // As of what we knew right after the FIRST assertion, the belief is still `false`, forever.
    let old = q
        .as_of(
            &token,
            &branch,
            "acct-9",
            "status",
            AsOf::at(Timestamp::from_ms(T_NOW)),
        )
        .unwrap();
    assert_eq!(
        old.claim.map(|c| c.object),
        Some(Value::Bool(false)),
        "AT-005: querying as-of the old known-time must return the OLD belief, unchanged, forever"
    );

    // As of now (after the correction), the belief is `true`.
    let new = q
        .as_of(
            &token,
            &branch,
            "acct-9",
            "status",
            AsOf::at(Timestamp::from_ms(T_LATER)),
        )
        .unwrap();
    assert_eq!(
        new.claim.map(|c| c.object),
        Some(Value::Bool(true)),
        "the corrected belief is current"
    );
}

/// **AT-006 — supersession keeps the old version queryable, and the current one is deterministic.**
#[test]
fn at_006_a_superseded_claim_remains_queryable() {
    let db = Loom::in_memory(TenantId::new("acme"))
        .unwrap()
        .with_clock(|| T_NOW);
    let (session, token) = db.open_session().unwrap();
    let branch = session.branch.clone();

    assert_claim(
        &db,
        &token,
        &branch,
        &session.id,
        "doc-1",
        claim(
            "doc-1",
            false,
            Interval::unknown(),
            Interval::from(Timestamp::from_ms(T_NOW)),
        ),
    );
    assert_claim(
        &db,
        &token,
        &branch,
        &session.id,
        "doc-1",
        claim(
            "doc-1",
            true,
            Interval::unknown(),
            Interval::from(Timestamp::from_ms(T_LATER)),
        ),
    );

    let q = AsOfQuery::new(&db);
    // The superseded version is still there, at its old known-time.
    let superseded = q
        .as_of(
            &token,
            &branch,
            "doc-1",
            "status",
            AsOf::at(Timestamp::from_ms(T_NOW)),
        )
        .unwrap();
    assert_eq!(
        superseded.claim.map(|c| c.status),
        Some(ClaimStatus::Superseded),
        "the old version is retained, marked Superseded — not deleted"
    );

    // The current one is deterministic: the latest by sequence.
    let current = q
        .as_of(
            &token,
            &branch,
            "doc-1",
            "status",
            AsOf::at(Timestamp::from_ms(T_LATER)),
        )
        .unwrap();
    assert_eq!(current.claim.map(|c| c.object), Some(Value::Bool(true)));
}

/// **AT-009 — an as-of query states the coordinates it used, and re-issuing them is identical.**
#[test]
fn at_009_an_as_of_answer_is_reproducible() {
    let db = Loom::in_memory(TenantId::new("acme"))
        .unwrap()
        .with_clock(|| T_NOW);
    let (session, token) = db.open_session().unwrap();
    let branch = session.branch.clone();

    assert_claim(
        &db,
        &token,
        &branch,
        &session.id,
        "kpi",
        claim(
            "kpi",
            true,
            Interval::from(Timestamp::from_ms(T_LAST_WEEK)),
            Interval::from(Timestamp::from_ms(T_NOW)),
        ),
    );

    let q = AsOfQuery::new(&db);
    let coords = AsOf::at(Timestamp::from_ms(T_NOW));

    let first = q.as_of(&token, &branch, "kpi", "status", coords).unwrap();
    // The answer STATES the coordinates it used — they are not implicit.
    assert_eq!(
        first.as_of, coords,
        "the answer must record the exact coordinates it was answered at"
    );

    // Re-issuing with those exact coordinates returns an identical answer.
    let second = q
        .as_of(&token, &branch, "kpi", "status", first.as_of)
        .unwrap();
    assert_eq!(
        first, second,
        "AT-009: the same coordinates must return byte-identical results"
    );
}
