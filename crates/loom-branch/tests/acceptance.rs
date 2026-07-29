//! L1 acceptance tests, against the catalog in `substrate/docs/05-loomdb-test-spec.md`.
//!
//! Each test names the `AT-` id it discharges. A capability is not done when it works — it is done
//! when the test that would have caught it failing is green.

use ed25519_dalek::{SigningKey, VerifyingKey};
use loom_branch::{
    actor_key_fingerprint, ActorRegistryAttestation, Loom, MemRefStore, MergePolicy, MergeResult,
};
use loom_core::{
    ActorId, BranchId, Claim, ClaimId, ClaimStatus, Confidence, Interval, LoomError, Method,
    Record, Result, SessionId, SourceRef, TenantId, Timestamp, Value, WriteEnvelope,
};
use std::collections::BTreeSet;
use std::sync::Arc;
use substrate_pager::{Pager, StoreConfig};

const NOW: u64 = 1_700_000_000_000;

fn loom() -> Loom {
    Loom::in_memory(TenantId::new("acme"))
        .expect("open")
        .with_clock(|| NOW)
}

fn envelope(branch: &BranchId) -> WriteEnvelope {
    WriteEnvelope::new(
        ActorId::new("agent-1"),
        SessionId::new("s1"),
        branch.clone(),
        "investigating the risk score increase",
    )
    .derived_from([SourceRef::new("idp", "signin-847223")])
}

fn counter(n: i64) -> Record {
    Record::Value(Value::Counter(n))
}

fn claim(method: Method, confidence: f64, object: Value) -> Record {
    Record::Claim(Box::new(Claim {
        id: ClaimId::new(),
        predicate: "identity.compromised".into(),
        subject: "user-4471".into(),
        object,
        valid: Interval::from(Timestamp::from_ms(NOW)),
        known: Interval::from(Timestamp::from_ms(NOW)),
        confidence: Confidence::new(confidence, method, "risk-v4"),
        evidence: vec![SourceRef::new("idp", "signin-847223")],
        status: ClaimStatus::Asserted,
        policy: None,
        actor: ActorId::new("agent-1"),
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// AT-001 — the envelope is mandatory
// ─────────────────────────────────────────────────────────────────────────────

/// **AT-001.** A write with no valid envelope is rejected at the entry point. No code path accepts it.
#[test]
fn at_001_a_write_without_an_envelope_is_refused() -> Result<()> {
    let db = loom();
    let (session, token) = db.open_session()?;

    // An envelope with no intent is not an envelope. "Why did the agent write this" is not optional.
    let mut bad = envelope(&session.branch);
    bad.intent = "   ".into();

    let err = db.write(&token, &session.branch, b"k".to_vec(), counter(1), &bad);
    assert!(
        matches!(err, Err(LoomError::MissingEnvelope)),
        "a write with no provenance must be refused: {err:?}"
    );

    // ...and nothing was written.
    assert_eq!(db.read(&token, &session.branch, b"k")?, None);

    // A complete envelope works.
    db.write(
        &token,
        &session.branch,
        b"k".to_vec(),
        counter(1),
        &envelope(&session.branch),
    )?;
    assert_eq!(db.read(&token, &session.branch, b"k")?, Some(counter(1)));
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// AT-010, AT-011, AT-019 — branching and isolation
// ─────────────────────────────────────────────────────────────────────────────

/// **AT-010.** A write in a branch is invisible in its base, and siblings never observe each other.
#[test]
fn at_010_branches_are_isolated_from_their_base_and_from_each_other() -> Result<()> {
    let db = loom();
    let (session, token) = db.open_session()?;

    db.write(
        &token,
        &session.branch,
        b"shared".to_vec(),
        counter(1),
        &envelope(&session.branch),
    )?;

    // Three hypotheses.
    let (h1, token) = db.branch(&token, &session.branch, "h1")?;
    let (h2, token) = db.branch(&token, &session.branch, "h2")?;
    let (h3, token) = db.branch(&token, &session.branch, "h3")?;

    db.write(
        &token,
        &h1,
        b"answer".to_vec(),
        counter(111),
        &envelope(&h1),
    )?;
    db.write(
        &token,
        &h2,
        b"answer".to_vec(),
        counter(222),
        &envelope(&h2),
    )?;

    // Each hypothesis sees only its own.
    assert_eq!(db.read(&token, &h1, b"answer")?, Some(counter(111)));
    assert_eq!(db.read(&token, &h2, b"answer")?, Some(counter(222)));
    assert_eq!(
        db.read(&token, &h3, b"answer")?,
        None,
        "h3 can see a sibling's write"
    );
    assert_eq!(
        db.read(&token, &session.branch, b"answer")?,
        None,
        "a branch leaked into its base"
    );

    // ...and all of them still see what was there before they forked.
    for branch in [&h1, &h2, &h3] {
        assert_eq!(db.read(&token, branch, b"shared")?, Some(counter(1)));
    }
    Ok(())
}

/// **AT-011.** Branch creation copies nothing, however large the database is.
#[test]
fn at_011_branch_creation_is_cheap_regardless_of_size() -> Result<()> {
    let db = loom();
    let (session, token) = db.open_session()?;

    // A few thousand records, enough to be a real tree with real splits.
    let records: Vec<_> = (0..3_000u64)
        .map(|n| (format!("key-{n:08}").into_bytes(), counter(n as i64)))
        .collect();
    db.write_many(&token, &session.branch, records, &envelope(&session.branch))?;

    let started = std::time::Instant::now();
    let (fork, token) = db.branch(&token, &session.branch, "experiment")?;
    let elapsed = started.elapsed();

    // The target is < 100ms warm (docs/03 §3.1). In memory it is microseconds; this asserts that
    // nothing has quietly started copying the database.
    assert!(
        elapsed.as_millis() < 100,
        "branching a 3,000-record database took {elapsed:?} — something is copying"
    );

    // And the fork really does have the data.
    assert_eq!(
        db.read(&token, &fork, b"key-00001500")?,
        Some(counter(1500))
    );
    Ok(())
}

/// **AT-019.** The token's scope is inescapable, through every surface.
#[test]
fn at_019_a_token_cannot_reach_outside_its_scope() -> Result<()> {
    let db = loom();

    let (alice, alice_token) = db.open_session_named(SessionId::new("alice"))?;
    let (bob, bob_token) = db.open_session_named(SessionId::new("bob"))?;

    db.write(
        &bob_token,
        &bob.branch,
        b"bob-secret".to_vec(),
        counter(42),
        &envelope(&bob.branch),
    )?;

    // Alice holds a valid token. It does not cover Bob's branch. Every operation must refuse.
    let reads = db.read(&alice_token, &bob.branch, b"bob-secret");
    assert!(matches!(reads, Err(LoomError::OutOfScope { .. })));

    let writes = db.write(
        &alice_token,
        &bob.branch,
        b"k".to_vec(),
        counter(1),
        &envelope(&bob.branch),
    );
    assert!(matches!(writes, Err(LoomError::OutOfScope { .. })));

    let scans = db.scan(&alice_token, &bob.branch);
    assert!(matches!(scans, Err(LoomError::OutOfScope { .. })));

    let rewinds = db.rewind(&alice_token, &bob.branch, &alice.base);
    assert!(matches!(rewinds, Err(LoomError::OutOfScope { .. })));

    let branches = db.branch(&alice_token, &bob.branch, "stolen");
    assert!(matches!(branches, Err(LoomError::OutOfScope { .. })));

    // Bob's data is untouched.
    assert_eq!(
        db.read(&bob_token, &bob.branch, b"bob-secret")?,
        Some(counter(42))
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// AT-012, AT-013, AT-014, AT-015, AT-017 — merge
// ─────────────────────────────────────────────────────────────────────────────

/// **AT-012.** **Merge is record-granular, not page-granular.**
///
/// Two branches write two *unrelated* facts. They land in the same physical page, because the
/// database is small and everything does. They must merge cleanly.
///
/// This is the bug the old design would have had: a merge engine that reports conflicts between
/// things that do not conflict is a merge engine that lies, and an agent would either escalate for
/// nothing or learn to ignore conflicts. Both are worse than having no merge.
#[test]
fn at_012_unrelated_facts_in_the_same_page_do_not_conflict() -> Result<()> {
    let db = loom();
    let (session, token) = db.open_session()?;

    db.write(
        &token,
        &session.branch,
        b"base".to_vec(),
        counter(1),
        &envelope(&session.branch),
    )?;

    let (a, token) = db.branch(&token, &session.branch, "a")?;
    let (b, token) = db.branch(&token, &session.branch, "b")?;

    // Two completely unrelated keys. In a database this small they are certainly in the same page.
    db.write(
        &token,
        &a,
        b"fact-from-a".to_vec(),
        counter(100),
        &envelope(&a),
    )?;
    db.write(
        &token,
        &b,
        b"fact-from-b".to_vec(),
        counter(200),
        &envelope(&b),
    )?;

    let result = db.merge(&token, &a, &b, &MergePolicy::Conflict, &envelope(&b))?;

    match &result {
        MergeResult::Merged { records, .. } => {
            assert_eq!(*records, 1, "only a's fact needs writing")
        }
        MergeResult::Conflict(report) => panic!(
            "two unrelated facts were reported as a conflict — the merge is page-granular:\n{report}"
        ),
        other => panic!("expected a clean merge, got {other:?}"),
    }

    // And b now has both.
    assert_eq!(db.read(&token, &b, b"fact-from-a")?, Some(counter(100)));
    assert_eq!(db.read(&token, &b, b"fact-from-b")?, Some(counter(200)));
    assert_eq!(db.read(&token, &b, b"base")?, Some(counter(1)));

    // a is untouched — a merge writes to the TARGET.
    assert_eq!(db.read(&token, &a, b"fact-from-b")?, None);
    Ok(())
}

/// **AT-013.** Two agents deriving the *same* fact is convergence, not conflict.
#[test]
fn at_013_convergent_edits_merge_silently() -> Result<()> {
    let db = loom();
    let (session, token) = db.open_session()?;

    let (a, token) = db.branch(&token, &session.branch, "a")?;
    let (b, token) = db.branch(&token, &session.branch, "b")?;

    // Both agents read the same source and reach the same conclusion.
    db.write(&token, &a, b"same".to_vec(), counter(7), &envelope(&a))?;
    db.write(&token, &b, b"same".to_vec(), counter(7), &envelope(&b))?;

    let result = db.merge(&token, &a, &b, &MergePolicy::Conflict, &envelope(&b))?;
    assert!(
        result.is_merged(),
        "two agents agreeing must not be a conflict: {result:?}"
    );
    assert_eq!(db.read(&token, &b, b"same")?, Some(counter(7)));
    Ok(())
}

/// **AT-014.** Two branches incrementing a counter yield the sum, not one of the values.
#[test]
fn at_014_counters_merge_arithmetically() -> Result<()> {
    let db = loom();
    let (session, token) = db.open_session()?;

    db.write(
        &token,
        &session.branch,
        b"tally".to_vec(),
        counter(10),
        &envelope(&session.branch),
    )?;

    let (a, token) = db.branch(&token, &session.branch, "a")?;
    let (b, token) = db.branch(&token, &session.branch, "b")?;

    db.write(&token, &a, b"tally".to_vec(), counter(13), &envelope(&a))?; // +3
    db.write(&token, &b, b"tally".to_vec(), counter(15), &envelope(&b))?; // +5

    let result = db.merge(&token, &a, &b, &MergePolicy::Conflict, &envelope(&b))?;
    assert!(result.is_merged(), "counters must not conflict: {result:?}");

    assert_eq!(
        db.read(&token, &b, b"tally")?,
        Some(counter(18)),
        "10 + 3 + 5 = 18. Taking either side's absolute value would silently discard the other \
         agent's work while reporting a clean merge."
    );
    Ok(())
}

/// **AT-015.** A verified claim outranks one a language model inferred.
#[test]
fn at_015_provenance_rank_breaks_a_tie() -> Result<()> {
    let db = loom();
    let (session, token) = db.open_session()?;

    let (a, token) = db.branch(&token, &session.branch, "a")?;
    let (b, token) = db.branch(&token, &session.branch, "b")?;

    // A very confident language model...
    db.write(
        &token,
        &a,
        b"claim/user-4471".to_vec(),
        claim(Method::LanguageModel, 0.99, Value::Bool(true)),
        &envelope(&a),
    )?;
    // ...versus a less confident direct reading of a verified system record.
    db.write(
        &token,
        &b,
        b"claim/user-4471".to_vec(),
        claim(Method::Direct, 0.60, Value::Bool(false)),
        &envelope(&b),
    )?;

    let result = db.merge(&token, &a, &b, &MergePolicy::Conflict, &envelope(&b))?;
    assert!(
        result.is_merged(),
        "provenance rank should resolve this: {result:?}"
    );

    let Some(Record::Claim(winner)) = db.read(&token, &b, b"claim/user-4471")? else {
        panic!("expected a claim");
    };
    assert_eq!(
        winner.confidence.method,
        Method::Direct,
        "a confident language model beat a verified system record"
    );
    assert_eq!(winner.object, Value::Bool(false));
    Ok(())
}

/// **AT-017.** A genuine conflict produces a report a language model could act on.
#[test]
fn at_017_a_merge_conflict_is_legible_to_a_model() -> Result<()> {
    let db = loom();
    let (session, token) = db.open_session()?;

    let (a, token) = db.branch(&token, &session.branch, "a")?;
    let (b, token) = db.branch(&token, &session.branch, "b")?;

    // Same method, same confidence, overlapping validity, opposite conclusions. There is genuinely no
    // principled way to choose, and the engine must not fabricate one.
    db.write(
        &token,
        &a,
        b"claim/user-4471".to_vec(),
        claim(Method::Rule, 0.9, Value::Bool(true)),
        &envelope(&a),
    )?;
    db.write(
        &token,
        &b,
        b"claim/user-4471".to_vec(),
        claim(Method::Rule, 0.9, Value::Bool(false)),
        &envelope(&b),
    )?;

    let result = db.merge(&token, &a, &b, &MergePolicy::Conflict, &envelope(&b))?;

    let MergeResult::Conflict(report) = result else {
        panic!("equal provenance and overlapping validity must be an honest conflict");
    };

    assert_eq!(report.conflicts.len(), 1);
    let conflict = &report.conflicts[0];

    // The key is readable, not a hash.
    assert_eq!(conflict.key, "claim/user-4471");
    // The sides are described, not enumerated.
    assert!(conflict
        .source
        .as_ref()
        .is_some_and(|s| s.contains("claim")));
    assert!(conflict
        .target
        .as_ref()
        .is_some_and(|s| s.contains("claim")));
    // And the reason tells a model what to DO.
    assert!(conflict.reason.contains("decide, or supersede"));

    // The whole report renders as something a person could read at 3am.
    let rendered = report.to_string();
    assert!(rendered.contains("claim/user-4471"));
    assert!(rendered.contains("base:"));

    // Nothing was written. A failed merge changes nothing.
    let Some(Record::Claim(unchanged)) = db.read(&token, &b, b"claim/user-4471")? else {
        panic!("expected a claim");
    };
    assert_eq!(
        unchanged.object,
        Value::Bool(false),
        "a conflict must not merge"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// AT-018 — rewind
// ─────────────────────────────────────────────────────────────────────────────

/// **AT-018.** Rewind abandons without destroying — the discarded hypothesis stays auditable.
#[test]
fn at_018_a_rewound_branch_is_still_auditable() -> Result<()> {
    let db = loom();
    let (session, token) = db.open_session()?;

    db.write(
        &token,
        &session.branch,
        b"k".to_vec(),
        counter(1),
        &envelope(&session.branch),
    )?;
    let v1 = db.head(&session.branch)?;

    db.write(
        &token,
        &session.branch,
        b"k".to_vec(),
        counter(2),
        &envelope(&session.branch),
    )?;
    let v2 = db.head(&session.branch)?;

    db.write(
        &token,
        &session.branch,
        b"k".to_vec(),
        counter(3),
        &envelope(&session.branch),
    )?;
    let v3 = db.head(&session.branch)?;

    // The agent decides the last two attempts were wrong.
    db.rewind(&token, &session.branch, &v1)?;
    assert_eq!(db.read(&token, &session.branch, b"k")?, Some(counter(1)));

    // But the abandoned attempts are STILL THERE. "What did the agent try and discard, and why" is a
    // question with an answer — which is the whole point of rewinding rather than rolling back.
    assert_eq!(
        db.read_at(&token, &session.branch, &v2, b"k")?,
        Some(counter(2))
    );
    assert_eq!(
        db.read_at(&token, &session.branch, &v3, b"k")?,
        Some(counter(3))
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// The narrative: the Q3 demo, in miniature (substrate/docs/04 §3.1)
// ─────────────────────────────────────────────────────────────────────────────

/// Three hypotheses, one merged, two rewound — and the whole history still readable.
#[test]
fn the_three_hypothesis_scenario() -> Result<()> {
    let db = loom();
    let (session, token) = db.open_session()?;

    // The agent knows one thing to start with.
    db.write(
        &token,
        &session.branch,
        b"observation/signin".to_vec(),
        counter(1),
        &envelope(&session.branch),
    )?;

    // It tries three explanations.
    let (h1, token) = db.branch(&token, &session.branch, "h1-credential-stuffing")?;
    let (h2, token) = db.branch(&token, &session.branch, "h2-travel")?;
    let (h3, token) = db.branch(&token, &session.branch, "h3-compromised-device")?;

    db.write(
        &token,
        &h1,
        b"claim/cause".to_vec(),
        claim(
            Method::LanguageModel,
            0.4,
            Value::Text("credential stuffing".into()),
        ),
        &envelope(&h1),
    )?;
    db.write(
        &token,
        &h2,
        b"claim/cause".to_vec(),
        claim(
            Method::Direct,
            0.9,
            Value::Text("the user is in Belarus".into()),
        ),
        &envelope(&h2),
    )?;
    db.write(
        &token,
        &h3,
        b"claim/cause".to_vec(),
        claim(
            Method::Statistical,
            0.5,
            Value::Text("compromised device".into()),
        ),
        &envelope(&h3),
    )?;

    // h2 won: it is grounded in a verified system record rather than a model's guess.
    let result = db.merge(
        &token,
        &h2,
        &session.branch,
        &MergePolicy::Conflict,
        &envelope(&session.branch),
    )?;
    assert!(result.is_merged(), "{result:?}");

    let Some(Record::Claim(winner)) = db.read(&token, &session.branch, b"claim/cause")? else {
        panic!("the winning hypothesis should be on the session branch");
    };
    assert_eq!(winner.object, Value::Text("the user is in Belarus".into()));

    // The losing hypotheses are rewound — and remain fully readable. Nothing an agent thought is
    // ever destroyed; it is only unreferenced.
    let h1_head = db.head(&h1)?;
    let h3_head = db.head(&h3)?;
    db.rewind(&token, &h1, &session.base)?;
    db.rewind(&token, &h3, &session.base)?;

    assert!(
        db.read_at(&token, &h1, &h1_head, b"claim/cause")?.is_some(),
        "a discarded hypothesis must still be auditable"
    );
    assert!(db.read_at(&token, &h3, &h3_head, b"claim/cause")?.is_some());

    // Six branches exist: main, the session, and the three hypotheses.
    let names: BTreeSet<String> = db.branch_names().into_iter().collect();
    assert!(names.contains("main"));
    assert!(names.contains("h1-credential-stuffing"));
    assert!(names.contains("h2-travel"));
    Ok(())
}

/// **Criss-cross merges are refused, not guessed.**
///
/// Once two branches have absorbed each other's work *concurrently*, their history has more than one
/// equally-valid merge base. A three-way merge takes exactly one, and picking one arbitrarily produces
/// an answer that is deterministic, defensible, and **wrong** in a way nobody will ever notice — for a
/// counter it silently over- or under-counts.
///
/// git's answer is a recursive merge over a virtual base. That is the right answer and it is not built
/// yet, so the engine says so out loud. A database that admits it does not know is worth more than one
/// that guesses confidently.
///
/// The model oracle found this by generating a criss-cross and disagreeing about the result.
///
/// # Building a real one
///
/// Two *sequential* merges do not criss-cross: the second absorbs the first, and a single base still
/// exists. (My first attempt at this test made exactly that mistake and passed for the wrong reason.)
/// You need two merges that are **concurrent** — each absorbing the other side as it was *before* the
/// other merge happened. A snapshot branch pinned at the old head is how you get one.
#[test]
fn a_criss_cross_history_is_refused_rather_than_guessed() -> Result<()> {
    let db = loom();
    let (session, token) = db.open_session()?;

    db.write(
        &token,
        &session.branch,
        b"tally".to_vec(),
        counter(0),
        &envelope(&session.branch),
    )?;

    let (a, token) = db.branch(&token, &session.branch, "a")?;
    let (b, token) = db.branch(&token, &session.branch, "b")?;

    db.write(&token, &a, b"a-work".to_vec(), counter(1), &envelope(&a))?;
    db.write(&token, &b, b"b-work".to_vec(), counter(2), &envelope(&b))?;

    // Pin each branch's head as it is RIGHT NOW, before either merge.
    let (a_pinned, token) = db.branch(&token, &a, "a-pinned")?;
    let (b_pinned, token) = db.branch(&token, &b, "b-pinned")?;

    // Two CONCURRENT merges: a absorbs b-as-it-was, and b absorbs a-as-it-was. Neither merge commit
    // descends from the other, so `a` and `b` now share two unrelated ancestors.
    let into_a = db.merge(&token, &b_pinned, &a, &MergePolicy::Conflict, &envelope(&a))?;
    assert!(into_a.is_merged(), "{into_a:?}");

    let into_b = db.merge(&token, &a_pinned, &b, &MergePolicy::Conflict, &envelope(&b))?;
    assert!(into_b.is_merged(), "{into_b:?}");

    // Both branches move on.
    db.write(&token, &a, b"tally".to_vec(), counter(5), &envelope(&a))?;
    db.write(&token, &b, b"tally".to_vec(), counter(9), &envelope(&b))?;

    // Now there is no single correct base.
    let ambiguous = db.merge(&token, &a, &b, &MergePolicy::Conflict, &envelope(&b))?;

    match ambiguous {
        MergeResult::AmbiguousHistory { bases, detail } => {
            assert!(bases > 1, "expected several merge bases, got {bases}");
            assert!(
                detail.contains("merged each other"),
                "the message must explain WHY, not merely refuse: {detail}"
            );
            assert!(
                detail.contains("Merge one direction only"),
                "and it must say what to DO about it: {detail}"
            );
        }
        other => panic!(
            "a criss-crossed history has several equally-valid merge bases. Picking one silently \
             produces a number nobody can justify. Expected a refusal, got {other:?}"
        ),
    }
    Ok(())
}

// ── AT-026 — envelope signatures verify ─────────────────────────────────────────────────────────
//
// AT-001 gets the envelope's *shape*: a write with no actor, session, branch, or intent is refused.
// That makes a write **attributable**. It does not make it **true**. Until something checks the
// signature, "who wrote this" is a field the writer fills in about itself, and an audit trail built
// on it is a work of fiction the moment two agents can reach the same database.

fn keypair(seed: u8) -> (SigningKey, VerifyingKey) {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

/// **A signed write from a registered actor is accepted; an unsigned one is refused.**
#[test]
fn at_026_an_unsigned_write_is_refused_when_the_database_authenticates_writers() -> Result<()> {
    let (signing, verifying) = keypair(1);
    let actor = ActorId::new("agent-1");

    let db = Loom::in_memory(TenantId::new("acme"))?
        .with_clock(|| NOW)
        .with_actor_keys([(actor.clone(), verifying)]);

    let (session, token) = db.open_session()?;

    let unsigned = WriteEnvelope::new(
        actor.clone(),
        session.id.clone(),
        session.branch.clone(),
        "write without signing",
    );

    let refused = db.write(
        &token,
        &session.branch,
        b"k".to_vec(),
        Record::Value(Value::Counter(1)),
        &unsigned,
    );

    assert!(
        matches!(refused, Err(LoomError::EnvelopeUnsigned { .. })),
        "an unsigned write must be refused by a database that authenticates its writers: {refused:?}"
    );

    // Nothing was written. A refused write must not leave a trace, or "refused" is a lie.
    assert!(db.read(&token, &session.branch, b"k")?.is_none());

    // The same write, signed, goes through.
    let signed = WriteEnvelope::new(
        actor,
        session.id.clone(),
        session.branch.clone(),
        "write without signing",
    )
    .signed_by(&signing);

    db.write(
        &token,
        &session.branch,
        b"k".to_vec(),
        Record::Value(Value::Counter(1)),
        &signed,
    )?;
    assert!(db.read(&token, &session.branch, b"k")?.is_some());

    Ok(())
}

/// **The production constructor cannot forget authentication or boot with an empty registry.**
#[test]
fn at_026_production_construction_requires_and_enforces_actor_keys() -> Result<()> {
    let empty_path = tempfile::tempdir().expect("temporary database directory");
    let refused =
        Loom::open_production(empty_path.path(), TenantId::new("acme"), std::iter::empty());
    assert!(
        matches!(refused, Err(LoomError::InvalidSecurityConfiguration { .. })),
        "production must refuse to construct without at least one trusted actor: {refused:?}"
    );

    let path = tempfile::tempdir().expect("temporary database directory");
    let (signing, verifying) = keypair(9);
    let actor = ActorId::new("agent-1");
    let db = Loom::open_production(
        path.path(),
        TenantId::new("acme"),
        [(actor.clone(), verifying)],
    )?
    .with_clock(|| NOW);
    let (session, token) = db.open_session()?;
    let unsigned = WriteEnvelope::new(
        actor.clone(),
        session.id.clone(),
        session.branch.clone(),
        "unsigned production write",
    );

    let refused = db.write(
        &token,
        &session.branch,
        b"k".to_vec(),
        counter(1),
        &unsigned,
    );
    assert!(
        matches!(refused, Err(LoomError::EnvelopeUnsigned { .. })),
        "a production database must reject unsigned writes: {refused:?}"
    );

    let signed = WriteEnvelope::new(
        actor,
        session.id.clone(),
        session.branch.clone(),
        "authenticated production write",
    )
    .signed_by(&signing);
    db.write(&token, &session.branch, b"k".to_vec(), counter(1), &signed)?;
    assert_eq!(db.read(&token, &session.branch, b"k")?, Some(counter(1)));
    Ok(())
}

/// **Live rotation is atomic; an old key stops working and revocation stops the new one.**
#[test]
fn at_026_actor_keys_rotate_and_revoke_without_reopening() -> Result<()> {
    let (old_signing, old_verifying) = keypair(10);
    let (new_signing, new_verifying) = keypair(11);
    let actor = ActorId::new("agent-1");
    let db = Loom::in_memory(TenantId::new("acme"))?
        .with_actor_keys([(actor.clone(), old_verifying)])
        .with_clock(|| NOW);
    let (session, token) = db.open_session()?;

    let old_envelope = WriteEnvelope::new(
        actor.clone(),
        session.id.clone(),
        session.branch.clone(),
        "write with the original key",
    )
    .signed_by(&old_signing);
    db.write(
        &token,
        &session.branch,
        b"before-rotation".to_vec(),
        counter(1),
        &old_envelope,
    )?;

    db.rotate_actor_key(actor.clone(), new_verifying)?;
    let old_after_rotation = db.write(
        &token,
        &session.branch,
        b"old-after-rotation".to_vec(),
        counter(1),
        &old_envelope,
    );
    assert!(
        matches!(
            old_after_rotation,
            Err(LoomError::EnvelopeSignatureInvalid { .. })
        ),
        "the old key remained valid after rotation: {old_after_rotation:?}"
    );

    let new_envelope = WriteEnvelope::new(
        actor.clone(),
        session.id.clone(),
        session.branch.clone(),
        "write with the rotated key",
    )
    .signed_by(&new_signing);
    db.write(
        &token,
        &session.branch,
        b"after-rotation".to_vec(),
        counter(2),
        &new_envelope,
    )?;

    assert!(db.revoke_actor_key(&actor)?);
    let after_revocation = db.write(
        &token,
        &session.branch,
        b"after-revocation".to_vec(),
        counter(3),
        &new_envelope,
    );
    assert!(
        matches!(after_revocation, Err(LoomError::UnknownActor { .. })),
        "the actor remained trusted after revocation: {after_revocation:?}"
    );
    Ok(())
}

/// **A durable production store refuses an actor registry that differs from its external pin.**
#[test]
fn at_026_production_restart_requires_the_pinned_actor_registry() -> Result<()> {
    let path = tempfile::tempdir().expect("temporary database directory");
    let actor = ActorId::new("agent-1");
    let (_, original_key) = keypair(12);
    let (_, unexpected_key) = keypair(13);
    let expected = actor_key_fingerprint([(actor.clone(), original_key)]);

    let db = Loom::open_production_pinned(
        path.path(),
        TenantId::new("acme"),
        [(actor.clone(), original_key)],
        &expected,
    )?;
    drop(db);

    let refused = Loom::open_production_pinned(
        path.path(),
        TenantId::new("acme"),
        [(actor, unexpected_key)],
        &expected,
    );
    assert!(
        matches!(
            &refused,
            Err(LoomError::InvalidSecurityConfiguration { .. })
        ),
        "a changed actor registry was trusted after restart: {refused:?}"
    );
    let detail = refused.unwrap_err().to_string();
    assert!(detail.contains("fingerprint mismatch"), "{detail}");
    Ok(())
}

/// **Caller-supplied/tiered storage enforces the same external registry pin.**
#[test]
fn at_026_tiered_production_storage_requires_the_pinned_registry() -> Result<()> {
    let actor = ActorId::new("agent-1");
    let (_, trusted_key) = keypair(14);
    let expected = actor_key_fingerprint([(actor.clone(), trusted_key)]);
    let pager = Arc::new(Pager::in_memory(StoreConfig {
        pool: "acme".into(),
        ..Default::default()
    })?);
    let store = Arc::new(MemRefStore::new());

    let refused = Loom::on_production_pinned(
        pager,
        store,
        TenantId::new("acme"),
        [(actor, trusted_key)],
        &"0".repeat(64),
    );
    assert!(
        matches!(refused, Err(LoomError::InvalidSecurityConfiguration { .. })),
        "tiered storage bypassed the external registry pin: {refused:?}"
    );
    assert_ne!(expected, "0".repeat(64));
    Ok(())
}

/// **A signed registry cannot be forged, substituted, or replayed below the deployment floor.**
#[test]
fn at_026_production_registry_attestation_is_signed_and_rollback_resistant() -> Result<()> {
    let tenant = TenantId::new("acme");
    let actor = ActorId::new("agent-1");
    let (_, actor_key) = keypair(15);
    let (_, substituted_key) = keypair(16);
    let (governance_signing, governance_verifying) = keypair(17);
    let (rogue_governance, _) = keypair(18);
    let keys = [(actor.clone(), actor_key)];
    let attestation =
        ActorRegistryAttestation::issue(tenant.clone(), 7, keys.clone(), &governance_signing);
    let attestation = ActorRegistryAttestation::from_json(&attestation.to_json()?)?;
    assert_eq!(attestation.generation(), 7);
    assert_eq!(
        attestation.fingerprint(),
        actor_key_fingerprint(keys.clone())
    );

    let path = tempfile::tempdir().expect("temporary database directory");
    let db = Loom::open_production_attested(
        path.path(),
        tenant.clone(),
        keys.clone(),
        &attestation,
        &governance_verifying,
        7,
    )?;
    drop(db);

    let rollback = match Loom::open_production_attested(
        path.path(),
        tenant.clone(),
        keys.clone(),
        &attestation,
        &governance_verifying,
        8,
    ) {
        Err(error) => error,
        Ok(_) => panic!("a signed but stale registry bypassed the generation floor"),
    };
    assert!(
        rollback.to_string().contains("rollback refused"),
        "{rollback}"
    );

    let substituted = match Loom::open_production_attested(
        path.path(),
        tenant.clone(),
        [(actor.clone(), substituted_key)],
        &attestation,
        &governance_verifying,
        7,
    ) {
        Err(error) => error,
        Ok(_) => panic!("an unattested actor key registry was trusted"),
    };
    assert!(
        substituted.to_string().contains("fingerprint mismatch"),
        "{substituted}"
    );

    let forged =
        ActorRegistryAttestation::issue(tenant.clone(), 8, keys.clone(), &rogue_governance);
    let forged_error = match Loom::open_production_attested(
        path.path(),
        tenant,
        keys,
        &forged,
        &governance_verifying,
        7,
    ) {
        Err(error) => error,
        Ok(_) => panic!("a registry signed by an untrusted governance key was trusted"),
    };
    assert!(
        forged_error.to_string().contains("signature is invalid"),
        "{forged_error}"
    );
    Ok(())
}

/// **You cannot write as somebody else.** This is the one that matters.
///
/// An agent holding its own valid key signs an envelope, then claims to be a different actor — the
/// compliance bot, the human reviewer, whoever is trusted. Verification is performed against the key
/// of the actor the envelope *claims to be*, not the one that signed it, so it fails.
///
/// If this test ever goes green by accident — say, by looking up the key by the signature instead of
/// by the claimed actor — then every agent can write as every other agent, and provenance is theatre.
#[test]
fn at_026_an_actor_cannot_impersonate_another_actor() -> Result<()> {
    let (attacker_key, attacker_pub) = keypair(2);
    let (_, victim_pub) = keypair(3);

    let attacker = ActorId::new("scraper-bot");
    let victim = ActorId::new("compliance-officer");

    let db = Loom::in_memory(TenantId::new("acme"))?
        .with_clock(|| NOW)
        .with_actor_keys([
            (attacker.clone(), attacker_pub),
            (victim.clone(), victim_pub),
        ]);

    let (session, token) = db.open_session()?;

    // Signed with the attacker's own, perfectly valid, registered key — but claiming to be the
    // compliance officer.
    let forged = WriteEnvelope::new(
        victim,
        session.id.clone(),
        session.branch.clone(),
        "approved by compliance",
    )
    .signed_by(&attacker_key);

    let refused = db.write(
        &token,
        &session.branch,
        b"approval".to_vec(),
        Record::Value(Value::Bool(true)),
        &forged,
    );

    assert!(
        matches!(refused, Err(LoomError::EnvelopeSignatureInvalid { .. })),
        "an actor signed with its OWN valid key but claimed to be someone else, and the write was \
         not refused. Every agent can now write as every other agent: {refused:?}"
    );
    assert!(db.read(&token, &session.branch, b"approval")?.is_none());

    Ok(())
}

/// **The signature covers the intent.** Altering *why* a write happened invalidates it.
///
/// `intent` is the field an auditor actually reads. A signature that covered the actor but not the
/// stated purpose would let an attacker keep a valid signature while rewriting the reason — the write
/// would verify, and the audit trail would say whatever the attacker wanted it to say.
#[test]
fn at_026_tampering_with_the_intent_breaks_the_signature() -> Result<()> {
    let (signing, verifying) = keypair(4);
    let actor = ActorId::new("agent-1");

    let db = Loom::in_memory(TenantId::new("acme"))?
        .with_clock(|| NOW)
        .with_actor_keys([(actor.clone(), verifying)]);

    let (session, token) = db.open_session()?;

    let mut envelope = WriteEnvelope::new(
        actor,
        session.id.clone(),
        session.branch.clone(),
        "routine refresh of a cached value",
    )
    .signed_by(&signing);

    // Same signature. Different story.
    envelope.intent = "authorized by the customer over the phone".into();

    let refused = db.write(
        &token,
        &session.branch,
        b"k".to_vec(),
        Record::Value(Value::Counter(1)),
        &envelope,
    );

    assert!(
        matches!(refused, Err(LoomError::EnvelopeSignatureInvalid { .. })),
        "the intent was rewritten after signing and the write was accepted. The signature does not \
         cover the field the auditor reads: {refused:?}"
    );

    Ok(())
}

/// **An actor nobody registered is refused, not trusted.** Fail closed.
///
/// Failing open here is the interesting bug: an attacker picks an actor name that has never been
/// registered — `"acme-compliance-bot"` — and, because there is no key to check against, the write
/// sails through and the audit trail records a ghost as its author.
#[test]
fn at_026_an_unregistered_actor_is_refused_rather_than_trusted() -> Result<()> {
    let (signing, verifying) = keypair(5);

    let db = Loom::in_memory(TenantId::new("acme"))?
        .with_clock(|| NOW)
        .with_actor_keys([(ActorId::new("agent-1"), verifying)]);

    let (session, token) = db.open_session()?;

    let ghost = WriteEnvelope::new(
        ActorId::new("acme-compliance-bot"), // never registered
        session.id.clone(),
        session.branch.clone(),
        "approved",
    )
    .signed_by(&signing);

    let refused = db.write(
        &token,
        &session.branch,
        b"k".to_vec(),
        Record::Value(Value::Counter(1)),
        &ghost,
    );

    assert!(
        matches!(refused, Err(LoomError::UnknownActor { .. })),
        "an actor with no registered key must be REFUSED, not trusted. Failing open here lets an \
         attacker invent an authoritative-sounding name and write as it: {refused:?}"
    );

    Ok(())
}
