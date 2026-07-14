//! L2 acceptance tests: AT-002, AT-020, AT-021, AT-023, AT-024, AT-025.

use loom_branch::{Loom, MergePolicy, MergeResult};
use loom_core::{
    ActorId, BranchId, Claim, ClaimId, ClaimStatus, Confidence, Interval, Method, Observation,
    ObservationId, Record, Result, SessionId, SourceRef, TenantId, Timestamp, TrustClass, Value,
    WriteEnvelope,
};
use loom_provenance::Provenance;

const NOW: u64 = 1_700_000_000_000;

fn loom() -> Loom {
    Loom::in_memory(TenantId::new("acme"))
        .expect("open")
        .with_clock(|| NOW)
}

fn envelope(session: &SessionId, branch: &BranchId, intent: &str) -> WriteEnvelope {
    WriteEnvelope::new(
        ActorId::new("agent-1"),
        session.clone(),
        branch.clone(),
        intent,
    )
}

fn observation(source: SourceRef, trust: TrustClass, payload: &[u8]) -> Record {
    Record::Observation(Box::new(Observation {
        id: ObservationId::of(payload),
        source,
        trust,
        observed_at: Some(Timestamp::from_ms(NOW)),
        ingested_at: Timestamp::from_ms(NOW),
        payload: payload.to_vec(),
    }))
}

fn claim(subject: &str, object: Value) -> Record {
    Record::Claim(Box::new(Claim {
        id: ClaimId::of(subject.as_bytes()),
        predicate: "identity.compromised".into(),
        subject: subject.into(),
        object,
        valid: Interval::from(Timestamp::from_ms(NOW)),
        known: Interval::from(Timestamp::from_ms(NOW)),
        confidence: Confidence::new(0.9, Method::Rule, "risk-v4"),
        evidence: vec![SourceRef::new("idp", "signin-847223")],
        status: ClaimStatus::Asserted,
        policy: None,
        actor: ActorId::new("agent-1"),
    }))
}

// ─────────────────────────────────────────────────────────────────────────────

/// **AT-002 — the read-set is engine-captured. A caller cannot launder a derivation by omission.**
///
/// This is the invariant that separates a provenance *system* from a provenance *claim*. If
/// `derived_from` were caller-supplied, an agent — or an attacker steering one — could hide where a
/// conclusion came from simply by not mentioning it.
#[test]
fn at_002_a_caller_cannot_launder_a_derivation_by_omission() -> Result<()> {
    let db = loom();
    let session = SessionId::new("s1");
    let (handle, token) = db.open_session_named(session.clone())?;
    let branch = handle.branch.clone();

    let poisoned = SourceRef::new("web", "attacker-controlled-page");

    // Ingest three observations. One is from a source that will later turn out to be poisoned.
    db.write(
        &token,
        &branch,
        b"obs/signin".to_vec(),
        observation(
            SourceRef::new("idp", "signin-847223"),
            TrustClass::VerifiedSystem,
            b"belarus",
        ),
        &envelope(&session, &branch, "ingest signin"),
    )?;
    db.write(
        &token,
        &branch,
        b"obs/scraped".to_vec(),
        observation(poisoned.clone(), TrustClass::Untrusted, b"trust me"),
        &envelope(&session, &branch, "ingest scraped page"),
    )?;

    // The agent READS all three, then writes a conclusion — and declares NOTHING.
    let _ = db.read(&token, &branch, b"obs/signin")?;
    let _ = db.read(&token, &branch, b"obs/scraped")?;

    let read_set = db.read_set(&session);
    assert!(
        read_set.sources.contains(&poisoned),
        "the engine did not notice the agent reading the poisoned source"
    );

    // An envelope with an EMPTY derived_from. The agent says it derived this from nothing.
    let mut liar = envelope(&session, &branch, "the account is compromised");
    liar.derived_from.clear();
    assert!(liar.derived_from.is_empty());

    db.write(
        &token,
        &branch,
        b"claim/compromised".to_vec(),
        claim("user-4471", Value::Bool(true)),
        &liar,
    )?;

    // The engine recorded the truth anyway. `taint()` finds the conclusion, even though the agent
    // never admitted to reading the page it came from.
    let prov = Provenance::new(&db);
    let (plan, _) = prov.taint(&poisoned)?;

    assert!(
        plan.reversible
            .iter()
            .any(|item| item.description.contains("claim/compromised")),
        "the agent laundered its derivation: it read the poisoned source, declared nothing, and the \
         conclusion is NOT downstream of it in the DAG.\n{plan}"
    );
    Ok(())
}

/// **AT-020 — taint crosses forks.** A poisoned write before a fork reaches *both* children.
#[test]
fn at_020_taint_reaches_both_children_of_a_fork() -> Result<()> {
    let db = loom();
    let session = SessionId::new("s1");
    let (handle, token) = db.open_session_named(session.clone())?;
    let root = handle.branch.clone();

    let poisoned = SourceRef::new("web", "poisoned-page");

    // Ingested BEFORE the fork.
    db.write(
        &token,
        &root,
        b"obs/poisoned".to_vec(),
        observation(poisoned.clone(), TrustClass::Untrusted, b"lies"),
        &envelope(&session, &root, "ingest"),
    )?;

    // Two agents fork and each derive their own conclusion from it.
    let (b, token) = db.branch(&token, &root, "agent-b")?;
    let (c, token) = db.branch(&token, &root, "agent-c")?;

    let _ = db.read(&token, &b, b"obs/poisoned")?;
    db.write(
        &token,
        &b,
        b"claim/from-b".to_vec(),
        claim("user-b", Value::Bool(true)),
        &envelope(&session, &b, "b's conclusion"),
    )?;

    let _ = db.read(&token, &c, b"obs/poisoned")?;
    db.write(
        &token,
        &c,
        b"claim/from-c".to_vec(),
        claim("user-c", Value::Bool(true)),
        &envelope(&session, &c, "c's conclusion"),
    )?;

    let prov = Provenance::new(&db);
    let (plan, stats) = prov.taint(&poisoned)?;

    let descriptions: Vec<&str> = plan
        .reversible
        .iter()
        .map(|i| i.description.as_str())
        .collect();

    assert!(
        descriptions.iter().any(|d| d.contains("claim/from-b")),
        "the taint stopped at the fork and missed branch b.\n{plan}"
    );
    assert!(
        descriptions.iter().any(|d| d.contains("claim/from-c")),
        "the taint stopped at the fork and missed branch c. A taint that misses contamination is \
         worse than no taint, because it reports 'contained' when it is not.\n{plan}"
    );
    assert!(stats.branches >= 3);
    Ok(())
}

/// **AT-021 — taint is exact.** Completeness *and* precision.
///
/// A plan that reverts too much is as unusable as one that reverts too little: an operator told to
/// roll back four hundred unrelated writes will simply not run the plan, and then the poisoned data
/// stays.
#[test]
fn at_021_taint_names_exactly_what_is_downstream_and_nothing_else() -> Result<()> {
    let db = loom();
    let session = SessionId::new("s1");
    let (handle, token) = db.open_session_named(session.clone())?;
    let branch = handle.branch.clone();

    let poisoned = SourceRef::new("web", "poisoned-page");
    let clean = SourceRef::new("idp", "signin-847223");

    db.write(
        &token,
        &branch,
        b"obs/poisoned".to_vec(),
        observation(poisoned.clone(), TrustClass::Untrusted, b"lies"),
        &envelope(&session, &branch, "ingest poisoned"),
    )?;
    db.write(
        &token,
        &branch,
        b"obs/clean".to_vec(),
        observation(clean.clone(), TrustClass::VerifiedSystem, b"truth"),
        &envelope(&session, &branch, "ingest clean"),
    )?;

    // A conclusion derived ONLY from the poisoned source.
    let _ = db.read(&token, &branch, b"obs/poisoned")?;
    db.write(
        &token,
        &branch,
        b"claim/contaminated".to_vec(),
        claim("user-a", Value::Bool(true)),
        &envelope(&session, &branch, "from the poisoned page"),
    )?;

    // A conclusion derived ONLY from the clean source. It must NOT be in the plan.
    let _ = db.read(&token, &branch, b"obs/clean")?;
    db.write(
        &token,
        &branch,
        b"claim/innocent".to_vec(),
        claim("user-b", Value::Bool(true)),
        &envelope(&session, &branch, "from the verified record"),
    )?;

    // A SECOND-ORDER conclusion, derived from the contaminated one. It must BE in the plan — the walk
    // has to go downstream through conclusions built on conclusions, not just one hop.
    let _ = db.read(&token, &branch, b"claim/contaminated")?;
    db.write(
        &token,
        &branch,
        b"claim/second-order".to_vec(),
        claim("user-c", Value::Bool(true)),
        &envelope(&session, &branch, "built on the contaminated claim"),
    )?;

    let prov = Provenance::new(&db);
    let (plan, _) = prov.taint(&poisoned)?;

    let hit = |needle: &str| {
        plan.reversible
            .iter()
            .any(|i| i.description.contains(needle))
    };

    // COMPLETENESS.
    assert!(
        hit("claim/contaminated"),
        "missed the direct derivation\n{plan}"
    );
    assert!(
        hit("claim/second-order"),
        "the walk stopped after one hop and missed a conclusion built on a contaminated \
         conclusion.\n{plan}"
    );

    // PRECISION. This is the half people forget.
    assert!(
        !hit("claim/innocent"),
        "the plan proposes reverting a claim that has NOTHING to do with the poisoned source. A plan \
         that reverts too much will not be run, and then the poisoned data stays.\n{plan}"
    );
    assert!(
        !hit("obs/clean"),
        "the plan proposes reverting an unrelated observation.\n{plan}"
    );
    Ok(())
}

/// **AT-024 — recall never auto-executes.** `taint()` is a dry run.
#[test]
fn at_024_taint_proposes_and_never_acts() -> Result<()> {
    let db = loom();
    let session = SessionId::new("s1");
    let (handle, token) = db.open_session_named(session.clone())?;
    let branch = handle.branch.clone();

    let poisoned = SourceRef::new("web", "poisoned-page");
    db.write(
        &token,
        &branch,
        b"obs/poisoned".to_vec(),
        observation(poisoned.clone(), TrustClass::Untrusted, b"lies"),
        &envelope(&session, &branch, "ingest"),
    )?;
    let _ = db.read(&token, &branch, b"obs/poisoned")?;
    db.write(
        &token,
        &branch,
        b"claim/x".to_vec(),
        claim("user-a", Value::Bool(true)),
        &envelope(&session, &branch, "conclusion"),
    )?;

    let head_before = db.head(&branch)?;

    let prov = Provenance::new(&db);
    let (plan, _) = prov.taint(&poisoned)?;
    assert!(!plan.is_empty());

    // NOTHING MOVED. A system that can silently delete a tenant's data on a signal is a system that
    // can be turned into a weapon.
    assert_eq!(
        db.head(&branch)?,
        head_before,
        "taint() mutated the database. It is a DRY RUN and must remain one."
    );
    assert!(db.read(&token, &branch, b"claim/x")?.is_some());
    assert!(plan.to_string().contains("DRY RUN"));
    Ok(())
}

/// **AT-023 — staleness is the soft path.**
///
/// The claim is still readable and auditable. It simply cannot authorize an action until it has been
/// re-derived. Most of the time, that is what you actually want.
#[test]
fn at_023_invalidated_evidence_makes_a_claim_stale_not_gone() -> Result<()> {
    let db = loom();
    let session = SessionId::new("s1");
    let (handle, token) = db.open_session_named(session.clone())?;
    let branch = handle.branch.clone();

    let source = SourceRef::new("idp", "signin-847223");
    db.write(
        &token,
        &branch,
        b"obs/signin".to_vec(),
        observation(source.clone(), TrustClass::VerifiedSystem, b"belarus"),
        &envelope(&session, &branch, "ingest"),
    )?;

    let _ = db.read(&token, &branch, b"obs/signin")?;
    db.write(
        &token,
        &branch,
        b"claim/compromised".to_vec(),
        claim("user-4471", Value::Bool(true)),
        &envelope(&session, &branch, "the account is compromised"),
    )?;

    // Before: the claim can authorize an action.
    let Some(Record::Claim(before)) = db.read(&token, &branch, b"claim/compromised")? else {
        panic!("expected a claim");
    };
    assert!(before.is_action_eligible());

    // The source is invalidated.
    let prov = Provenance::new(&db);
    let marked = prov.mark_stale(
        &token,
        &branch,
        &source,
        &envelope(&session, &branch, "the source record was corrected"),
    )?;
    assert_eq!(marked.len(), 1);

    // After: still there, still readable, still auditable — and NO LONGER able to act.
    let Some(Record::Claim(after)) = db.read(&token, &branch, b"claim/compromised")? else {
        panic!(
            "the claim was DELETED. Staleness is the scalpel, not the sledgehammer — a stale \
                claim must remain readable and auditable."
        );
    };
    assert_eq!(after.status, ClaimStatus::Stale);
    assert!(
        !after.is_action_eligible(),
        "a stale claim must not be able to authorize an action"
    );

    // And the message tells a model what to DO.
    let reason = after.ineligibility_reason().expect("a reason");
    assert!(reason.contains("STALE"));
    assert!(reason.contains("Re-derive"));
    Ok(())
}

/// **AT-025 — the walk is bounded.** A cyclic or pathological DAG is refused, not chased.
#[test]
fn at_025_a_pathological_derivation_graph_is_refused_not_chased() -> Result<()> {
    use loom_core::{CommitId, DerivationNode, NodeId};
    use loom_provenance::flood_downstream;
    use std::collections::{BTreeMap, BTreeSet};

    // Build a DAG by hand that is longer than the bound. The engine's own write path cannot produce a
    // cycle (a node's id depends on its parents, so a cycle would need a hash preimage), but a corrupt
    // or hostile store could — and an unbounded walk on untrusted input is a denial of service against
    // ourselves.
    let mut nodes: BTreeMap<NodeId, DerivationNode> = BTreeMap::new();
    let mut previous: Vec<NodeId> = vec![];

    for i in 0..(loom_provenance::MAX_DERIVATION_DEPTH + 10) {
        let node = DerivationNode::new(
            BranchId::new("b"),
            CommitId::from_bytes([1; 32]),
            format!("k{i}").into_bytes(),
            ActorId::new("a"),
            vec![],
            "chain".into(),
            previous.clone(),
            vec![],
        );
        previous = vec![node.id];
        nodes.insert(node.id, node);
    }

    let seed: BTreeSet<NodeId> = nodes
        .values()
        .filter(|n| n.derived_from.is_empty())
        .map(|n| n.id)
        .collect();

    let err = flood_downstream(&nodes, &seed);
    assert!(
        matches!(err, Err(loom_core::LoomError::DerivationCycle { .. })),
        "a derivation chain past the bound must be REFUSED. Chasing it is a denial of service \
         against ourselves, and the result could not be trusted anyway."
    );

    let message = err.expect_err("bounded").to_string();
    assert!(
        message.contains("loom audit"),
        "the error must say what to do: {message}"
    );
    Ok(())
}

/// The narrative: **an agent reads a poisoned page, three branches build on it, and taint names
/// exactly what it contaminated — and says, out loud, what it cannot undo.**
#[test]
fn the_taint_and_recall_narrative() -> Result<()> {
    let db = loom();
    let session = SessionId::new("investigation-1");
    let (handle, token) = db.open_session_named(session.clone())?;
    let root = handle.branch.clone();

    let poisoned = SourceRef::new("web", "threat-intel-blog");

    db.write(
        &token,
        &root,
        b"obs/threat-intel".to_vec(),
        observation(
            poisoned.clone(),
            TrustClass::Untrusted,
            b"this IP is a known C2 server",
        ),
        &envelope(&session, &root, "ingest threat intel"),
    )?;

    let (h1, token) = db.branch(&token, &root, "h1")?;
    let (h2, token) = db.branch(&token, &root, "h2")?;

    for (branch, key) in [(&h1, b"claim/h1".as_slice()), (&h2, b"claim/h2".as_slice())] {
        let _ = db.read(&token, branch, b"obs/threat-intel")?;
        db.write(
            &token,
            branch,
            key.to_vec(),
            claim("host-88", Value::Bool(true)),
            &envelope(&session, branch, "the host is compromised"),
        )?;
    }

    // The blog was wrong. Someone poisoned it.
    let prov = Provenance::new(&db);
    let (plan, stats) = prov.taint(&poisoned)?;

    let report = plan.to_string();

    // The report is a dry run, and it says so.
    assert!(report.contains("DRY RUN"));
    // It names the source.
    assert!(report.contains("threat-intel-blog"));
    // It found both conclusions.
    assert!(plan.reversible.len() >= 2, "{report}");
    assert!(stats.contaminated >= 2);

    // And — the whole point of the two-section shape — it already says what it cannot undo, even
    // though there are no actions yet to list.
    assert!(
        plan.is_fully_reversible(),
        "there are no actions in this scenario, so nothing should be listed as irreversible"
    );

    println!("\n{report}");
    Ok(())
}

/// **AT-020 (the merge boundary). A taint crosses a merge, and the merged record is downstream.**
///
/// # Why this test exists
///
/// Merging the winning hypothesis back into `main` is not a corner case — it is the *normal* path.
/// An agent forks, works, and merges. If provenance does not survive that, then every taint stops
/// dead at the first merge boundary, and `taint()` reports "contained" about a `main` branch that is
/// full of conclusions derived from the poisoned source.
///
/// It nearly did. The merge engine reads through the tree rather than through `Loom::read`, so the
/// session's read-set never sees what a merge merged, and the merged record was written into `main`
/// with **no derivation parents at all** — a fresh, clean-looking fact with no history. Nothing
/// failed. `taint()` just quietly returned a shorter list.
///
/// The fix is to say the true thing: a merged record IS derived from the node that produced it on
/// each side. Per key — not the union of every parent in the merge, which was the *first* fix and
/// was wrong in the other direction (it made every merged record look derived from every other one).
#[test]
fn at_020_taint_survives_a_merge_into_main() -> Result<()> {
    let db = loom();
    let (main, token) = db.open_session()?;
    let session = main.id.clone();

    let bad = SourceRef::new("web", "poisoned-page");

    // The agent forks a hypothesis branch, ingests the poisoned page there, and derives a conclusion.
    let (h, token) = db.branch(&token, &main.branch, "hypothesis")?;

    db.write(
        &token,
        &h,
        b"obs/scrape".to_vec(),
        observation(bad.clone(), TrustClass::Untrusted, b"CFO is Dana"),
        &envelope(&session, &h, "ingest the page"),
    )?;

    let seen = db.read(&token, &h, b"obs/scrape")?;
    assert!(
        seen.is_some(),
        "the observation must be readable to be read"
    );

    db.write(
        &token,
        &h,
        b"claim/cfo".to_vec(),
        claim("acme", Value::Text("Dana".into())),
        &envelope(&session, &h, "conclude who the CFO is"),
    )?;

    // …and merges it back into main, which is what an agent does when it likes its answer.
    let outcome = db.merge(
        &token,
        &h,
        &main.branch,
        &MergePolicy::Conflict,
        &envelope(&session, &main.branch, "adopt"),
    )?;
    assert!(
        matches!(outcome, MergeResult::Merged { .. }),
        "the merge must succeed for this test to be testing anything: {outcome:?}"
    );

    // The page turns out to be poisoned.
    let prov = Provenance::new(&db);
    let (plan, _) = prov.taint(&bad)?;

    // Not just "does main appear" — the merged *observation* re-cites its own source when it lands in
    // main, so main appears in the plan whether or not provenance survived. The first version of this
    // test asserted exactly that, passed with the fix reverted, and was therefore worthless.
    //
    // The thing that must survive the merge is the DERIVED CONCLUSION: a claim that cites no source of
    // its own and is contaminated only because of what it was built on. If the merge severs its
    // parents, it lands in main looking like a clean, freshly-authored fact.
    let conclusion_on_main = plan
        .reversible
        .iter()
        .any(|item| item.branch == main.branch && item.description.contains("claim/cfo"));

    assert!(
        conclusion_on_main,
        "the poisoned CONCLUSION was merged into main, and the plan does not name it there.\n\
         A merged record is derived from the node that produced it on each side. If the merge drops \
         that edge, the conclusion arrives in main with no history — a clean-looking fact — and every \
         taint stops dead at the merge boundary, which is the branch an agent uses on every single \
         run.\n\
         plan: {plan}"
    );

    Ok(())
}
