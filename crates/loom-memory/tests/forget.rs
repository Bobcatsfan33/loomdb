//! **AT-044 — forgetting propagates, and reports what it cannot undo.**
//!
//! Forget an observation that a summary, an embedding, a cached response, and two derived claims all
//! rest on. Afterwards: every governed representation is gone from the index, both derived claims are
//! invalidated (not merely stale — the input is gone, so the conclusion is withdrawn), the source's
//! own representation is gone, and a completion report accounts for all of it — leading with the
//! irreversible section, which is empty today and honestly so.

use loom_branch::Loom;
use loom_core::{
    ActorId, BranchId, Claim, ClaimId, ClaimStatus, Confidence, Embedding, IndexHint, Interval,
    Method, Observation, ObservationId, Record, SessionId, SourceRef, TenantId, Timestamp,
    TrustClass, Value, WriteEnvelope,
};
use loom_memory::{Forgetter, RetrievalQuery, Retriever};

const NOW: u64 = 1_700_000_000_000;

fn env(session: &SessionId, branch: &BranchId) -> WriteEnvelope {
    WriteEnvelope::new(
        ActorId::new("agent"),
        session.clone(),
        branch.clone(),
        "build memory",
    )
}

fn embed(text: &str) -> Embedding {
    let b = text.as_bytes();
    Embedding::new([
        b.iter().map(|x| *x as f32).sum::<f32>() % 7.0,
        b.len() as f32,
        (b.first().copied().unwrap_or(0) as f32) % 5.0,
    ])
}

fn observation(source: &SourceRef, text: &str) -> Record {
    Record::Observation(Box::new(Observation {
        id: ObservationId::of(text.as_bytes()),
        source: source.clone(),
        trust: TrustClass::Untrusted,
        observed_at: None,
        ingested_at: Timestamp::from_ms(NOW),
        payload: text.as_bytes().to_vec(),
    }))
}

/// A claim citing `evidence`, so it is action-relevant and indexable.
fn claim(subject: &str, text: &str, evidence: Vec<SourceRef>) -> Record {
    Record::Claim(Box::new(Claim {
        id: ClaimId::of(text.as_bytes()),
        predicate: "derived_from".into(),
        subject: subject.into(),
        object: Value::Text(text.into()),
        valid: Interval::from(Timestamp::from_ms(NOW)),
        known: Interval::from(Timestamp::from_ms(NOW)),
        confidence: Confidence::new(0.9, Method::Rule, "v1"),
        evidence,
        status: ClaimStatus::Asserted,
        policy: None,
        actor: ActorId::new("agent"),
    }))
}

#[test]
fn at_044_forgetting_a_source_removes_everything_derived_from_it() -> loom_core::Result<()> {
    let db = Loom::in_memory(TenantId::new("acme"))?.with_clock(|| NOW);
    let (session, token) = db.open_session()?;
    let branch = session.branch.clone();
    let sid = session.id.clone();

    let poisoned = SourceRef::new("web", "poisoned-page");

    // The observation itself, indexed.
    db.write_indexed(
        &token,
        &branch,
        b"obs/scrape".to_vec(),
        observation(&poisoned, "the scraped page says X"),
        IndexHint::text("the scraped page says X").with_embedding(embed("scrape X")),
        &env(&sid, &branch),
    )?;

    // Read it, so the derivations that follow are engine-captured as derived from it (AT-002).
    let _ = db.read(&token, &branch, b"obs/scrape")?;

    // Four governed representations built on it: two derived claims, a summary, a cached response.
    // Each cites the poisoned source as evidence, and each is indexed.
    for (key, subject, text) in [
        (
            b"claim/a".to_vec(),
            "entity-a",
            "claim A derived from the scrape",
        ),
        (
            b"claim/b".to_vec(),
            "entity-b",
            "claim B derived from the scrape",
        ),
        (
            b"summary/1".to_vec(),
            "summary",
            "a summary that leans on the scrape",
        ),
        (
            b"cache/resp".to_vec(),
            "cached",
            "a cached response citing the scrape",
        ),
    ] {
        let _ = db.read(&token, &branch, b"obs/scrape")?; // each read re-derives from the source
        db.write_indexed(
            &token,
            &branch,
            key,
            claim(subject, text, vec![poisoned.clone()]),
            IndexHint::text(text).with_embedding(embed(text)),
            &env(&sid, &branch),
        )?;
    }

    // Sanity: before forgetting, everything is retrievable.
    let retr = Retriever::new(&db);
    let before = retr.retrieve(
        &token,
        &branch,
        &RetrievalQuery::text("scrape claim summary cached", 100_000),
    )?;
    assert!(
        before.items.len() >= 5,
        "all five representations should be retrievable first: {}",
        before.items.len()
    );

    // ── forget ────────────────────────────────────────────────────────────
    let report = Forgetter::new(&db).forget(&token, &branch, &poisoned, &env(&sid, &branch))?;

    // Every derived representation is gone from the index.
    let after = retr.retrieve(
        &token,
        &branch,
        &RetrievalQuery::text("scrape claim summary cached", 100_000),
    )?;
    assert!(
        after.items.is_empty(),
        "AT-044: after forgetting, NOTHING derived from the source may still be retrievable. Left: {:?}",
        after.items.iter().map(|i| String::from_utf8_lossy(&i.key).to_string()).collect::<Vec<_>>()
    );

    // The two derived claims are invalidated (not merely stale — the input is gone).
    for key in [b"claim/a".as_slice(), b"claim/b".as_slice()] {
        let Some(Record::Claim(c)) = db.read(&token, &branch, key)? else {
            panic!("claim should still be readable — history is not rewritten");
        };
        assert_eq!(
            c.status,
            ClaimStatus::Invalidated,
            "a claim resting on a forgotten source must be withdrawn, not left asserted"
        );
    }

    // The report accounts for the whole set.
    assert!(
        report.deindexed >= 5,
        "the report must count every representation removed: {}",
        report.deindexed
    );
    assert!(
        report.invalidated >= 2,
        "both derived claims must be counted invalidated: {}",
        report.invalidated
    );
    assert_eq!(report.source.as_ref(), Some(&poisoned));

    // And it leads with what it cannot undo — empty today, but the sentence is there.
    let summary = report.summary();
    assert!(
        summary.contains("cannot be undone") || summary.contains("nothing that cannot be undone"),
        "the report must speak to reversibility, first: {summary}"
    );
    Ok(())
}

/// The report's irreversible section is FIRST in the struct and stays empty-but-shaped until L3.5.
/// This is the AT-022/AT-044 discipline, guarded so nobody quietly drops it.
#[test]
fn at_044_the_report_is_shaped_to_lead_with_the_irreversible() {
    let report = loom_memory::ForgetReport::default();
    // Field order is load-bearing: irreversible is declared before the counts, the same way
    // RecallPlan puts it first. A struct is not a promise, but the summary() that reads it is.
    assert!(report.irreversible.is_empty());
    assert!(
        report.summary().contains("nothing that cannot be undone"),
        "an empty report still states, affirmatively, that nothing escaped — silence is not the same claim"
    );
}
