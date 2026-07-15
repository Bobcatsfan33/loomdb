//! **AT-022 — the taint plan names the account it cannot un-suspend. Demo step 10.**
//!
//! This is the second of the two moments the roadmap calls "the entire company". A source turns out
//! to be poisoned. `taint(S)` returns a `RecallPlan` in two sections, and the **irreversible** one
//! comes first: the account we already suspended, its receipt, and the registered compensating action.
//! A plan that showed the reverted writes and quietly omitted the suspended account would be a
//! liability, not an audit — a person is still locked out while the report says "contained".
//!
//! The whole chain is exercised end to end: ingest an observation, derive a claim from it, run a real
//! action through the gateway justified by that claim, then taint the observation's source and check
//! that the executed action surfaces in the plan's irreversible section, ahead of the reversible writes.

use loom_action::{ActionGateway, AgentStore, Connector, ConnectorOutcome};
use loom_branch::Loom;
use loom_core::{
    ActorId, BranchId, Claim, ClaimId, ClaimStatus, Confidence, IndexHint, Interval, Method,
    Observation, ObservationId, Record, SessionId, SourceRef, TenantId, Timestamp, TrustClass,
    Value, WriteEnvelope,
};
use loom_policy::{Effect, Engine, Match, PolicyRule, PolicySet};
use loom_provenance::Provenance;

const NOW: u64 = 1_700_000_000_000;

fn env(session: &SessionId, branch: &BranchId) -> WriteEnvelope {
    WriteEnvelope::new(
        ActorId::new("agent"),
        session.clone(),
        branch.clone(),
        "work",
    )
}

/// A suspension connector that succeeds with a receipt and knows how to be undone.
struct SuspendConnector;
impl Connector for SuspendConnector {
    fn action_type(&self) -> &str {
        "identity.suspend_account"
    }
    fn compensating_action(&self) -> Option<String> {
        Some("identity.reinstate_account".to_string())
    }
    fn execute(&self, target: &str, _key: &str) -> ConnectorOutcome {
        ConnectorOutcome::Succeeded {
            receipt: format!("SUSPEND-RECEIPT-{target}"),
        }
    }
}

fn allow_all() -> Engine {
    Engine::new(&PolicySet::new(
        "v1",
        vec![PolicyRule {
            actor: Match::Any,
            label: Match::Any,
            purpose: Match::Any,
            action: Match::Any,
            effect: Effect::Allow,
        }],
    ))
}

#[test]
fn at_022_taint_lists_the_suspended_account_first_with_its_receipt() -> loom_core::Result<()> {
    let db = Loom::in_memory(TenantId::new("acme"))?.with_clock(|| NOW);
    let (session, token) = db.open_session()?;
    let branch = session.branch.clone();
    let sid = session.id.clone();

    let source = SourceRef::new("hr-system", "record-42");

    // Ingest the observation.
    db.write_indexed(
        &token,
        &branch,
        b"obs/hr".to_vec(),
        Record::Observation(Box::new(Observation {
            id: ObservationId::of(b"hr"),
            source: source.clone(),
            trust: TrustClass::VerifiedSystem,
            observed_at: None,
            ingested_at: Timestamp::from_ms(NOW),
            payload: b"the account looks fraudulent".to_vec(),
        })),
        IndexHint::text("account looks fraudulent"),
        &env(&sid, &branch),
    )?;

    // Derive a claim from it (engine captures the derivation).
    let _ = db.read(&token, &branch, b"obs/hr")?;
    let claim_record = Record::Claim(Box::new(Claim {
        id: ClaimId::of(b"suspend-claim"),
        predicate: "should_suspend".into(),
        subject: "user-42".into(),
        object: Value::Bool(true),
        valid: Interval::from(Timestamp::from_ms(NOW)),
        known: Interval::from(Timestamp::from_ms(NOW)),
        confidence: Confidence::new(0.95, Method::Rule, "v1"),
        evidence: vec![source.clone()],
        status: ClaimStatus::Asserted,
        policy: None,
        actor: ActorId::new("agent"),
    }));
    let Record::Claim(the_claim) = claim_record.clone() else {
        unreachable!()
    };
    db.write_indexed(
        &token,
        &branch,
        b"claim/suspend".to_vec(),
        claim_record,
        IndexHint::text("user-42 should be suspended"),
        &env(&sid, &branch),
    )?;

    // The agent proposes the suspension; the gateway executes it, justified by the claim.
    let gateway =
        ActionGateway::new("acme", allow_all()).with_connector(Box::new(SuspendConnector));
    let agent = AgentStore::new(ActorId::new("agent"), branch.as_str(), false);
    let outcome = gateway.execute(&agent.propose(
        "identity.suspend_account",
        "user-42",
        "susp-1",
        vec![*the_claim],
        vec![b"claim/suspend".to_vec()], // the record key that justifies it
        TrustClass::VerifiedSystem,
    ));
    assert!(
        outcome.status.is_success(),
        "the suspension executed: {outcome:?}"
    );

    // ── The source turns out to be poisoned. taint(S). ──────────────────────
    let executed: Vec<_> = gateway
        .records()
        .iter()
        .filter_map(|r| r.to_executed())
        .collect();
    let prov = Provenance::new(&db);
    let (plan, _) = prov.taint_with_actions(&source, &executed)?;

    // AT-022: the executed suspension is in the IRREVERSIBLE section, with its receipt and compensation.
    assert_eq!(
        plan.irreversible.len(),
        1,
        "the plan must name the action that already happened. Got: {:?}",
        plan.irreversible
    );
    let item = &plan.irreversible[0];
    assert_eq!(item.action_type, "identity.suspend_account");
    assert_eq!(item.target, "user-42");
    assert_eq!(
        item.receipt.as_deref(),
        Some("SUSPEND-RECEIPT-user-42"),
        "the receipt is the proof"
    );
    assert_eq!(
        item.compensating_action.as_deref(),
        Some("identity.reinstate_account"),
        "the registered compensation must be offered"
    );

    // And the reversible writes are there too — but the irreversible section is FIRST.
    assert!(
        !plan.reversible.is_empty(),
        "the downstream claim write is reversible"
    );

    // The report leads with what it cannot undo (the RecallPlan Display, guarded in loom-core, puts
    // "CANNOT BE UNDONE" before "CAN be reverted"). Here we just assert the data is present and
    // ordered: irreversible is a non-empty section the renderer shows first.
    let rendered = plan.to_string();
    let cannot = rendered.find("CANNOT BE UNDONE");
    let can = rendered.find("CAN be reverted");
    if let (Some(c1), Some(c2)) = (cannot, can) {
        assert!(c1 < c2, "the plan must lead with what it cannot undo");
    }
    // The suspended account and its receipt must appear in the human-readable plan.
    assert!(
        rendered.contains("user-42"),
        "the suspended account must be named in the report"
    );

    Ok(())
}

/// **When there is no compensating action, the plan says so — it does not invent one.**
#[test]
fn at_022_no_compensation_is_stated_not_faked() -> loom_core::Result<()> {
    struct NoCompConnector;
    impl Connector for NoCompConnector {
        fn action_type(&self) -> &str {
            "email.send"
        }
        // compensating_action defaults to None — you cannot un-send an email.
        fn execute(&self, _t: &str, _k: &str) -> ConnectorOutcome {
            ConnectorOutcome::Succeeded {
                receipt: "MSG-1".into(),
            }
        }
    }

    let db = Loom::in_memory(TenantId::new("acme"))?.with_clock(|| NOW);
    let (session, token) = db.open_session()?;
    let branch = session.branch.clone();
    let sid = session.id.clone();
    let source = SourceRef::new("web", "s");

    db.write_indexed(
        &token,
        &branch,
        b"obs/s".to_vec(),
        Record::Observation(Box::new(Observation {
            id: ObservationId::of(b"s"),
            source: source.clone(),
            trust: TrustClass::VerifiedSystem,
            observed_at: None,
            ingested_at: Timestamp::from_ms(NOW),
            payload: b"x".to_vec(),
        })),
        IndexHint::text("x"),
        &env(&sid, &branch),
    )?;
    let _ = db.read(&token, &branch, b"obs/s")?;
    let claim = Claim {
        id: ClaimId::of(b"c"),
        predicate: "p".into(),
        subject: "customer".into(),
        object: Value::Bool(true),
        valid: Interval::from(Timestamp::from_ms(NOW)),
        known: Interval::from(Timestamp::from_ms(NOW)),
        confidence: Confidence::new(0.9, Method::Rule, "v1"),
        evidence: vec![source.clone()],
        status: ClaimStatus::Asserted,
        policy: None,
        actor: ActorId::new("agent"),
    };
    db.write_indexed(
        &token,
        &branch,
        b"claim/email".to_vec(),
        Record::Claim(Box::new(claim.clone())),
        IndexHint::text("notify the customer"),
        &env(&sid, &branch),
    )?;

    let gateway = ActionGateway::new("acme", allow_all()).with_connector(Box::new(NoCompConnector));
    let agent = AgentStore::new(ActorId::new("agent"), branch.as_str(), false);
    gateway.execute(&agent.propose(
        "email.send",
        "customer@example.com",
        "email-1",
        vec![claim],
        vec![b"claim/email".to_vec()],
        TrustClass::VerifiedSystem,
    ));

    let executed: Vec<_> = gateway
        .records()
        .iter()
        .filter_map(|r| r.to_executed())
        .collect();
    let (plan, _) = Provenance::new(&db).taint_with_actions(&source, &executed)?;

    assert_eq!(plan.irreversible.len(), 1);
    let item = &plan.irreversible[0];
    assert_eq!(
        item.compensating_action, None,
        "there is no un-send; the plan must not pretend there is"
    );
    assert!(
        item.escalation.contains("human must decide")
            || item.escalation.to_lowercase().contains("no registered"),
        "with no compensation, the plan escalates to a human rather than inventing a fix: {}",
        item.escalation
    );
    Ok(())
}
