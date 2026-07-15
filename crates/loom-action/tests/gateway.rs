//! **AT-027–033: the action gateway.**
//!
//! Demo step 7 and the guarantees around it: an agent proposes, the gateway checks and acts once,
//! with a receipt — and every way the world can refuse to cooperate (a timeout, a receiptless
//! success, a stale input, a flipped kill switch, a simulation branch) has an honest answer that is
//! never a guessed success.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use loom_action::{
    ActionGateway, ActionStatus, AgentStore, Connector, ConnectorOutcome, KillSwitch,
};
use loom_core::{
    ActorId, Claim, ClaimId, ClaimStatus, Confidence, Interval, Method, SourceRef, Timestamp,
    TrustClass, Value,
};
use loom_policy::{Effect, Engine, Match, PolicyRule, PolicySet};

const NOW: u64 = 1_700_000_000_000;

/// A connector that counts how many times it was actually invoked — the side-effect counter that
/// AT-028 is about.
struct CountingConnector {
    action_type: String,
    calls: Arc<AtomicUsize>,
    outcome: ConnectorOutcome,
    simulated: bool,
}

impl Connector for CountingConnector {
    fn action_type(&self) -> &str {
        &self.action_type
    }
    fn is_simulated(&self) -> bool {
        self.simulated
    }
    fn execute(&self, _target: &str, _key: &str) -> ConnectorOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.outcome.clone()
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

fn good_claim() -> Claim {
    Claim {
        id: ClaimId::of(b"c"),
        predicate: "p".into(),
        subject: "acme".into(),
        object: Value::Bool(true),
        valid: Interval::from(Timestamp::from_ms(NOW)),
        known: Interval::from(Timestamp::from_ms(NOW)),
        confidence: Confidence::new(0.9, Method::Rule, "v1"),
        evidence: vec![SourceRef::new("erp", "r1")], // cites evidence => eligible
        status: ClaimStatus::Asserted,
        policy: None,
        actor: ActorId::new("agent"),
    }
}

fn gateway(outcome: ConnectorOutcome, calls: Arc<AtomicUsize>) -> ActionGateway {
    ActionGateway::new("acme", allow_all()).with_connector(Box::new(CountingConnector {
        action_type: "identity.suspend_account".into(),
        calls,
        outcome,
        simulated: false,
    }))
}

fn agent() -> AgentStore {
    AgentStore::new(ActorId::new("agent"), "main", false)
}

/// **AT-032: a successful action returns a receipt, and reaches terminal Succeeded.**
#[test]
fn at_032_success_carries_a_receipt() {
    let calls = Arc::new(AtomicUsize::new(0));
    let gw = gateway(
        ConnectorOutcome::Succeeded {
            receipt: "TICKET-99".into(),
        },
        calls.clone(),
    );
    let p = agent().propose(
        "identity.suspend_account",
        "user-1",
        "key-1",
        vec![good_claim()],
        vec![b"claim/x".to_vec()],
        TrustClass::VerifiedSystem,
    );
    let rec = gw.execute(&p);
    assert!(rec.status.is_success());
    assert_eq!(rec.receipt(), Some("TICKET-99"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// **AT-032: success WITHOUT a receipt does not reach terminal success.**
#[test]
fn at_032_success_without_a_receipt_is_not_terminal_success() {
    let calls = Arc::new(AtomicUsize::new(0));
    let gw = gateway(ConnectorOutcome::SucceededWithoutReceipt, calls);
    let rec = gw.execute(&agent().propose(
        "identity.suspend_account",
        "user-1",
        "key-1",
        vec![good_claim()],
        vec![b"claim/x".to_vec()],
        TrustClass::VerifiedSystem,
    ));
    assert!(!rec.status.is_success(), "no receipt => not Succeeded");
    assert!(matches!(rec.status, ActionStatus::Indeterminate { .. }));
}

/// **AT-029: a connector timeout is Indeterminate — not success, not failure.**
#[test]
fn at_029_a_timeout_is_indeterminate() {
    let calls = Arc::new(AtomicUsize::new(0));
    let gw = gateway(
        ConnectorOutcome::Indeterminate {
            detail: "timeout".into(),
        },
        calls,
    );
    let rec = gw.execute(&agent().propose(
        "identity.suspend_account",
        "u",
        "k",
        vec![good_claim()],
        vec![b"claim/x".to_vec()],
        TrustClass::VerifiedSystem,
    ));
    assert!(matches!(rec.status, ActionStatus::Indeterminate { .. }));
    assert!(!rec.status.is_success());
}

/// **AT-028: 100 concurrent retries of the same key cause at most one side effect.**
#[test]
fn at_028_idempotent_under_concurrent_retries() {
    let calls = Arc::new(AtomicUsize::new(0));
    let gw = Arc::new(gateway(
        ConnectorOutcome::Succeeded {
            receipt: "R".into(),
        },
        calls.clone(),
    ));

    let mut handles = Vec::new();
    for _ in 0..100 {
        let gw = gw.clone();
        handles.push(std::thread::spawn(move || {
            gw.execute(&agent().propose(
                "identity.suspend_account",
                "user-1",
                "same-key", // the SAME idempotency key across all 100
                vec![good_claim()],
                vec![b"claim/x".to_vec()],
                TrustClass::VerifiedSystem,
            ))
        }));
    }
    let ids: Vec<_> = handles.into_iter().map(|h| h.join().unwrap().id).collect();

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "AT-028: at most ONE side effect for one idempotency key, however many concurrent retries"
    );
    // Every caller got the same ActionId.
    assert!(
        ids.iter().all(|i| *i == ids[0]),
        "every retry must report the same ActionId"
    );
}

/// **AT-030: a stale claim cannot authorize an action.**
#[test]
fn at_030_stale_evidence_cannot_authorize() {
    let calls = Arc::new(AtomicUsize::new(0));
    let gw = gateway(
        ConnectorOutcome::Succeeded {
            receipt: "R".into(),
        },
        calls.clone(),
    );

    let mut stale = good_claim();
    stale.status = ClaimStatus::Stale;

    let rec = gw.execute(&agent().propose(
        "identity.suspend_account",
        "u",
        "k",
        vec![stale],
        vec![b"claim/x".to_vec()],
        TrustClass::VerifiedSystem,
    ));
    assert!(
        matches!(rec.status, ActionStatus::Refused { .. }),
        "stale evidence must be refused"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "and nothing may have executed"
    );
}

/// **AT-033: the kill switch disables new actions; the switch's own state is unaffected by it.**
#[test]
fn at_033_kill_switch_disables_actions() {
    let calls = Arc::new(AtomicUsize::new(0));
    let gw = gateway(
        ConnectorOutcome::Succeeded {
            receipt: "R".into(),
        },
        calls.clone(),
    );

    // Flip it.
    {
        let mut ks: std::sync::MutexGuard<'_, KillSwitch> = gw.kill_switch().lock().unwrap();
        ks.disable_all();
    }

    let rec = gw.execute(&agent().propose(
        "identity.suspend_account",
        "u",
        "k",
        vec![good_claim()],
        vec![b"claim/x".to_vec()],
        TrustClass::VerifiedSystem,
    ));
    assert!(matches!(rec.status, ActionStatus::Refused { .. }));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no external effect while disabled"
    );

    // Investigation still works: records() (the audit surface) is fully available while disabled.
    assert_eq!(
        gw.records().len(),
        1,
        "the refused action is still recorded and auditable"
    );
}

/// **AT-031: a simulation-branch proposal may not reach a production connector.**
#[test]
fn at_031_simulation_cannot_touch_production() {
    let calls = Arc::new(AtomicUsize::new(0));
    let gw = gateway(
        ConnectorOutcome::Succeeded {
            receipt: "R".into(),
        },
        calls.clone(),
    );

    // An agent on a SIMULATION branch.
    let sim_agent = AgentStore::new(ActorId::new("agent"), "what-if", true);
    let rec = gw.execute(&sim_agent.propose(
        "identity.suspend_account",
        "u",
        "k",
        vec![good_claim()],
        vec![b"claim/x".to_vec()],
        TrustClass::VerifiedSystem,
    ));
    assert!(
        matches!(rec.status, ActionStatus::Refused { .. }),
        "a simulation may not act on production"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the production connector was never called"
    );
}

/// **AT-027, structural: an `AgentStore` has no method that acts.**
///
/// This is not a runtime assertion — it cannot be, because the guarantee is the *absence* of a method.
/// If someone added `AgentStore::execute`, this comment would be a lie and the demo's step-8 promise
/// would be hollow. The test that enforces it is the compiler: `agent().execute(...)` does not compile,
/// because there is no such method. What we *can* assert at runtime is the other half — that proposing
/// does nothing until a separate gateway acts.
#[test]
fn at_027_proposing_does_nothing_by_itself() {
    let calls = Arc::new(AtomicUsize::new(0));
    let _gw = gateway(
        ConnectorOutcome::Succeeded {
            receipt: "R".into(),
        },
        calls.clone(),
    );

    // Build a proposal. This is all an agent can do.
    let _proposal = agent().propose(
        "identity.suspend_account",
        "user-1",
        "key-1",
        vec![good_claim()],
        vec![b"claim/x".to_vec()],
        TrustClass::VerifiedSystem,
    );

    // No connector was called: a proposal is inert. Acting requires the gateway, which the agent does
    // not hold.
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "AT-027: proposing must have NO external effect — only the gateway acts"
    );
}
