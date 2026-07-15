//! **The policy oracle — the third one (docs/05 §4).**
//!
//! # What it guards, and why failing here is the worst kind
//!
//! The engine indexes rules by action and short-circuits on the first deny. That is a real
//! optimisation, and every optimisation over a security decision is a chance to get deny-overrides or
//! fail-closed subtly wrong — to skip a wildcard rule, to return an allow before seeing a later deny,
//! to treat "no rule matched" as permission. Any of those fails **open**, and an authorization engine
//! that fails open is worse than none, because it is trusted.
//!
//! So a naive model evaluates the pure truth-table semantics — scan every rule, deny if any applicable
//! deny, else allow if any applicable allow, else deny — and thousands of randomized policy sets and
//! requests try to make the engine disagree with it. The model uses none of the engine's indexing; it
//! is the definition, written the dumbest way. If they ever differ, the engine is wrong, because the
//! model *is* the spec.

use loom_core::TrustClass;
use loom_policy::{Decision, Effect, Engine, Match, PolicyRule, PolicySet, Request};
use proptest::prelude::*;

/// The model: deny-overrides over a flat scan, then fail closed. This is the whole of the policy
/// semantics, and it uses no part of the engine.
fn model_decide(set: &PolicySet, req: &Request) -> Decision {
    let applies = |r: &PolicyRule| {
        matches(&r.actor, &req.actor)
            && label_matches(&r.label, &req.label)
            && matches(&r.purpose, &req.purpose)
            && matches(&r.action, &req.action)
    };

    // Deny-overrides: any applicable deny, anywhere, wins.
    if set
        .rules
        .iter()
        .filter(|r| applies(r))
        .any(|r| r.effect == Effect::Deny)
    {
        return Decision::Deny;
    }
    // Otherwise an allow, if one applies.
    if set
        .rules
        .iter()
        .filter(|r| applies(r))
        .any(|r| r.effect == Effect::Allow)
    {
        return Decision::Allow;
    }
    // Otherwise: no. Fail closed.
    Decision::Deny
}

fn matches(m: &Match<String>, v: &str) -> bool {
    match m {
        Match::Is(s) => s == v,
        Match::Any => true,
    }
}

fn label_matches(m: &Match<TrustClass>, v: &TrustClass) -> bool {
    match m {
        Match::Is(s) => s == v,
        Match::Any => true,
    }
}

// Small, fixed domains so randomized rules and requests actually collide and exercise precedence.
const ACTORS: [&str; 3] = ["agent", "human", "system"];
const PURPOSES: [&str; 3] = ["public_answer", "internal", "authorize_action"];
const ACTIONS: [&str; 4] = ["read", "pack_into_context", "suspend_account", "refund"];
const LABELS: [TrustClass; 4] = [
    TrustClass::VerifiedSystem,
    TrustClass::Human,
    TrustClass::ThirdParty,
    TrustClass::Untrusted,
];

fn a_match<T: Clone>(opt: Option<T>) -> Match<T> {
    match opt {
        Some(v) => Match::Is(v),
        None => Match::Any,
    }
}

fn rule_strategy() -> impl Strategy<Value = PolicyRule> {
    (
        prop::option::of(0usize..ACTORS.len()),
        prop::option::of(0usize..LABELS.len()),
        prop::option::of(0usize..PURPOSES.len()),
        prop::option::of(0usize..ACTIONS.len()),
        any::<bool>(),
    )
        .prop_map(|(actor, label, purpose, action, deny)| PolicyRule {
            actor: a_match(actor.map(|i| ACTORS[i].to_string())),
            label: a_match(label.map(|i| LABELS[i])),
            purpose: a_match(purpose.map(|i| PURPOSES[i].to_string())),
            action: a_match(action.map(|i| ACTIONS[i].to_string())),
            effect: if deny { Effect::Deny } else { Effect::Allow },
        })
}

fn request_strategy() -> impl Strategy<Value = Request> {
    (
        0usize..ACTORS.len(),
        0usize..LABELS.len(),
        0usize..PURPOSES.len(),
        0usize..ACTIONS.len(),
    )
        .prop_map(|(a, l, p, ac)| Request {
            actor: ACTORS[a].to_string(),
            label: LABELS[l],
            purpose: PURPOSES[p].to_string(),
            action: ACTIONS[ac].to_string(),
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("POLICY_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(4000)
    ))]

    /// **The indexed, short-circuiting engine decides exactly what the naive truth table decides.**
    #[test]
    fn engine_agrees_with_the_truth_table(
        rules in prop::collection::vec(rule_strategy(), 0..12),
        requests in prop::collection::vec(request_strategy(), 1..8),
    ) {
        let set = PolicySet::new("vtest", rules);
        let engine = Engine::new(&set);

        for req in &requests {
            let want = model_decide(&set, req);
            let got = engine.decide(req).decision;
            prop_assert_eq!(
                got, want,
                "DISAGREEMENT on {:?}\n  engine: {:?}\n  model:  {:?}\n  rules:  {:?}",
                req, got, want, set.rules
            );
        }
    }

    /// **Fail closed as an invariant: whenever no rule applies, the answer is deny — never allow.**
    ///
    /// A separate, sharper statement of the one direction that must never break. If the engine ever
    /// says allow while the model finds nothing applicable, it is failing open.
    #[test]
    fn no_applicable_rule_always_denies(
        rules in prop::collection::vec(rule_strategy(), 0..12),
        req in request_strategy(),
    ) {
        let set = PolicySet::new("vtest", rules);
        let any_applies = model_decide(&set, &req);
        // model_decide returns Deny both for "a deny applied" and "nothing applied"; to isolate
        // fail-closed, check the case where the engine allows: it must be because SOME allow applied.
        let engine = Engine::new(&set);
        if engine.decide(&req).decision == Decision::Allow {
            prop_assert_eq!(any_applies, Decision::Allow,
                "engine allowed a request the truth table does not — failing open");
        }
    }
}
