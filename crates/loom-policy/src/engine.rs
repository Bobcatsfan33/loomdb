//! The engine: rules, the request, and the decision.

use std::collections::BTreeMap;

use loom_core::TrustClass;
use serde::{Deserialize, Serialize};

/// Allow, or deny.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    /// Permit — but only if nothing else denies. Deny-overrides means an allow is never the last word.
    Allow,
    /// Refuse. Final: no allow anywhere can lift a deny.
    Deny,
}

/// A field pattern: a specific value, or "any".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Match<T> {
    /// Matches this exact value.
    Is(T),
    /// Matches anything.
    Any,
}

impl<T: PartialEq> Match<T> {
    fn matches(&self, value: &T) -> bool {
        match self {
            Match::Is(v) => v == value,
            Match::Any => true,
        }
    }
}

/// What is being asked of the policy: an actor, acting on data with a label, for a purpose, taking an
/// action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Who is acting (an actor id, or a role name — the policy does not care which).
    pub actor: String,
    /// The trust label on the data being acted on. Restricted data acted on for the wrong purpose is
    /// the whole of AT-034/035/036.
    pub label: TrustClass,
    /// What the request is for. `"public_answer"`, `"internal_analysis"`, `"authorize_action"`.
    pub purpose: String,
    /// The action being attempted. `"identity.suspend_account"`, `"pack_into_context"`, `"read"`.
    pub action: String,
}

/// One rule in a policy set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Which actor this applies to.
    pub actor: Match<String>,
    /// Which data label this applies to.
    pub label: Match<TrustClass>,
    /// Which purpose this applies to.
    pub purpose: Match<String>,
    /// Which action this applies to.
    pub action: Match<String>,
    /// What it says.
    pub effect: Effect,
}

impl PolicyRule {
    fn applies_to(&self, req: &Request) -> bool {
        self.actor.matches(&req.actor)
            && self.label.matches(&req.label)
            && self.purpose.matches(&req.purpose)
            && self.action.matches(&req.action)
    }
}

/// A versioned set of rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySet {
    /// The version, recorded in every decision so "which policy allowed this" is answerable (AT-038).
    pub version: String,
    /// The rules. Order does not affect the decision — deny-overrides is order-independent — but it is
    /// preserved for auditing.
    pub rules: Vec<PolicyRule>,
}

impl PolicySet {
    /// An empty policy set. **Denies everything**, because the default is no (AT-037).
    pub fn empty(version: impl Into<String>) -> Self {
        PolicySet {
            version: version.into(),
            rules: Vec::new(),
        }
    }

    /// Build from rules.
    pub fn new(version: impl Into<String>, rules: Vec<PolicyRule>) -> Self {
        PolicySet {
            version: version.into(),
            rules,
        }
    }
}

/// Allow or deny, plus why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Permitted.
    Allow,
    /// Refused.
    Deny,
}

impl Decision {
    /// Is this an allow?
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// A decision, with the evidence that produced it — an audit record, not just a boolean (AT-038).
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyDecision {
    /// Allow or deny.
    pub decision: Decision,
    /// The policy version that decided.
    pub policy_version: String,
    /// The request that was evaluated, verbatim.
    pub request: RequestSnapshot,
    /// In one line, why — the rule that decided, or the fact that nothing matched.
    pub rationale: String,
}

/// A request as recorded in a decision. Owned, so the decision outlives the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestSnapshot {
    /// The actor.
    pub actor: String,
    /// The label.
    pub label: TrustClass,
    /// The purpose.
    pub purpose: String,
    /// The action.
    pub action: String,
}

impl From<&Request> for RequestSnapshot {
    fn from(r: &Request) -> Self {
        RequestSnapshot {
            actor: r.actor.clone(),
            label: r.label,
            purpose: r.purpose.clone(),
            action: r.action.clone(),
        }
    }
}

/// **The policy engine.** Rules indexed by action, so a decision does not scan every rule — the real
/// structure the oracle exists to keep honest.
pub struct Engine {
    version: String,
    /// action → rules whose action is exactly that. Plus a bucket of action-wildcard rules that apply
    /// to every request. Indexing by the request's action lets a decision skip every rule about some
    /// other action — the optimisation whose correctness the oracle checks.
    by_action: BTreeMap<String, Vec<PolicyRule>>,
    any_action: Vec<PolicyRule>,
}

impl Engine {
    /// Compile a policy set.
    pub fn new(set: &PolicySet) -> Self {
        let mut by_action: BTreeMap<String, Vec<PolicyRule>> = BTreeMap::new();
        let mut any_action = Vec::new();
        for rule in &set.rules {
            match &rule.action {
                Match::Is(a) => by_action.entry(a.clone()).or_default().push(rule.clone()),
                Match::Any => any_action.push(rule.clone()),
            }
        }
        Engine {
            version: set.version.clone(),
            by_action,
            any_action,
        }
    }

    /// **Decide.** Deny-overrides, then allow-if-permitted, else fail closed.
    ///
    /// The two passes are the whole semantics, and the order of the passes — not the order of the
    /// rules — is what makes deny final: we look for *any* applicable deny first, across both the
    /// action-specific rules and the action-wildcard rules, and only if there is none do we look for an
    /// allow. No allow can be reached while a deny applies.
    pub fn decide(&self, req: &Request) -> PolicyDecision {
        let specific = self
            .by_action
            .get(&req.action)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let applicable = || {
            specific
                .iter()
                .chain(&self.any_action)
                .filter(|r| r.applies_to(req))
        };

        // Pass 1: any deny wins.
        if let Some(rule) = applicable().find(|r| r.effect == Effect::Deny) {
            return self.decision(req, Decision::Deny, format!("denied by rule {rule:?}"));
        }

        // Pass 2: an allow, now that we know nothing denies.
        if applicable().any(|r| r.effect == Effect::Allow) {
            return self.decision(
                req,
                Decision::Allow,
                "allowed, and no rule denies".to_string(),
            );
        }

        // Pass 3: nothing applied. The default is no.
        self.decision(
            req,
            Decision::Deny,
            "no rule permits this; the default is deny (fail closed)".to_string(),
        )
    }

    fn decision(&self, req: &Request, decision: Decision, rationale: String) -> PolicyDecision {
        PolicyDecision {
            decision,
            policy_version: self.version.clone(),
            request: RequestSnapshot::from(req),
            rationale,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(action: &str) -> Request {
        Request {
            actor: "agent".into(),
            label: TrustClass::Untrusted,
            purpose: "authorize_action".into(),
            action: action.into(),
        }
    }

    fn rule(action: Match<String>, effect: Effect) -> PolicyRule {
        PolicyRule {
            actor: Match::Any,
            label: Match::Any,
            purpose: Match::Any,
            action,
            effect,
        }
    }

    #[test]
    fn an_empty_policy_denies_everything() {
        let e = Engine::new(&PolicySet::empty("v0"));
        assert_eq!(e.decide(&req("anything")).decision, Decision::Deny);
    }

    #[test]
    fn deny_overrides_allow_regardless_of_order() {
        // Allow first, then deny.
        let e = Engine::new(&PolicySet::new(
            "v1",
            vec![
                rule(Match::Any, Effect::Allow),
                rule(Match::Is("x".into()), Effect::Deny),
            ],
        ));
        assert_eq!(
            e.decide(&req("x")).decision,
            Decision::Deny,
            "a deny must beat an allow"
        );

        // Deny first, then allow — same result.
        let e2 = Engine::new(&PolicySet::new(
            "v1",
            vec![
                rule(Match::Is("x".into()), Effect::Deny),
                rule(Match::Any, Effect::Allow),
            ],
        ));
        assert_eq!(
            e2.decide(&req("x")).decision,
            Decision::Deny,
            "order must not matter"
        );
    }

    #[test]
    fn a_decision_records_the_version_and_request() {
        let e = Engine::new(&PolicySet::new("v7", vec![rule(Match::Any, Effect::Allow)]));
        let d = e.decide(&req("read"));
        assert_eq!(d.policy_version, "v7");
        assert_eq!(d.request.action, "read");
    }
}
