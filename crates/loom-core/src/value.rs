//! Records: what actually gets stored, and what the merge engine has to reason about.

use crate::ids::{ActorId, ClaimId, ObservationId, PolicyDecisionId};
use crate::time::{Interval, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// How much a source is trusted.
///
/// This is not decoration. It is an **input to the merge engine** (a claim derived from a
/// `VerifiedSystem` observation outranks one derived from an `Untrusted` scrape) and an input to the
/// action gateway (`Untrusted` evidence may not authorize a destructive action — which is what turns
/// a prompt injection into a string in a context window and nothing else).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustClass {
    /// A system we authenticated and whose records we treat as authoritative.
    VerifiedSystem,
    /// A human being, identified.
    Human,
    /// A third party we have a relationship with.
    ThirdParty,
    /// The open internet, a scraped page, a document of unknown origin. **An agent will read this and
    /// an attacker may have written it.**
    Untrusted,
}

/// Where a piece of evidence came from.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceRef {
    /// The system that produced it.
    pub system: String,
    /// Its identifier within that system.
    pub record_id: String,
}

impl SourceRef {
    /// Name a source.
    pub fn new(system: impl Into<String>, record_id: impl Into<String>) -> Self {
        SourceRef {
            system: system.into(),
            record_id: record_id.into(),
        }
    }
}

impl std::fmt::Display for SourceRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.system, self.record_id)
    }
}

/// A record we received from a source. **Never deleted; corrected by a later observation.**
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// This observation's id.
    pub id: ObservationId,
    /// Where it came from.
    pub source: SourceRef,
    /// How much that source is trusted.
    pub trust: TrustClass,
    /// When it was true in the world. `None` if the source did not say.
    pub observed_at: Option<Timestamp>,
    /// When *we* learned it. Assigned by the engine; immutable.
    pub ingested_at: Timestamp,
    /// The payload.
    pub payload: Vec<u8>,
}

/// How a claim was arrived at.
///
/// Stored because a 0.8 from a calibrated rule set and a 0.8 from a language model are **not the same
/// number**, and combining them arithmetically without saying so is how a system talks itself into
/// confidence it has not earned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Method {
    /// A direct mapping from an observation. No inference.
    Direct,
    /// A deterministic rule.
    Rule,
    /// A statistical model.
    Statistical,
    /// A language model.
    LanguageModel,
    /// A person said so.
    Human,
    /// An assessment imported from another system.
    Imported,
}

impl Method {
    /// How much this method's output is worth when two claims collide.
    ///
    /// Used as a tiebreak in the merge engine, *after* validity. A claim derived directly from a
    /// verified system beats one a language model inferred, and that ordering should not be
    /// controversial.
    pub fn rank(&self) -> u8 {
        match self {
            Method::Direct => 5,
            Method::Human => 4,
            Method::Rule => 3,
            Method::Statistical => 2,
            Method::Imported => 1,
            Method::LanguageModel => 0,
        }
    }
}

/// A confidence value, and where it came from.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Confidence {
    /// 0.0 to 1.0.
    pub value: f64,
    /// The method that produced it.
    pub method: Method,
    /// Which calibration this value is on. Two values are only comparable within one.
    pub calibration: String,
}

impl Confidence {
    /// A confidence from a method, on a named calibration.
    pub fn new(value: f64, method: Method, calibration: impl Into<String>) -> Self {
        Confidence {
            value: value.clamp(0.0, 1.0),
            method,
            calibration: calibration.into(),
        }
    }

    /// Whether two confidences are on the same scale and may be compared or combined.
    ///
    /// **They usually are not**, and the engine refuses to average across calibrations rather than
    /// producing a number that looks meaningful and is not.
    pub fn comparable_with(&self, other: &Confidence) -> bool {
        self.method == other.method && self.calibration == other.calibration
    }
}

/// Where a claim is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimStatus {
    /// Believed.
    Asserted,
    /// A newer claim has taken its place. Still readable, still auditable, **not deleted**.
    Superseded,
    /// Another claim contradicts it within an overlapping validity window.
    Contradicted,
    /// Its evidence was invalidated. **Readable, but not action-eligible until recomputed.**
    ///
    /// This is the everyday mechanism, and it is deliberately *softer* than taint. Most of the time
    /// the right answer to "an input changed" is not "revert history" — it is "stop letting that
    /// conclusion authorize anything until you re-derive it."
    Stale,
    /// Withdrawn.
    Invalidated,
    /// Its validity window has passed.
    Expired,
}

/// A statement we believe. Possibly wrongly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    /// This claim's id.
    pub id: ClaimId,
    /// What is being said about what. `"identity.risk_increased"`, and the subject it is about.
    pub predicate: String,
    /// The subject.
    pub subject: String,
    /// The value asserted.
    pub object: Value,
    /// When it holds **in the world**.
    pub valid: Interval,
    /// When **we** believed it. Assigned by the engine; immutable; closed rather than overwritten.
    pub known: Interval,
    /// How confident we are, and by what method.
    pub confidence: Confidence,
    /// What it was derived from. **May be empty — and an empty one can never authorize an action.**
    pub evidence: Vec<SourceRef>,
    /// Where it is in its life.
    pub status: ClaimStatus,
    /// Which policy decision permitted the write that created it.
    pub policy: Option<PolicyDecisionId>,
    /// Who wrote it.
    pub actor: ActorId,
}

impl Claim {
    /// **The invariant.** A claim with no evidence may be stored, and may be read. It may **never**
    /// authorize an external effect.
    ///
    /// Agents speculate. Forbidding that would just push the speculation somewhere we cannot see it.
    /// So we store the speculation and refuse to let it suspend anybody's account.
    pub fn is_action_eligible(&self) -> bool {
        !self.evidence.is_empty() && matches!(self.status, ClaimStatus::Asserted)
    }

    /// Why this claim cannot authorize an action, in words an LLM can act on.
    pub fn ineligibility_reason(&self) -> Option<String> {
        if self.evidence.is_empty() {
            return Some(format!(
                "claim {} is unsupported (it cites no evidence) and cannot justify an action. \
                 Cite the observations it was derived from, or re-derive it.",
                self.id
            ));
        }
        match self.status {
            ClaimStatus::Asserted => None,
            ClaimStatus::Stale => Some(format!(
                "claim {} is STALE: evidence it depends on was invalidated. \
                 Re-derive it before citing it to justify an action.",
                self.id
            )),
            other => Some(format!(
                "claim {} is {other:?} and cannot justify an action.",
                self.id
            )),
        }
    }

    /// The rank used to break a merge tie: trustworthiness of method, then confidence.
    pub fn provenance_rank(&self) -> (u8, u64) {
        (
            self.confidence.method.rank(),
            (self.confidence.value * 1_000_000.0) as u64,
        )
    }
}

/// What a record holds.
///
/// The variants exist because **the merge engine needs to know how to combine them**. A blob it
/// cannot merge; a counter it can add; a set it can union. Typing values is what lets two agents work
/// concurrently without every write becoming a conflict.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Value {
    /// Opaque bytes. Not mergeable — two different edits go to the merge policy.
    Blob(Vec<u8>),
    /// A number that only ever accumulates. **Merges arithmetically**, and this is most agent
    /// concurrency: two branches each incrementing by 3 yields +6, not a conflict.
    Counter(i64),
    /// A set that only grows. Merges by union.
    Set(BTreeSet<Vec<u8>>),
    /// A boolean.
    Bool(bool),
    /// Text.
    Text(String),
    /// A number.
    Number(f64),
}

impl Value {
    /// True if this value type merges without asking anyone.
    pub fn is_additive(&self) -> bool {
        matches!(self, Value::Counter(_) | Value::Set(_))
    }

    /// A short description, for a conflict report a language model has to read.
    pub fn describe(&self) -> String {
        match self {
            Value::Blob(b) => format!("{} bytes of opaque data", b.len()),
            Value::Counter(n) => format!("counter = {n}"),
            Value::Set(s) => format!("set of {} items", s.len()),
            Value::Bool(b) => format!("{b}"),
            Value::Text(t) if t.len() <= 60 => format!("{t:?}"),
            Value::Text(t) => format!("{:?}… ({} chars)", &t[..60], t.len()),
            Value::Number(n) => format!("{n}"),
        }
    }
}

/// What is stored at a key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Record {
    /// A source record.
    Observation(Box<Observation>),
    /// A belief.
    Claim(Box<Claim>),
    /// A raw value, for the memory stores that do not need the full claim machinery.
    Value(Value),
}

impl Record {
    /// The value inside, whatever the wrapper.
    pub fn value(&self) -> Option<&Value> {
        match self {
            Record::Claim(c) => Some(&c.object),
            Record::Value(v) => Some(v),
            Record::Observation(_) => None,
        }
    }

    /// A one-line description, for a merge conflict report an LLM has to act on.
    pub fn describe(&self) -> String {
        match self {
            Record::Observation(o) => format!(
                "observation from {} (trust: {:?})",
                o.source, o.trust
            ),
            Record::Claim(c) => format!(
                "claim {:?} about {:?} = {} (method: {:?}, confidence {:.2}, {} evidence item(s), {:?})",
                c.predicate,
                c.subject,
                c.object.describe(),
                c.confidence.method,
                c.confidence.value,
                c.evidence.len(),
                c.status
            ),
            Record::Value(v) => v.describe(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::ClaimId;

    fn claim(evidence: Vec<SourceRef>, status: ClaimStatus) -> Claim {
        Claim {
            id: ClaimId::new(),
            predicate: "identity.compromised".into(),
            subject: "user-4471".into(),
            object: Value::Bool(true),
            valid: Interval::from(Timestamp::from_ms(0)),
            known: Interval::from(Timestamp::from_ms(0)),
            confidence: Confidence::new(0.9, Method::Rule, "risk-v4"),
            evidence,
            status,
            policy: None,
            actor: ActorId::new("agent-1"),
        }
    }

    #[test]
    fn an_unsupported_claim_can_be_stored_but_never_act() {
        let c = claim(vec![], ClaimStatus::Asserted);
        assert!(!c.is_action_eligible());

        let reason = c.ineligibility_reason().expect("must give a reason");
        assert!(reason.contains("unsupported"));
        // The message has to tell a model what to DO, not just what went wrong.
        assert!(reason.contains("Cite the observations"));
    }

    #[test]
    fn a_stale_claim_cannot_act_and_says_why() {
        let c = claim(
            vec![SourceRef::new("idp", "signin-847")],
            ClaimStatus::Stale,
        );
        assert!(!c.is_action_eligible());
        let reason = c.ineligibility_reason().expect("must give a reason");
        assert!(reason.contains("STALE"));
        assert!(reason.contains("Re-derive"));
    }

    #[test]
    fn a_supported_asserted_claim_can_act() {
        let c = claim(
            vec![SourceRef::new("idp", "signin-847")],
            ClaimStatus::Asserted,
        );
        assert!(c.is_action_eligible());
        assert_eq!(c.ineligibility_reason(), None);
    }

    #[test]
    fn a_direct_observation_outranks_a_language_model() {
        // The tiebreak that decides merges. It should not be controversial.
        assert!(Method::Direct.rank() > Method::LanguageModel.rank());
        assert!(Method::Human.rank() > Method::Statistical.rank());
    }

    #[test]
    fn confidences_from_different_methods_are_not_comparable() {
        // A 0.8 from a rule set and a 0.8 from an LLM are not the same number, and the engine must
        // not pretend otherwise.
        let rule = Confidence::new(0.8, Method::Rule, "risk-v4");
        let llm = Confidence::new(0.8, Method::LanguageModel, "risk-v4");
        assert!(!rule.comparable_with(&llm));

        let same = Confidence::new(0.6, Method::Rule, "risk-v4");
        assert!(rule.comparable_with(&same));
    }

    #[test]
    fn counters_and_sets_are_additive_and_blobs_are_not() {
        assert!(Value::Counter(1).is_additive());
        assert!(Value::Set(BTreeSet::new()).is_additive());
        assert!(!Value::Blob(vec![1]).is_additive());
        assert!(!Value::Text("x".into()).is_additive());
    }
}
