//! The durable record of an action: what was asked, what was decided, what happened.

use loom_core::ActorId;

/// A stable id for an action, derived from its idempotency key.
///
/// **Derived, not random**, so that a retry of the same logical action computes the *same* id without
/// coordination — which is what makes idempotency checkable (AT-028). Two proposals with the same
/// idempotency key are the same action, and they get the same `ActionId`, and the gateway executes it
/// once.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionId(pub String);

impl ActionId {
    /// The id for an idempotency key.
    pub fn of(idempotency_key: &str) -> Self {
        ActionId(format!("act_{}", blake3_hex(idempotency_key.as_bytes())))
    }

    /// As a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Where an action is in its life. The terminal states are `Succeeded`, `Failed`, and `Refused`;
/// `Indeterminate` is terminal-for-now but honest that it may need a human.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionStatus {
    /// Refused before execution — by policy, by the kill switch, by stale evidence, by containment. It
    /// never touched the world. The reason names the corrective action.
    Refused {
        /// Why, in words a caller (or an LLM) can act on.
        reason: String,
    },
    /// Done, with proof.
    Succeeded {
        /// The connector's receipt.
        receipt: String,
    },
    /// Definitively failed.
    Failed {
        /// Why.
        reason: String,
    },
    /// **Unknown.** The effect may or may not have happened. Surfaced to an operator; blocks nothing
    /// else (AT-029).
    Indeterminate {
        /// What we know.
        detail: String,
    },
}

impl ActionStatus {
    /// Did this reach terminal success? Only `Succeeded` — never `Indeterminate`, never a receiptless
    /// success. This is the AT-032 gate in one function.
    pub fn is_success(&self) -> bool {
        matches!(self, ActionStatus::Succeeded { .. })
    }
}

/// The durable record of one action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionRecord {
    /// The id (stable across retries).
    pub id: ActionId,
    /// What kind of action.
    pub action_type: String,
    /// What it acted on.
    pub target: String,
    /// Who proposed it.
    pub actor: ActorId,
    /// The branch it was proposed on.
    pub branch: String,
    /// The policy version that decided.
    pub policy_version: String,
    /// Where it ended up.
    pub status: ActionStatus,
}

impl ActionRecord {
    /// The receipt, if this action succeeded. Used to fill a taint plan's irreversible section
    /// (AT-022) — the proof of a thing that happened and cannot be un-happened.
    pub fn receipt(&self) -> Option<&str> {
        match &self.status {
            ActionStatus::Succeeded { receipt } => Some(receipt),
            _ => None,
        }
    }
}

/// A tiny local BLAKE3-to-hex, to avoid taking a dependency just for an id. Deterministic.
fn blake3_hex(bytes: &[u8]) -> String {
    let hash = blake3::hash(bytes);
    hash.to_hex().to_string()[..16].to_string()
}
