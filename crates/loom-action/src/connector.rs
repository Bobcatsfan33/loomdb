//! The connector: the thing that reaches into the world, and the honest account of what it did.

/// What a connector reports after being asked to do something.
///
/// The variants are exhaustive about the three things that can actually happen, and — crucially —
/// they distinguish "it worked" from "it *said* it worked but gave me nothing to prove it" and from
/// "I have no idea". Collapsing those into a boolean is how a system claims success it cannot back and
/// retries an effect that already happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectorOutcome {
    /// It happened, and here is the proof. The receipt is what makes terminal success *auditable* —
    /// without it, "succeeded" is a claim, not a fact (AT-032).
    Succeeded {
        /// The connector's receipt: an external id, a confirmation number, whatever proves it.
        receipt: String,
    },
    /// It reported success but returned **no receipt**. This is NOT terminal success. A connector that
    /// cannot prove what it did is a connector we do not let mark an action done.
    SucceededWithoutReceipt,
    /// It definitively failed, and here is why.
    Failed {
        /// Why it failed, in words.
        reason: String,
    },
    /// **We do not know.** A timeout, a dropped connection, a connector with no idempotency status —
    /// the effect may or may not have happened. This is a first-class answer (AT-029), not a failure
    /// in disguise, because treating "unknown" as "failed" invites a retry that double-acts.
    Indeterminate {
        /// What we do know — the timeout, the error, the last thing we saw.
        detail: String,
    },
}

/// Something that can perform an external effect.
///
/// Implementors do the actual work — call an API, send the email, suspend the account. The gateway
/// handles everything *around* the call: policy, evidence, idempotency, receipts. A connector's only
/// job is to do the thing and report honestly what happened, including "I don't know".
pub trait Connector: Send + Sync {
    /// The action type this connector handles, e.g. `"identity.suspend_account"`.
    fn action_type(&self) -> &str;

    /// Whether this connector is a **simulation** — a safe stand-in with no external effect, used by
    /// simulation branches (AT-031). A production connector returns `false`; a simulated one returns
    /// `true`, and the gateway routes simulation-branch proposals only to these.
    fn is_simulated(&self) -> bool {
        false
    }

    /// Do the thing. `idempotency_key` is stable across retries of the *same* logical action, so a
    /// connector that supports it can deduplicate on its own side too.
    fn execute(&self, target: &str, idempotency_key: &str) -> ConnectorOutcome;
}
