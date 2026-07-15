//! **Forgetting, and the report that says what it could not undo (AT-044).**
//!
//! Forgetting is taint's mutating cousin. Taint (L2) walks the derivation DAG and returns a *dry-run*
//! plan; forget walks the same DAG and *acts*: it removes every governed representation derived from a
//! source — the index entries that carry the embedding, the text, the summary — and invalidates the
//! claims that rested on it. What it cannot do is reach into the world and un-send what already went
//! out, and the report says so, first, before it says anything it *did* manage to undo.
//!
//! # Why the report leads with what it cannot reverse
//!
//! The same reason a `RecallPlan` does (see `loom_core::recall`): a report that opens with "removed 4
//! representations, invalidated 2 claims" invites the reader to believe the contamination is contained
//! — while the email the poisoned claim authorised is still in someone's inbox. Rewinding a branch and
//! deleting an embedding are reversible; a sent message is not. The irreversible section is first, and
//! it stays first even when it is empty.
//!
//! **It is empty today, and honestly so.** The action gateway is L3.5. Until an action can execute,
//! nothing derived from a forgotten source can have reached the world, so there is nothing to put in
//! the irreversible section. The shape is built and the discipline is enforced by a test; the content
//! arrives with the gateway. This is the same posture as AT-022, and it is tracked, not claimed.

use loom_branch::{CapabilityToken, Loom};
use loom_core::{BranchId, Result, SourceRef, WriteEnvelope};
use loom_provenance::Provenance;

/// What forgetting a source did, and — first — what it could not undo.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ForgetReport {
    /// The source that was forgotten.
    pub source: Option<SourceRef>,
    /// **What reached the world and cannot be pulled back.** First, always. Empty until the action
    /// gateway (L3.5) exists to have executed anything — and honestly empty, not pretended-complete.
    pub irreversible: Vec<IrreversibleEffect>,
    /// Index entries removed — the embeddings, texts, and summaries that made records retrievable.
    pub deindexed: usize,
    /// Claims withdrawn (`Invalidated`). Still readable and auditable; no longer believed or eligible.
    pub invalidated: usize,
    /// The record keys the forget reached, for an auditor who wants to check the set.
    pub reached: Vec<Vec<u8>>,
}

/// An effect that already happened in the outside world and cannot be reversed by touching the
/// database. It carries what is needed to *compensate* or to escalate to a human — never a pretence
/// that removing a row undid it.
#[derive(Clone, Debug, PartialEq)]
pub struct IrreversibleEffect {
    /// What was done.
    pub description: String,
    /// The receipt or action id, so a human can find it.
    pub receipt: String,
}

impl ForgetReport {
    /// A one-line, human-first summary that **leads with the irreversible**.
    pub fn summary(&self) -> String {
        if self.irreversible.is_empty() {
            format!(
                "Forgot {}: removed {} representation(s), invalidated {} claim(s). \
                 Nothing external had been done, so there is nothing that cannot be undone.",
                self.source
                    .as_ref()
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                self.deindexed,
                self.invalidated,
            )
        } else {
            format!(
                "⚠ {} ACTION(S) ALREADY HAPPENED and CANNOT BE UNDONE by forgetting. \
                 Then: removed {} representation(s), invalidated {} claim(s). \
                 The removals are reversible; the actions above are not — compensate or escalate.",
                self.irreversible.len(),
                self.deindexed,
                self.invalidated,
            )
        }
    }
}

/// Forgets sources, propagating through the derivation DAG.
pub struct Forgetter<'a> {
    db: &'a Loom,
}

impl<'a> Forgetter<'a> {
    /// Wrap a database.
    pub fn new(db: &'a Loom) -> Self {
        Forgetter { db }
    }

    /// **Forget a source on a branch, propagating to everything derived from it.**
    ///
    /// Finds the contaminated set with the L2 taint walk, then — in one commit — removes every derived
    /// representation and invalidates every dependent claim. Returns a report that leads with what it
    /// could not undo.
    ///
    /// This *mutates*, and it is token-gated. It is not `taint`, which proposes; it is the execution
    /// the caller explicitly asked for.
    pub fn forget(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        source: &SourceRef,
        envelope: &WriteEnvelope,
    ) -> Result<ForgetReport> {
        // 1. Everything downstream of the source on this branch — the same walk taint uses.
        let prov = Provenance::new(self.db);
        let reached = prov.contaminated_keys_on(branch, source)?;

        // 2. Remove their representations and withdraw their claims, atomically.
        let (invalidated, deindexed) = self
            .db
            .invalidate_and_deindex(token, branch, &reached, envelope)?;

        // 3. The report. The irreversible section is empty until the action gateway exists to have
        //    executed anything — and that emptiness is honest, not a gap we are papering over.
        Ok(ForgetReport {
            source: Some(source.clone()),
            irreversible: Vec::new(),
            deindexed,
            invalidated,
            reached,
        })
    }
}
