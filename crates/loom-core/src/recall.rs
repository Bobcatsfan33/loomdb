//! The `RecallPlan` — what a taint can undo, and what it cannot.
//!
//! # Why this shape exists before the thing that fills it
//!
//! The `irreversible` section will be **empty until the action gateway lands in L3.5**. It is defined
//! now anyway, for the same reason `WriteEnvelope` was defined in L1 rather than L2: a field added
//! later is a field that everything downstream was built without, and reshaping a report that an
//! auditor, a CLI, and an MCP tool have all learned to read is a change nobody wants to make.
//!
//! # The dishonesty this shape exists to prevent
//!
//! **Taint cannot undo an action.** Rewinding a manifest reverts *writes*. It does not un-suspend an
//! account, un-send an email, or un-wire money.
//!
//! An earlier draft of the architecture implied that `taint()` reverted everything downstream of a
//! poisoned source. That was false in the way that gets a company sued. A taint report that shows six
//! reverted writes and quietly omits the account it suspended is not an audit tool — it is a
//! liability, and it is worse than no report at all, because it will be *believed*.
//!
//! So the plan has two sections, and **the one we cannot fix is printed first**:
//!
//! ```text
//! RecallPlan
//!   IRREVERSIBLE ─── the actions that already happened in the world.        ← FIRST. ALWAYS.
//!                    Each with its receipt, and either a registered
//!                    compensating action or an explicit escalation
//!                    to a human.
//!
//!   reversible ───── the writes and claims. Rewind or tombstone.
//!                    This part we can actually do.
//! ```
//!
//! `compensate: None` is an **allowed and honest answer**. Fabricating a compensating action for an
//! irreversible effect would be worse than admitting there isn't one.

use crate::ids::{ActorId, BranchId, ClaimId, CommitId};
use crate::value::SourceRef;
use serde::{Deserialize, Serialize};

/// What a taint proposes doing about one contaminated write.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Compensation {
    /// Move the branch back to a commit before the contamination. O(1), and it takes everything
    /// after it with it.
    Rewind {
        /// The branch to move.
        branch: BranchId,
        /// Where to move it to.
        to: CommitId,
    },
    /// Mark specific records invalid without rewinding the branch — used when the contaminated
    /// writes are interleaved with clean ones and a rewind would take too much with it.
    Tombstone {
        /// The branch.
        branch: BranchId,
        /// The claims to invalidate.
        claims: Vec<ClaimId>,
    },
}

/// One thing the plan can actually undo.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReversibleItem {
    /// Where it lives.
    pub branch: BranchId,
    /// The commit that introduced it.
    pub commit: CommitId,
    /// Who wrote it.
    pub actor: ActorId,
    /// What it was, in words a person can read.
    pub description: String,
    /// How it got here from the tainted source — the derivation path, so a reader can *check* the
    /// claim rather than take it on faith.
    pub derived_via: Vec<String>,
    /// What to do about it.
    pub compensation: Compensation,
}

/// **One thing the plan cannot undo.**
///
/// An effect that already happened in the world. The database can tell you it happened, prove what
/// justified it, and — if the connector registered one — propose a compensating action. It cannot
/// make it not have happened.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrreversibleItem {
    /// The action.
    pub action_id: String,
    /// What it did. `"identity.suspend_account"`.
    pub action_type: String,
    /// What it did it to.
    pub target: String,
    /// Who asked for it, and under whose delegated authority.
    pub actor: ActorId,
    /// The connector's receipt — the proof it actually happened.
    pub receipt: Option<String>,
    /// The claims that justified it, which are downstream of the tainted source.
    pub justified_by: Vec<ClaimId>,
    /// How it got here from the tainted source.
    pub derived_via: Vec<String>,
    /// What can be done about it.
    ///
    /// `None` means **nothing can**, and that is a real answer. The connector registered no
    /// compensating action, so a human has to decide. Inventing one would be worse than saying so.
    pub compensating_action: Option<String>,
    /// What a human is being asked to do, in plain words.
    pub escalation: String,
}

/// The plan.
///
/// Produced by `taint()`. **Nothing here has happened.** Execution is a separate, token-gated call —
/// a system that can silently delete a tenant's data on a signal is a system that can be turned into
/// a weapon.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecallPlan {
    /// What was tainted.
    pub source: Option<SourceRef>,

    /// **The actions that already happened in the world.**
    ///
    /// First in the struct, first in the report, first in every rendering. If this list is non-empty
    /// and a reader misses it, the report has failed at its only job.
    pub irreversible: Vec<IrreversibleItem>,

    /// The writes and claims. These we can actually undo.
    pub reversible: Vec<ReversibleItem>,
}

impl RecallPlan {
    /// True if the contamination is fully containable — nothing escaped into the world.
    pub fn is_fully_reversible(&self) -> bool {
        self.irreversible.is_empty()
    }

    /// True if a human has to make a decision no compensating action can make for them.
    pub fn needs_human(&self) -> bool {
        self.irreversible
            .iter()
            .any(|i| i.compensating_action.is_none())
    }

    /// How many things this plan touches.
    pub fn len(&self) -> usize {
        self.irreversible.len() + self.reversible.len()
    }

    /// True if nothing is downstream of the tainted source.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Display for RecallPlan {
    /// The report. **Written for a human being who is having a bad day.**
    ///
    /// The irreversible section is printed first, and it is printed loudly, because the single worst
    /// outcome of this feature is a reader who skims a wall of reverted writes and never notices the
    /// account that is still suspended.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.source {
            Some(source) => writeln!(f, "RECALL PLAN — tainted source: {source}")?,
            None => writeln!(f, "RECALL PLAN")?,
        }
        writeln!(f, "This is a DRY RUN. Nothing has been changed.\n")?;

        if self.is_empty() {
            return writeln!(
                f,
                "Nothing is downstream of this source. No action is needed."
            );
        }

        // ── THE PART WE CANNOT FIX. FIRST. ────────────────────────────────
        if !self.irreversible.is_empty() {
            writeln!(
                f,
                "⚠  {} ACTION(S) ALREADY HAPPENED IN THE WORLD AND CANNOT BE UNDONE BY THIS DATABASE.",
                self.irreversible.len()
            )?;
            writeln!(
                f,
                "   Rewinding a branch reverts writes. It does not un-suspend an account.\n"
            )?;

            for item in &self.irreversible {
                writeln!(f, "   • {} → {}", item.action_type, item.target)?;
                writeln!(f, "       requested by:  {}", item.actor)?;
                if let Some(receipt) = &item.receipt {
                    writeln!(f, "       receipt:       {receipt}")?;
                }
                writeln!(
                    f,
                    "       justified by:  {} claim(s) downstream of the tainted source",
                    item.justified_by.len()
                )?;
                match &item.compensating_action {
                    Some(action) => {
                        writeln!(f, "       CAN BE COMPENSATED: {action}")?;
                    }
                    None => {
                        writeln!(
                            f,
                            "       NO COMPENSATING ACTION EXISTS. A human must decide."
                        )?;
                    }
                }
                writeln!(f, "       → {}\n", item.escalation)?;
            }
        }

        // ── The part we can fix. ──────────────────────────────────────────
        if !self.reversible.is_empty() {
            writeln!(
                f,
                "{} write(s) are downstream of this source and CAN be reverted:\n",
                self.reversible.len()
            )?;
            for item in &self.reversible {
                writeln!(f, "   • {} [{}]", item.description, item.branch)?;
                writeln!(f, "       written by: {}", item.actor)?;
                match &item.compensation {
                    Compensation::Rewind { branch, to } => {
                        writeln!(f, "       action:     rewind {branch} to {to}")?;
                    }
                    Compensation::Tombstone { branch, claims } => {
                        writeln!(
                            f,
                            "       action:     invalidate {} claim(s) in {branch}",
                            claims.len()
                        )?;
                    }
                }
                if !item.derived_via.is_empty() {
                    writeln!(f, "       via:        {}", item.derived_via.join(" → "))?;
                }
                writeln!(f)?;
            }
        }

        writeln!(
            f,
            "To carry out the reversible part, call execute_recall() with this plan's id. \
             It is a separate, token-gated call, deliberately."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn irreversible(compensating: Option<&str>) -> IrreversibleItem {
        IrreversibleItem {
            action_id: "acn_01".into(),
            action_type: "identity.suspend_account".into(),
            target: "user-4471".into(),
            actor: ActorId::new("agent-responder"),
            receipt: Some("okta:suspend:88213".into()),
            justified_by: vec![ClaimId::of(b"clm")],
            derived_via: vec!["obs_signin".into(), "clm_compromised".into()],
            compensating_action: compensating.map(str::to_string),
            escalation: "Review whether the suspension was warranted; if not, restore the account."
                .into(),
        }
    }

    #[test]
    fn a_plan_with_no_actions_is_fully_reversible() {
        let plan = RecallPlan {
            source: Some(SourceRef::new("web", "poisoned-page")),
            irreversible: vec![],
            reversible: vec![],
        };
        assert!(plan.is_fully_reversible());
        assert!(!plan.needs_human());
    }

    #[test]
    fn an_action_that_already_happened_makes_the_plan_irreversible() {
        let plan = RecallPlan {
            source: Some(SourceRef::new("web", "poisoned-page")),
            irreversible: vec![irreversible(Some("identity.restore_account"))],
            reversible: vec![],
        };
        assert!(!plan.is_fully_reversible());
        // A compensating action exists, so a human is not strictly required.
        assert!(!plan.needs_human());
    }

    #[test]
    fn no_compensating_action_means_a_human_must_decide() {
        // This is the honest case. The connector registered no way to undo what it did, and
        // fabricating one would be worse than saying so.
        let plan = RecallPlan {
            source: Some(SourceRef::new("web", "poisoned-page")),
            irreversible: vec![irreversible(None)],
            reversible: vec![],
        };
        assert!(plan.needs_human());
        assert!(plan
            .to_string()
            .contains("NO COMPENSATING ACTION EXISTS. A human must decide."));
    }

    #[test]
    fn the_report_leads_with_what_it_cannot_undo() {
        // THE test for this type. The worst outcome of this whole feature is a reader who skims a
        // wall of reverted writes and never notices the account that is still suspended. So the
        // thing we cannot fix comes first, in the struct and on the page.
        let plan = RecallPlan {
            source: Some(SourceRef::new("web", "poisoned-page")),
            irreversible: vec![irreversible(None)],
            reversible: vec![ReversibleItem {
                branch: BranchId::new("h2"),
                commit: CommitId::from_bytes([1; 32]),
                actor: ActorId::new("agent-1"),
                description: "claim: user-4471 is compromised".into(),
                derived_via: vec!["obs_poisoned".into()],
                compensation: Compensation::Rewind {
                    branch: BranchId::new("h2"),
                    to: CommitId::from_bytes([0; 32]),
                },
            }],
        };

        let report = plan.to_string();
        let irreversible_at = report
            .find("CANNOT BE UNDONE")
            .expect("the report must say what it cannot undo");
        let reversible_at = report
            .find("CAN be reverted")
            .expect("the report must say what it can undo");

        assert!(
            irreversible_at < reversible_at,
            "the report buried the account it cannot un-suspend BELOW a list of writes it can \
             revert. That is precisely the report that gets skimmed, and precisely the omission \
             that makes this a liability rather than an audit tool."
        );

        // And it must be unmissable.
        assert!(report.contains("⚠"));
        assert!(report.contains("It does not un-suspend an account"));
        // And it must say, out loud, that it has not done anything yet.
        assert!(report.contains("DRY RUN"));
    }

    #[test]
    fn a_plan_is_a_proposal_not_an_act() {
        // taint() never auto-executes. A system that can silently delete a tenant's data on a signal
        // is a system that can be turned into a weapon (AT-024).
        let plan = RecallPlan::default();
        assert!(plan.to_string().contains("DRY RUN"));
    }
}
