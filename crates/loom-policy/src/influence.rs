//! Where policy meets memory and actions: the two questions the demo turns on.
//!
//! - **May this be packed?** (AT-036) — asked of every retrieval candidate, *before* packing, so
//!   restricted data never enters the context window.
//! - **May this authorize this action?** (AT-034) — asked of a proposed action, so an `Untrusted`
//!   scrape cannot suspend an account no matter how confidently an agent proposes it.
//!
//! Both are the *same* engine and the *same* deny-overrides, fail-closed semantics. There is not a
//! separate "influence policy" with its own rules to get out of sync — there is one policy, asked two
//! questions.

use loom_core::{IndexEntry, TrustClass};

use crate::engine::{Decision, Engine, PolicyDecision, Request};

/// The action name a retrieval uses when asking "may this candidate be packed?".
pub const ACTION_PACK: &str = "pack_into_context";

/// The purpose a high-privilege action authorisation is evaluated under.
pub const PURPOSE_AUTHORIZE: &str = "authorize_action";

/// **May a candidate with this label be packed for this purpose?** (AT-036)
///
/// The answer the influence filter needs, per candidate. A deny means the candidate is dropped before
/// scoring — it never reaches the packer, never reaches the window.
pub fn may_pack(engine: &Engine, actor: &str, purpose: &str, entry: &IndexEntry) -> bool {
    engine
        .decide(&Request {
            actor: actor.to_string(),
            label: entry.label,
            purpose: purpose.to_string(),
            action: ACTION_PACK.to_string(),
        })
        .decision
        .is_allowed()
}

/// **May evidence with this label authorize this action?** (AT-034)
///
/// Returns the full decision, not just a bool, because when the answer is *no* the caller must record
/// exactly which policy version refused and why — "what forbade this" has to have an answer, the same
/// way "what allowed this" does (AT-038).
pub fn may_authorize_action(
    engine: &Engine,
    actor: &str,
    action: &str,
    evidence_label: TrustClass,
) -> PolicyDecision {
    engine.decide(&Request {
        actor: actor.to_string(),
        label: evidence_label,
        purpose: PURPOSE_AUTHORIZE.to_string(),
        action: action.to_string(),
    })
}

/// Whether a decision permitted the thing.
pub fn permitted(decision: &PolicyDecision) -> bool {
    decision.decision == Decision::Allow
}
