//! **The policy engine (L3.5).**
//!
//! One question, asked the same way everywhere: *may this actor, acting on data with this label, for
//! this purpose, take this action?* The answer is a [`PolicyDecision`] — allow or deny, with the
//! version and inputs that produced it, so "what allowed this" always has an exact answer (AT-038).
//!
//! Two rules govern how the answer is computed, and both are non-negotiable:
//!
//! - **Deny-overrides.** If *any* applicable rule denies, the decision is deny — no matter how many
//!   rules allow, and no matter what order they are in. Security is a veto, not a vote.
//! - **Fail closed.** No applicable rule means **deny**, not allow (AT-037). There is no policy set,
//!   however misconfigured, and no engine state, however broken, in which an action fails *open*. The
//!   default is no.
//!
//! # Why this has an oracle
//!
//! docs/05 §4 names three subsystems that get a naive model and a differential test, because an engine
//! written fast has a trust problem only evidence answers. Policy is the third (taint and branch are
//! the others). The engine here indexes rules by action and short-circuits on the first deny — a real
//! optimisation, and exactly the kind of thing that gets deny-overrides or fail-closed subtly wrong. A
//! naive truth-table model evaluates the pure semantics, and thousands of randomized policy sets try to
//! make the two disagree. Getting this wrong fails *open*, which is the one direction that must be
//! impossible by construction.

mod engine;

pub use engine::{
    Decision, Effect, Engine, Match, PolicyDecision, PolicyRule, PolicySet, Request,
    RequestSnapshot,
};

/// Re-exported: the trust of the data being acted on is its policy label.
pub use loom_core::TrustClass;
