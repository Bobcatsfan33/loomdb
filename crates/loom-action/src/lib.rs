//! **The action gateway (L3.5).**
//!
//! The one place an external effect can happen — and, structurally, the *only* place. This is where
//! demo step 7 lives (a real action, checked and executed idempotently with a receipt) and where the
//! guarantees that make step 8 and step 10 meaningful are enforced.
//!
//! # The shape of the guarantee (AT-027): agents propose, the gateway acts
//!
//! An agent holds an [`AgentStore`]. Look at its methods: it can `propose`. There is **no
//! `execute`** — not a private one, not a guarded one, none. Executing takes an [`ActionGateway`],
//! which an agent does not have and cannot construct from an `AgentStore`. This is the same move that
//! made branch isolation structural: the strongest way to guarantee an agent cannot act is for there
//! to be no method it could call, so a prompt injection that says "call execute_action" is asking for
//! a function that does not exist.
//!
//! # What the gateway checks, in order, before anything happens
//!
//! 1. **The kill switch** (AT-033). If actions are disabled — globally or for this tenant — every new
//!    action is refused. Reads, writes, and audit are untouched, because they never come through here.
//! 2. **Evidence** (AT-007, AT-030). Every cited claim must be *action-eligible*: it must cite
//!    evidence, and it must not be `Stale`/`Invalidated`. A conclusion whose input was withdrawn
//!    cannot authorize an effect until it is re-derived.
//! 3. **Policy** (AT-034, AT-037). `may_authorize_action` under deny-overrides, fail-closed. `Untrusted`
//!    evidence cannot authorize a destructive action however confident the claim.
//! 4. **Simulation containment** (AT-031). A proposal from a simulation branch may not reach a
//!    production connector; it is denied by default, or routed to a registered simulated one.
//!
//! Only then does it execute — **idempotently** (AT-028): the same idempotency key yields at most one
//! side effect, however many times it is retried, concurrently or after a timeout. And a connector
//! that reports success without a **receipt** does not reach terminal `Succeeded` (AT-032); a
//! connector that times out with no idempotency status is **`Indeterminate`** (AT-029), never a
//! guessed success or failure.

mod connector;
mod gateway;
mod record;

pub use connector::{Connector, ConnectorOutcome};
pub use gateway::{ActionGateway, AgentStore, KillSwitch, Proposal};
pub use record::{ActionId, ActionRecord, ActionStatus};
