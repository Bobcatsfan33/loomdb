//! # loom-provenance
//!
//! The derivation DAG's *readers*: **taint**, **staleness**, and the walk that connects a poisoned
//! source to every conclusion built on it.
//!
//! The DAG's *writers* live in `loom-branch`, at the write entry point, deliberately: if provenance
//! could be attached by a layer above the write, then there would be a code path that writes without
//! it — and a bypassable audit trail is worse than no audit trail, because it is **believed**.
//!
//! ## What this can answer that an audit log cannot
//!
//! > *A source you trusted turns out to have been poisoned. Which of your agent's conclusions are
//! > downstream of it, and what do you do about them?*
//!
//! An audit log records **that** a write happened. It does not record **what it was derived from**.
//! That is the whole difference, and it is why this is a DAG.
//!
//! ## Two mechanisms, and they are not the same
//!
//! - **Staleness** is the scalpel. An input was corrected or invalidated, so everything downstream is
//!   marked `Stale` — still readable, still auditable, but **no longer able to authorize an action**
//!   until it is re-derived. This is what you want on a Tuesday.
//! - **Taint** is the sledgehammer. A source was *poisoned*, and history has to be walked and undone.
//!   It produces a plan; it never executes one.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(rust_2018_idioms)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod taint;

pub use taint::{flood_downstream, Provenance, TaintStats, MAX_DERIVATION_DEPTH};
