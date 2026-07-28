//! # loom-branch
//!
//! Sessions-as-branches, capability tokens, and the record-level merge engine.
//!
//! Built on substrate v1.x public APIs only. Nothing here reaches past `PageStore`.
//!
//! ## A session is a branch
//!
//! `open_session()` forks the tenant's base image — a substrate `fork`, which is O(1) and copies
//! nothing. A million idle sessions are a million manifests: bytes in object storage, no compute.
//!
//! An agent can therefore afford to *try* things. It branches three hypotheses, writes freely in each,
//! merges the one that worked, and rewinds the two that did not — and the rewound ones stay readable
//! and auditable, because nothing was destroyed, only unreferenced.
//!
//! ## Two mechanisms, two different questions
//!
//! - [`token`] answers **"may you write here?"** — branch scope, and there is no code path that
//!   touches a page outside it.
//! - It does **not** answer *"may this data influence what you produce, or what you do?"*. That is
//!   information flow, it is where prompt injection lives, and it belongs to `loom-policy`.
//!
//! Conflating the two is how a system ends up claiming a "provable blast radius" it does not have.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(rust_2018_idioms)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod ann;
pub mod merge;
mod refs;
pub mod session;
pub mod sleep;
pub mod tenancy;
pub mod token;
pub mod tree;

pub use merge::{
    is_reserved, plan_merge, MergeConflict, MergeConflictReport, MergeOutcome, MergePolicy,
    Resolution, RESERVED_PREFIX,
};
pub use refs::{FileRefStore, MemRefStore, RefEdit, RefStore, Refs, REFS_FORMAT_VERSION};
pub use session::ReadSet;
pub use session::{Loom, MergeResult, SessionHandle, DEFAULT_SESSION_TTL_MS, MAIN};
pub use sleep::LoomWakeToken;
pub use tenancy::Tenancy;
pub use token::{CapabilityToken, TokenClaims, TokenIssuer};
pub use tree::{Meta, Node, Tree, FORMAT_VERSION, META_PAGE};
