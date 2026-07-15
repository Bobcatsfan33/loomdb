//! # loom-core
//!
//! The vocabulary. Every other LoomDB crate speaks in these types, and none of them defines a
//! competing version — a system with two ideas of what a "claim" is has no idea what a claim is.
//!
//! The shapes here come straight from `docs/03` in the substrate repository, which is the
//! architecture of record.
//!
//! ## The distinction the whole database hangs on
//!
//! An **observation** is what a source told us. A **claim** is what we *believe*, possibly wrongly.
//! They are different objects, and conflating them makes "what did the agent actually know" a
//! question with no answer.
//!
//! | | Observation | Claim |
//! |---|---|---|
//! | Who made it | the world | us — a rule, a model, or a human |
//! | Can it be wrong? | yes, but it is still *what the source said* | yes, and then it is **our** mistake |
//! | Deleted? | never; corrected by a later observation | never; superseded or invalidated |
//!
//! The identity provider said this account signed in from Belarus. That is an *observation*. "This
//! account is compromised" is a *claim* derived from it, by a method, with a confidence — and it can
//! be wrong in ways the observation cannot.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(rust_2018_idioms)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod embedding;
mod envelope;
mod error;
mod ids;
mod index;
mod provenance;
mod recall;
mod time;
mod value;

pub use embedding::Embedding;
pub use envelope::WriteEnvelope;
pub use error::{LoomError, Result};
pub use ids::{
    ActorId, BranchId, ClaimId, CommitId, ObservationId, PolicyDecisionId, SessionId, TenantId,
};
pub use index::{IndexEntry, IndexHint, RESERVED_INDEX_PREFIX};
pub use provenance::{
    is_provenance, latest_node_key, node_from_index_value, node_storage_key, prov_seq_key,
    source_index_key, source_index_prefix, DerivationNode, NodeId, PROV_PREFIX,
    RESERVED_LATEST_PREFIX, SRC_PREFIX,
};
pub use recall::{Compensation, IrreversibleItem, RecallPlan, ReversibleItem};
pub use time::{Interval, Timestamp};
pub use value::{
    Claim, ClaimStatus, Confidence, Method, Observation, Record, SourceRef, TrustClass, Value,
};

/// A record key. Ordered, opaque bytes.
///
/// Ordering is lexicographic, which is what makes range scans and the B-tree work. The layers above
/// impose structure on it (`claim/<entity>/<predicate>`), and the storage layer does not care.
pub type Key = Vec<u8>;
