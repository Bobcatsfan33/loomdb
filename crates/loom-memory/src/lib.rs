//! **Memory and retrieval for LoomDB (L3).**
//!
//! This crate turns a branch's records into something an agent can retrieve *under a token budget*,
//! with three properties that are not negotiable because each maps to an acceptance test:
//!
//! - **Branch isolation is structural** (AT-040). Index entries live in the branch's own tree, so a
//!   sibling branch cannot see them — the same content-addressed fork isolation that `read` relies
//!   on. There is no global index with a branch filter to forget. See [`loom_core::IndexEntry`].
//! - **Every packed item is cited** (AT-041). An uncited entry cannot be constructed, so no retrieval
//!   can pack one. The citation resolves to a real `SourceRef` that also appears in the provenance
//!   DAG.
//! - **Packing is robust under any budget** (AT-042). Whole items only, greedy by score, never a
//!   panic and never a fact truncated mid-evidence — whether the budget is 50 tokens against 100,000
//!   candidates or unlimited against three.
//!
//! And two that shape the ranking:
//!
//! - **Stale claims are down-ranked and marked** (AT-043), never silently dropped and never silently
//!   trusted.
//! - **Forgetting propagates** (AT-044): removing a source rebuilds or removes every representation
//!   derived from it, and reports what it could not undo.

mod forget;
mod retrieval;
mod tokens;

pub use forget::{ForgetReport, Forgetter, IrreversibleEffect};
pub use retrieval::{
    pack, score_candidate, PackedContext, PackedItem, RetrievalQuery, Retriever, ScoredCandidate,
};
pub use tokens::{estimate, Budget};

/// Re-exported so callers do not need a direct `loom-core` dependency just to build a query.
pub use loom_core::{
    hnsw_insert, hnsw_search, Embedding, Hnsw, HnswMeta, IndexEntry, ItemId, NodeStore,
    PersistedNode, StoreError, EF_DEFAULT, M,
};
