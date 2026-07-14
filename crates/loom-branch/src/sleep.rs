//! Sleeping and waking a whole tenant.
//!
//! substrate's `sleep()` puts **one** database to sleep and hands back a pointer to one manifest.
//! LoomDB has **many heads** — every branch is one — so putting a tenant to sleep means making every
//! branch durable, not just the one somebody happened to be looking at.
//!
//! # The token carries the refs
//!
//! ```text
//! LoomWakeToken { pool, page_size, refs }
//! ```
//!
//! The `refs` are the whole map: branch → head, tags, and the **commit DAG with its merge edges**. A
//! wake token that carried only a manifest id would restore the data and lose the branch names — and
//! *"where is branch h2"* is precisely the question that has to have an answer after a restart.
//!
//! It is also why the DAG travels: substrate's manifests have one parent, LoomDB records the second
//! itself, and a token that dropped it would silently restore the double-counting merge bug (merge
//! twice, and a `+3` becomes a `+6`, and the merge reports success).

use crate::refs::Refs;
use loom_core::{LoomError, Result, TenantId};
use serde::{Deserialize, Serialize};

/// Everything needed to bring a sleeping tenant back.
///
/// A million sleeping sessions is a million branch entries in one of these — bytes in a registry, no
/// compute (substrate docs/02 §9.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoomWakeToken {
    /// The tenant. Also the substrate *pool*, so two tenants never share a page.
    pub tenant: TenantId,
    /// The page size the store was created with.
    pub page_size: usize,
    /// Branch heads, tags, and the commit DAG — including every merge's second parent.
    pub refs: Refs,
}

impl LoomWakeToken {
    /// Serialize, for a registry to hold.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| LoomError::CorruptNode {
            page: 0,
            detail: format!("cannot encode wake token: {e}"),
        })
    }

    /// Parse.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| LoomError::CorruptNode {
            page: 0,
            detail: format!("cannot decode wake token: {e}"),
        })
    }

    /// Where each branch points. The answer to *"where is branch h2"*.
    pub fn branches(&self) -> impl Iterator<Item = (&str, loom_core::CommitId)> {
        self.refs.branches.iter().map(|(n, c)| (n.as_str(), *c))
    }
}
