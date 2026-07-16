//! **The multi-tenant surface — one front door, structurally isolated tenants (AT-039).**
//!
//! Until now LoomDB was one engine per tenant, and cross-tenant isolation was proven by there being two
//! separate engines with no shared surface. This is the real front door: **one router over many
//! tenants' engines**, which is exactly where cross-tenant isolation could leak if it were a runtime
//! `WHERE tenant = ?` someone forgets. It is not.
//!
//! # Isolation is structural, the same move as AT-027 and AT-040
//!
//! A capability token carries its tenant **inside the signature** ([`TokenClaims::tenant`]). The router
//! reads that tenant, routes to that tenant's engine, and the engine verifies the token against **its
//! own key**. So:
//!
//! - A token minted by tenant A lands in A's engine and reaches only A's pool. A key that exists in
//!   tenant B is, from A, simply **not found** — the same answer as a key that never existed anywhere.
//!   There is no code path on which A's request touches B's pool.
//! - A token whose `tenant` field was flipped to B (to try to route into B) fails B's signature check,
//!   because A's engine signed the original `tenant = A`. It returns [`LoomError::Unauthorized`].
//! - A token naming an **unregistered** tenant also returns [`LoomError::Unauthorized`] — the *same*
//!   error. So a caller cannot tell "tenant B does not exist" from "tenant B exists but rejected my
//!   token". There is no existence oracle (AT-039). There is only "no".
//!
//! The router never exposes "does tenant X exist" or "list tenants" to a tenant; the registry is an
//! operator surface.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use loom_core::{BranchId, LoomError, Record, Result, TenantId};

use crate::session::Loom;
use crate::token::CapabilityToken;

/// A router over many tenants' engines. One process, many isolated pools.
#[derive(Default)]
pub struct Tenancy {
    engines: RwLock<BTreeMap<TenantId, Arc<Loom>>>,
}

impl Tenancy {
    /// An empty tenancy.
    pub fn new() -> Self {
        Tenancy {
            engines: RwLock::new(BTreeMap::new()),
        }
    }

    /// **Register a tenant's engine.** An operator surface — a tenant cannot call this for itself, and
    /// it is how a new pool comes to exist. Returns the engine so the operator can hand the tenant its
    /// first session.
    pub fn register(&self, tenant: TenantId, engine: Arc<Loom>) -> Arc<Loom> {
        self.engines
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(tenant, engine.clone());
        engine
    }

    /// The number of registered tenants. Operator-only (there is no tenant-facing count).
    pub fn tenant_count(&self) -> usize {
        self.engines.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// **Resolve a token to its tenant's engine — or a uniform refusal.**
    ///
    /// Routes by the token's *signed* tenant. Returns [`LoomError::Unauthorized`] if that tenant is not
    /// registered, so an unregistered-tenant request is indistinguishable from a rejected one. The
    /// engine's own `authorize`/`verify` does the signature and scope check on the actual operation —
    /// this only picks the engine, and picks the *right* one because the tenant is inside the signature.
    fn engine_for(&self, token: &CapabilityToken) -> Result<Arc<Loom>> {
        let tenant = &token.claims.tenant;
        self.engines
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(tenant)
            .cloned()
            .ok_or(LoomError::Unauthorized)
    }

    /// **Read a record, through the router.** The whole cross-tenant story in one method: the token
    /// selects the tenant, the engine reads only that tenant's pool, and a key in another tenant comes
    /// back `Ok(None)` — the same as a key that never existed.
    pub fn read(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        key: &[u8],
    ) -> Result<Option<Record>> {
        let engine = self.engine_for(token)?;
        // The engine verifies the token against ITS key. A token whose tenant field was tampered to
        // route here will fail this, returning the engine's forge/scope error — which we normalise to
        // the same uniform `Unauthorized`, so no error distinguishes "tampered" from "no such tenant".
        match engine.read(token, branch, key) {
            Ok(v) => Ok(v),
            Err(LoomError::TokenForged) => Err(LoomError::Unauthorized),
            Err(other) => Err(other),
        }
    }
}
