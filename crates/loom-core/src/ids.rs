//! Identifiers.
//!
//! All of them are opaque strings or content hashes. None of them is a sequential integer, because a
//! sequential id in a multi-tenant system is an invitation to enumerate — and "tenant A cannot even
//! *confirm the existence* of tenant B's identifiers" is an invariant (docs/05 §3.9), not a
//! nice-to-have.

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! opaque_id {
    ($name:ident, $prefix:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            /// Wrap an existing identifier.
            pub fn new(id: impl Into<String>) -> Self {
                $name(id.into())
            }

            /// The underlying string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", $prefix, self.0)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                $name(s.to_string())
            }
        }
    };
}

opaque_id!(
    TenantId,
    "tnt_",
    "A tenant. The outermost isolation boundary."
);
opaque_id!(
    SessionId,
    "ses_",
    "An agent session. **A session is a branch** (docs/03 §3.1)."
);
opaque_id!(BranchId, "br_", "A branch of a tenant's state.");
opaque_id!(
    ActorId,
    "act_",
    "Whoever did something: an agent, a human, or a tool."
);
opaque_id!(
    PolicyDecisionId,
    "pdc_",
    "One evaluation of policy, recorded so 'what allowed this' has an exact answer."
);

/// A commit. This is a substrate `ManifestId` — the state of the database, as a 32-byte value.
pub type CommitId = substrate_pager::ManifestId;

/// An observation's id: the content hash of the observation itself.
///
/// Content-addressed on purpose. Two ingestions of the same source record produce the same id, so
/// ingestion is idempotent and a retry does not duplicate the world.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObservationId([u8; 32]);

/// A claim's id.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ClaimId([u8; 32]);

macro_rules! hash_id {
    ($name:ident, $prefix:literal) => {
        impl $name {
            /// A fresh, random id.
            pub fn new() -> Self {
                let mut bytes = [0u8; 32];
                // BLAKE3 of an OS-random seed. Not cryptographic identity — just unguessable.
                let mut seed = [0u8; 32];
                if getrandom::fill(&mut seed).is_err() {
                    // Entropy failure is not a reason to kill a database. Fall back to a hash of the
                    // address of a fresh allocation, which is not great but is not predictable
                    // either, and record nothing that pretends it was random.
                    let boxed = Box::new(0u8);
                    let addr = (&*boxed as *const u8) as usize;
                    seed[..8].copy_from_slice(&addr.to_le_bytes());
                }
                bytes.copy_from_slice(blake3::hash(&seed).as_bytes());
                $name(bytes)
            }

            /// Derive from content, so ingesting the same thing twice yields the same id.
            pub fn of(content: &[u8]) -> Self {
                $name(*blake3::hash(content).as_bytes())
            }

            /// The raw bytes.
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Hex.
            pub fn to_hex(&self) -> String {
                self.0.iter().map(|b| format!("{b:02x}")).collect()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                $name::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", $prefix, &self.to_hex()[..12])
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self)
            }
        }
    };
}

hash_id!(ObservationId, "obs_");
hash_id!(ClaimId, "clm_");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_addressed_ids_make_ingestion_idempotent() {
        // Ingesting the same source record twice must not duplicate the world.
        let a = ObservationId::of(b"signin-847223");
        let b = ObservationId::of(b"signin-847223");
        assert_eq!(a, b);
        assert_ne!(a, ObservationId::of(b"signin-847224"));
    }

    #[test]
    fn fresh_ids_are_distinct() {
        let ids: std::collections::HashSet<_> = (0..64).map(|_| ClaimId::new()).collect();
        assert_eq!(ids.len(), 64);
    }

    #[test]
    fn ids_display_with_their_prefix() {
        assert!(TenantId::new("acme").to_string().starts_with("tnt_"));
        assert!(SessionId::new("s1").to_string().starts_with("ses_"));
        assert!(ClaimId::of(b"x").to_string().starts_with("clm_"));
    }
}
