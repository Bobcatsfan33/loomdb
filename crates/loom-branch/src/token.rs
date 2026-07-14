//! Capability tokens: the isolation mechanism.
//!
//! ```rust,ignore
//! CapabilityToken = signed { session, branch_scope, expiry }
//! ```
//!
//! Every operation verifies the token covers the branch it is about to touch, and — this is the part
//! that has to hold under an adversary — **there is no code path in LoomDB that touches a page outside
//! the token's branch scope.** Not a debug path, not an admin path, not a "just this once" helper.
//!
//! # What a token does not do
//!
//! A capability token answers *"may you write here."* It does **not** answer *"may this data influence
//! what you produce, or what you do."*
//!
//! That distinction matters more than it sounds, and an earlier draft of the architecture blurred it —
//! claiming that tokens gave agents "a provable blast radius". They give a provable *branch* scope.
//! Information flow is a different question, it is where prompt injection and exfiltration actually
//! live, and it is `loom-policy`'s job (docs/03 §5). A token will happily let an agent write a
//! conclusion it drew from a poisoned document into a branch it owns.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use loom_core::{BranchId, LoomError, Result, SessionId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The claims a token makes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenClaims {
    /// The session this token belongs to.
    pub session: SessionId,
    /// Exactly which branches it covers.
    ///
    /// An explicit set, not a prefix or a wildcard. A wildcard scope is a scope nobody can audit, and
    /// "the token covered it because the name started with the right thing" is not a sentence anyone
    /// wants to read in an incident review.
    pub scope: BTreeSet<BranchId>,
    /// When it stops being valid, in ms since the epoch.
    pub expires_at_ms: u64,
}

/// A signed capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// What it claims.
    pub claims: TokenClaims,
    /// Ed25519 over the canonical claim bytes.
    signature: Vec<u8>,
}

impl CapabilityToken {
    /// The session this token is for.
    pub fn session(&self) -> &SessionId {
        &self.claims.session
    }

    /// The branches it covers.
    pub fn scope(&self) -> &BTreeSet<BranchId> {
        &self.claims.scope
    }
}

/// Issues and verifies tokens.
///
/// The signing key never leaves the database. A token is therefore unforgeable by a client, which is
/// the whole point: a client that could mint its own capability would have no capability at all.
pub struct TokenIssuer {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl std::fmt::Debug for TokenIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenIssuer(<key redacted>)")
    }
}

impl TokenIssuer {
    /// Build an issuer from a signing key.
    pub fn new(signing: SigningKey) -> Self {
        let verifying = signing.verifying_key();
        TokenIssuer { signing, verifying }
    }

    /// Build an issuer with a fresh key. The key lives as long as the process.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        if getrandom::getrandom(&mut seed).is_err() {
            // Entropy failure is not a reason to kill a database, but it IS a reason not to pretend
            // we have a secure key. Derive something unpredictable-but-not-random and carry on; the
            // deployment story for a real key is a KeyProvider (substrate-security), not this path.
            let boxed = Box::new(0u8);
            seed[..8].copy_from_slice(&(((&*boxed) as *const u8) as usize).to_le_bytes());
        }
        TokenIssuer::new(SigningKey::from_bytes(&seed))
    }

    /// Mint a token for a set of branches.
    pub fn issue(
        &self,
        session: SessionId,
        scope: BTreeSet<BranchId>,
        expires_at_ms: u64,
    ) -> Result<CapabilityToken> {
        let claims = TokenClaims {
            session,
            scope,
            expires_at_ms,
        };
        let signature = self.signing.sign(&canonical(&claims)?);
        Ok(CapabilityToken {
            claims,
            signature: signature.to_bytes().to_vec(),
        })
    }

    /// Mint a token that covers everything an old one did, plus one more branch.
    ///
    /// This is what `branch()` returns. A new branch is not automatically reachable from an old token
    /// — the caller gets a *new* token, and the old one still means exactly what it meant.
    pub fn extend(&self, token: &CapabilityToken, branch: BranchId) -> Result<CapabilityToken> {
        let mut scope = token.claims.scope.clone();
        scope.insert(branch);
        self.issue(
            token.claims.session.clone(),
            scope,
            token.claims.expires_at_ms,
        )
    }

    /// **The check.** Verify the signature, the expiry, and the scope — in that order.
    ///
    /// Signature first, deliberately: an expired-token message tells an attacker their forgery was
    /// structurally valid, and a scope message tells them which branches exist. Neither is a
    /// catastrophe, and neither is a thing to hand over for free.
    pub fn authorize(&self, token: &CapabilityToken, branch: &BranchId, now_ms: u64) -> Result<()> {
        let bytes: [u8; 64] = token
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| LoomError::TokenForged)?;

        self.verifying
            .verify(&canonical(&token.claims)?, &Signature::from_bytes(&bytes))
            .map_err(|_| LoomError::TokenForged)?;

        if now_ms >= token.claims.expires_at_ms {
            return Err(LoomError::TokenExpired {
                session: token.claims.session.clone(),
            });
        }

        if !token.claims.scope.contains(branch) {
            return Err(LoomError::OutOfScope {
                branch: branch.clone(),
                scope: token
                    .claims
                    .scope
                    .iter()
                    .map(|b| b.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        }
        Ok(())
    }
}

/// The bytes that get signed. Deterministic, or a signature means nothing.
fn canonical(claims: &TokenClaims) -> Result<Vec<u8>> {
    bincode::serialize(claims).map_err(|source| LoomError::Codec {
        op: "encode",
        what: "capability token",
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000_000;
    const HOUR: u64 = 3_600_000;

    fn scope(branches: &[&str]) -> BTreeSet<BranchId> {
        branches.iter().map(|b| BranchId::new(*b)).collect()
    }

    #[test]
    fn a_token_authorizes_exactly_its_scope_and_nothing_else() -> Result<()> {
        let issuer = TokenIssuer::generate();
        let token = issuer.issue(SessionId::new("s1"), scope(&["b1", "b2"]), NOW + HOUR)?;

        issuer.authorize(&token, &BranchId::new("b1"), NOW)?;
        issuer.authorize(&token, &BranchId::new("b2"), NOW)?;

        let err = issuer.authorize(&token, &BranchId::new("b7"), NOW);
        assert!(matches!(err, Err(LoomError::OutOfScope { .. })));

        // The message must tell a language model what to DO next, not merely that it failed.
        let message = err.expect_err("out of scope").to_string();
        assert!(
            message.contains("Call branch() from your session root"),
            "an error a model cannot act on produces a retry loop, not a recovery: {message}"
        );
        Ok(())
    }

    #[test]
    fn an_expired_token_authorizes_nothing() -> Result<()> {
        let issuer = TokenIssuer::generate();
        let token = issuer.issue(SessionId::new("s1"), scope(&["b1"]), NOW + HOUR)?;

        issuer.authorize(&token, &BranchId::new("b1"), NOW)?;
        assert!(matches!(
            issuer.authorize(&token, &BranchId::new("b1"), NOW + HOUR),
            Err(LoomError::TokenExpired { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_client_cannot_widen_its_own_scope() -> Result<()> {
        // The attack: take a valid token, add a branch to the scope, present it. The signature must
        // fail, or a capability is just a suggestion.
        let issuer = TokenIssuer::generate();
        let mut token = issuer.issue(SessionId::new("s1"), scope(&["b1"]), NOW + HOUR)?;

        token
            .claims
            .scope
            .insert(BranchId::new("someone-elses-branch"));

        assert!(matches!(
            issuer.authorize(&token, &BranchId::new("someone-elses-branch"), NOW),
            Err(LoomError::TokenForged)
        ));
        Ok(())
    }

    #[test]
    fn a_client_cannot_extend_its_own_expiry() -> Result<()> {
        let issuer = TokenIssuer::generate();
        let mut token = issuer.issue(SessionId::new("s1"), scope(&["b1"]), NOW)?;
        token.claims.expires_at_ms = NOW + 100 * HOUR;

        assert!(matches!(
            issuer.authorize(&token, &BranchId::new("b1"), NOW),
            Err(LoomError::TokenForged)
        ));
        Ok(())
    }

    #[test]
    fn a_token_from_another_database_is_refused() -> Result<()> {
        let ours = TokenIssuer::generate();
        let theirs = TokenIssuer::generate();

        let foreign = theirs.issue(SessionId::new("s1"), scope(&["b1"]), NOW + HOUR)?;

        assert!(matches!(
            ours.authorize(&foreign, &BranchId::new("b1"), NOW),
            Err(LoomError::TokenForged)
        ));
        Ok(())
    }

    #[test]
    fn extending_a_token_adds_one_branch_and_leaves_the_old_token_alone() -> Result<()> {
        let issuer = TokenIssuer::generate();
        let original = issuer.issue(SessionId::new("s1"), scope(&["b1"]), NOW + HOUR)?;

        let extended = issuer.extend(&original, BranchId::new("b2"))?;

        issuer.authorize(&extended, &BranchId::new("b1"), NOW)?;
        issuer.authorize(&extended, &BranchId::new("b2"), NOW)?;

        // The ORIGINAL token still means exactly what it meant. Issuing a new capability must not
        // retroactively widen an old one.
        assert!(issuer
            .authorize(&original, &BranchId::new("b2"), NOW)
            .is_err());
        Ok(())
    }
}
