//! The write envelope. **No write exists without one.**
//!
//! # Why this type lives here, in L1, and not in L2 where the provenance engine is built
//!
//! Because a mandatory parameter introduced later is a parameter that stays optional forever.
//!
//! `docs/03` §3.4 says the write path *rejects* any write without a valid envelope, and that this is
//! enforced at `loom-branch`'s write entry point — not as middleware, not as a decorator someone can
//! forget. If we shipped L1 with an optional envelope and promised to tighten it in L2, there would
//! be a period in which writes without provenance were legal, code would be written against that, and
//! the tightening would break it. So the envelope is required from the first write the database ever
//! accepts, and L2 fills in the derivation DAG behind it.
//!
//! A bypassable audit trail is worse than no audit trail, because it is **believed**.

use crate::error::{LoomError, Result};
use crate::ids::{ActorId, BranchId, PolicyDecisionId, SessionId};
use crate::value::SourceRef;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Everything we record about *why* a write happened.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteEnvelope {
    /// Who wrote it: an agent, a human, or a tool.
    pub actor: ActorId,
    /// The session it happened in.
    pub session: SessionId,
    /// The branch it landed on.
    pub branch: BranchId,
    /// A hash of the context that produced it.
    pub context_hash: [u8; 32],
    /// The chain of authority. `A → B → C`, not just the last hop.
    ///
    /// Agents delegate. "Who authorized this" has to mean the whole chain, or a compromised
    /// sub-agent's writes look like they came from nowhere.
    pub delegation: Vec<ActorId>,
    /// What it was derived from.
    ///
    /// **Engine-captured, not caller-supplied.** During a session transaction the engine records what
    /// was actually read and attaches it here. Callers may *add* external source URIs; they cannot
    /// *omit* what they read. An agent — or an attacker steering one — must not be able to launder a
    /// derivation by declining to mention it. (The engine-capture half lands with the read-set
    /// tracking in L2; the field is here from the start so nothing has to be retrofitted.)
    pub derived_from: Vec<SourceRef>,
    /// Why, in the agent's own words.
    pub intent: String,
    /// Which policy decision permitted this write.
    pub policy: Option<PolicyDecisionId>,
    /// Ed25519 now; an ML-DSA slot is reserved so adding a post-quantum signature is not a format
    /// break. Empty until L2 signs it.
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl WriteEnvelope {
    /// The minimum an envelope can be and still be one.
    ///
    /// Note what is *not* optional: the actor, the session, the branch, and the intent. A write whose
    /// author or purpose is unknown is a write nobody can audit, and this database exists to be
    /// auditable.
    pub fn new(
        actor: ActorId,
        session: SessionId,
        branch: BranchId,
        intent: impl Into<String>,
    ) -> Self {
        WriteEnvelope {
            actor,
            session,
            branch,
            context_hash: [0u8; 32],
            delegation: Vec::new(),
            derived_from: Vec::new(),
            intent: intent.into(),
            policy: None,
            signature: Vec::new(),
        }
    }

    /// Record what this write was derived from.
    pub fn derived_from(mut self, sources: impl IntoIterator<Item = SourceRef>) -> Self {
        self.derived_from.extend(sources);
        self
    }

    /// Record the chain of authority.
    pub fn delegated_through(mut self, chain: impl IntoIterator<Item = ActorId>) -> Self {
        self.delegation.extend(chain);
        self
    }

    /// Hash of the context that produced this write.
    pub fn with_context(mut self, context: &[u8]) -> Self {
        self.context_hash = *blake3::hash(context).as_bytes();
        self
    }

    /// **The bytes a signature covers.**
    ///
    /// # Why this is a separate, canonical encoding and not just `bincode(self)`
    ///
    /// A signature is a promise about *what was said*. If the bytes that get signed can vary while the
    /// meaning stays the same — field order, a serde flag, a version bump — then a signature that
    /// verified yesterday fails today, and the natural fix is to stop checking it. So the signed bytes
    /// are pinned here, explicitly, length-prefixed so that no two different envelopes can produce the
    /// same input (`actor="ab", intent="c"` must not collide with `actor="a", intent="bc"`).
    ///
    /// **The signature must not cover itself**, so `signature` is excluded. Everything else that
    /// changes the *meaning* of the write is in: who, where, why, the chain of authority, and what it
    /// claims to be derived from. Leaving `intent` out would let an attacker keep a valid signature
    /// while rewriting the stated purpose of the write, which is precisely the field an auditor reads.
    pub fn signing_bytes(&self) -> Vec<u8> {
        fn field(out: &mut Vec<u8>, bytes: &[u8]) {
            out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            out.extend_from_slice(bytes);
        }

        let mut out = Vec::new();

        field(&mut out, b"loom-envelope-v1");
        field(&mut out, self.actor.as_str().as_bytes());
        field(&mut out, self.session.as_str().as_bytes());
        field(&mut out, self.branch.as_str().as_bytes());
        field(&mut out, &self.context_hash);
        field(&mut out, self.intent.as_bytes());

        out.extend_from_slice(&(self.delegation.len() as u64).to_le_bytes());
        for actor in &self.delegation {
            field(&mut out, actor.as_str().as_bytes());
        }

        out.extend_from_slice(&(self.derived_from.len() as u64).to_le_bytes());
        for source in &self.derived_from {
            field(&mut out, source.to_string().as_bytes());
        }

        out
    }

    /// Sign this envelope.
    pub fn signed_by(mut self, key: &SigningKey) -> Self {
        let sig: Signature = key.sign(&self.signing_bytes());
        self.signature = sig.to_bytes().to_vec();
        self
    }

    /// **Verify that this envelope was signed by the key the actor is registered with.**
    ///
    /// The lookup is by the actor the envelope *claims to be*. That is the point: sign as `agent-a`,
    /// claim to be `agent-b`, and verification is performed against `agent-b`'s key — which will not
    /// verify. An actor cannot be impersonated by anyone who does not hold its key.
    pub fn verify(&self, key: &VerifyingKey) -> Result<()> {
        if self.signature.is_empty() {
            return Err(LoomError::EnvelopeUnsigned {
                actor: self.actor.as_str().to_string(),
            });
        }

        let bytes: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| {
            LoomError::EnvelopeSignatureInvalid {
                actor: self.actor.as_str().to_string(),
                detail: format!(
                    "an ed25519 signature is 64 bytes; this one is {}",
                    self.signature.len()
                ),
            }
        })?;

        key.verify_strict(&self.signing_bytes(), &Signature::from_bytes(&bytes))
            .map_err(|e| LoomError::EnvelopeSignatureInvalid {
                actor: self.actor.as_str().to_string(),
                detail: e.to_string(),
            })
    }

    /// Whether this envelope is structurally complete.
    ///
    /// Deliberately shallow: it checks that the fields that make a write *attributable* are present.
    /// It does not check the signature — that is `verify`, and it is a different question. A
    /// structurally complete envelope tells you what the write *claims*; only a signature tells you
    /// the claim is true.
    pub fn is_valid(&self) -> bool {
        !self.actor.as_str().is_empty()
            && !self.session.as_str().is_empty()
            && !self.branch.as_str().is_empty()
            && !self.intent.trim().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> WriteEnvelope {
        WriteEnvelope::new(
            ActorId::new("agent-1"),
            SessionId::new("s1"),
            BranchId::new("b1"),
            "investigating the risk score increase",
        )
    }

    #[test]
    fn a_complete_envelope_is_valid() {
        assert!(envelope().is_valid());
    }

    #[test]
    fn an_envelope_with_no_intent_is_not_an_envelope() {
        // "Why did the agent write this" is not an optional question.
        let mut e = envelope();
        e.intent = "   ".into();
        assert!(!e.is_valid());
    }

    #[test]
    fn an_envelope_with_no_actor_is_not_an_envelope() {
        let mut e = envelope();
        e.actor = ActorId::new("");
        assert!(!e.is_valid());
    }

    #[test]
    fn the_delegation_chain_is_the_whole_chain() {
        // A → B → C. Recording only "C wrote it" makes a compromised sub-agent's writes look like
        // they came from nowhere.
        let e = envelope().delegated_through([
            ActorId::new("human-analyst"),
            ActorId::new("agent-supervisor"),
            ActorId::new("agent-worker"),
        ]);
        assert_eq!(e.delegation.len(), 3);
        assert_eq!(e.delegation[0], ActorId::new("human-analyst"));
    }

    #[test]
    fn context_hashing_is_deterministic() {
        assert_eq!(
            envelope().with_context(b"the prompt").context_hash,
            envelope().with_context(b"the prompt").context_hash
        );
        assert_ne!(
            envelope().with_context(b"the prompt").context_hash,
            envelope().with_context(b"a different prompt").context_hash
        );
    }
}
