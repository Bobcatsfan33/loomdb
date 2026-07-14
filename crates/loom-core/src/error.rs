//! Errors.
//!
//! Every message here is read by **a language model deciding what to do next**, not only by a human
//! reading a stack trace. So each one states the *corrective action* (docs/03 §7). `ERR_SCOPE_VIOLATION`
//! makes a model retry the same thing; "call branch() from your session root first" makes it recover.

use crate::ids::{BranchId, ClaimId, SessionId};

/// The result type.
pub type Result<T> = std::result::Result<T, LoomError>;

/// Everything that can go wrong.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoomError {
    /// The envelope carries no signature, and this database requires one.
    #[error(
        "the write envelope for actor {actor} is not signed, and this database has an actor \
         registry, which means every write must be signed. Sign the envelope with that actor's \
         key before writing: WriteEnvelope::new(..).signed_by(&signing_key)."
    )]
    EnvelopeUnsigned {
        /// The actor the envelope claims.
        actor: String,
    },

    /// The signature does not verify against the key the claimed actor is registered with.
    #[error(
        "the write envelope claims to be from actor {actor}, but its signature does not verify \
         against that actor's registered key ({detail}). Either the envelope was altered after it \
         was signed, or it was signed by a different key than the one {actor} is registered with. \
         Do not retry this write: re-sign it with the correct key, or register the key you actually \
         hold under the actor you actually are."
    )]
    EnvelopeSignatureInvalid {
        /// The actor the envelope claims.
        actor: String,
        /// What the verifier said.
        detail: String,
    },

    /// The envelope claims an actor this database has never heard of.
    #[error(
        "no verifying key is registered for actor {actor}, so this write cannot be authenticated. \
         Register the actor's public key with Loom::with_actor_keys before it writes. An \
         unregistered actor is refused rather than trusted."
    )]
    UnknownActor {
        /// The actor the envelope claims.
        actor: String,
    },

    /// The capability token does not cover the branch being touched.
    #[error(
        "branch {branch} is not covered by your capability token (which covers {scope}). \
         Call branch() from your session root to get a token that includes it."
    )]
    OutOfScope {
        /// The branch that was reached for.
        branch: BranchId,
        /// What the token actually covers.
        scope: String,
    },

    /// The token has expired.
    #[error("your capability token for session {session} expired. Open a new session.")]
    TokenExpired {
        /// The session.
        session: SessionId,
    },

    /// The token's signature does not verify.
    #[error("capability token signature is invalid — it was not issued by this database")]
    TokenForged,

    /// A write arrived without an envelope.
    #[error(
        "this write has no WriteEnvelope. Every write must record who made it, what it was derived \
         from, and why. Attach an envelope and retry."
    )]
    MissingEnvelope,

    /// A claim was cited to justify an action, and cannot.
    #[error("{0}")]
    ClaimCannotAct(String),

    /// A claim does not exist.
    #[error("no such claim: {0}")]
    NoSuchClaim(ClaimId),

    /// The record at a key is not the type the caller expected.
    #[error("the record at this key is a {actual}, not a {expected}")]
    WrongRecordType {
        /// What was expected.
        expected: &'static str,
        /// What is there.
        actual: &'static str,
    },

    /// A branch name is already taken.
    #[error(
        "branch {name:?} already exists. Moving it would discard whatever it points at; \
         pick another name, or rewind the existing branch on purpose."
    )]
    BranchExists {
        /// The name.
        name: String,
    },

    /// A derivation walk ran past its depth bound.
    ///
    /// A derivation chain in a real agent is shallow — an observation, a claim, a conclusion. A chain
    /// this long is a cycle or a bug, and chasing it is a denial of service against ourselves (AT-025).
    #[error(
        "the derivation graph is not acyclic: a walk exceeded {depth} hops. \
         Some write claims to be derived from something downstream of itself. \
         Inspect the derivation DAG with `loom audit` before trusting any taint result."
    )]
    DerivationCycle {
        /// The bound that was exceeded.
        depth: usize,
    },

    /// A page's bytes are not a valid node.
    #[error("corrupt node at logical page {page}: {detail}")]
    CorruptNode {
        /// Which page.
        page: u64,
        /// What is wrong with it.
        detail: String,
    },

    /// Serialization failed.
    #[error("failed to {op} {what}: {source}")]
    Codec {
        /// `"encode"` or `"decode"`.
        op: &'static str,
        /// What we were handling.
        what: &'static str,
        /// Why.
        #[source]
        source: Box<bincode::ErrorKind>,
    },

    /// The storage engine refused.
    #[error(transparent)]
    Pager(#[from] substrate_pager::PagerError),
}
