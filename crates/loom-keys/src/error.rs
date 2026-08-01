//! Every way custody can refuse, named.
//!
//! A verifier that fails with "signature invalid" for all four of *unknown key*, *revoked key*,
//! *wrong role*, and *actually forged* gives an operator nothing to act on, and gives an auditor no
//! way to tell a rotation mistake from an attack. Each refusal below says which one it was.

use crate::{Algorithm, Backend, KeyRole, KeyStatus};

/// This crate's result type.
pub type Result<T> = std::result::Result<T, KeyError>;

/// A custody refusal.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The register could not be read.
    #[error("cannot read the trust-root register at {path}: {detail}")]
    Io {
        /// The register path.
        path: String,
        /// What the filesystem said.
        detail: String,
    },

    /// The register is not a file this crate will trust.
    ///
    /// Same fail-closed shape as the policy file and the actor registry: a regular file, size
    /// bounded, never a symlink that could be repointed between restarts, never group- or
    /// world-writable — anything that can rewrite the register can appoint its own trust roots.
    #[error("the trust-root register at {path} is not usable: {detail}")]
    RegisterUnusable {
        /// The register path.
        path: String,
        /// Which rule it broke.
        detail: String,
    },

    /// The register parsed but does not describe a usable custody state.
    #[error("the trust-root register is invalid: {detail}")]
    RegisterInvalid {
        /// What is wrong with it.
        detail: String,
    },

    /// No entry in this role carries that key id.
    #[error(
        "no trust root named {key_id:?} is registered for the {role} role. A key that is not in \
         the register authorizes nothing, however well its signature verifies."
    )]
    UnknownKeyId {
        /// The key id that was asked for.
        key_id: String,
        /// The role it was asked for.
        role: KeyRole,
    },

    /// The key exists, but speaks for a different authority.
    #[error(
        "trust root {key_id:?} is registered for the {found} role, not {expected}. Roles are \
         separate authorities: a release key cannot appoint writers, and a backup key cannot bless \
         a software update."
    )]
    RoleMismatch {
        /// The key id.
        key_id: String,
        /// The role the caller needed.
        expected: KeyRole,
        /// The role the key actually holds.
        found: KeyRole,
    },

    /// The key was revoked. Its material still verifies; the register says do not accept it.
    #[error(
        "trust root {key_id:?} was REVOKED at generation {generation}: {reason}. The signature may \
         still be cryptographically valid — revocation is a decision, and this is it."
    )]
    KeyRevoked {
        /// The key id.
        key_id: String,
        /// The generation at which it was revoked.
        generation: u64,
        /// Why it was revoked, from the register.
        reason: String,
    },

    /// The key is staged but not yet trusted.
    #[error(
        "trust root {key_id:?} is {status} and authorizes nothing yet. Distributing a key and \
         trusting it are separate acts; run the activate step once every verifier holds it."
    )]
    KeyNotTrusted {
        /// The key id.
        key_id: String,
        /// The status it is actually in.
        status: KeyStatus,
    },

    /// The key is registered under a different algorithm than the artifact claims.
    #[error(
        "trust root {key_id:?} is registered for {expected}, but the artifact claims {found}. An \
         algorithm the key was not registered for is not a key you have checked."
    )]
    AlgorithmMismatch {
        /// The key id.
        key_id: String,
        /// The algorithm the register binds.
        expected: Algorithm,
        /// The algorithm the artifact declared.
        found: String,
    },

    /// The signature does not verify against that key.
    #[error("the signature does not verify against trust root {key_id:?} ({detail})")]
    SignatureInvalid {
        /// The key id it was checked against.
        key_id: String,
        /// What the verifier said.
        detail: String,
    },

    /// Nothing in the role could have produced this signature.
    #[error(
        "no trusted {role} trust root verifies this signature. {tried} key(s) were tried; revoked \
         and staged keys are never tried, so a signature from one of those lands here."
    )]
    NoTrustedKey {
        /// The role searched.
        role: KeyRole,
        /// How many keys were eligible to try.
        tried: usize,
    },

    /// The role has no key that may sign.
    #[error(
        "the {role} role has no active trust root, so nothing may sign for it. Rotation leaves \
         exactly one active key; a role with none is a role that has been sealed."
    )]
    NoActiveSigner {
        /// The role.
        role: KeyRole,
    },

    /// A transition that changes what verifies needs more than one person.
    #[error(
        "trust root {key_id:?} cannot become {status} with {approvals} approval(s): a transition \
         that changes what verifies requires {required} distinct approvers, recorded against a \
         ceremony reference."
    )]
    DualControlRequired {
        /// The key id.
        key_id: String,
        /// The status it was being moved to.
        status: KeyStatus,
        /// How many approvals were recorded.
        approvals: usize,
        /// How many are required.
        required: usize,
    },

    /// The rotation step does not apply from the key's current status.
    #[error("trust root {key_id:?} cannot go from {from} to {to}: {detail}")]
    InvalidTransition {
        /// The key id.
        key_id: String,
        /// Its current status.
        from: KeyStatus,
        /// The status requested.
        to: KeyStatus,
        /// Why the sequence forbids it.
        detail: String,
    },

    /// The signing key material is unusable.
    #[error("the signing key for {key_id:?} is unusable: {detail}")]
    SigningKeyUnusable {
        /// The key id.
        key_id: String,
        /// What is wrong.
        detail: String,
    },

    /// The register asks for a backend this build cannot drive.
    #[error(
        "trust root {key_id:?} declares the {backend} backend, which this binary cannot drive. It \
         is NOT signed in software as a fallback: a receipt claiming hardware custody must come \
         from hardware."
    )]
    BackendUnavailable {
        /// The key id.
        key_id: String,
        /// The backend the register declared.
        backend: Backend,
    },
}
