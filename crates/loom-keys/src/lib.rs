//! **Trust-root custody for every loomDB signing role.**
//!
//! loomDB signs three different things with three different authorities, and until P8 each one
//! verified against "whatever public key you hand me":
//!
//! | Role | Signs | Verified by |
//! |---|---|---|
//! | [`KeyRole::ActorGovernance`] | the actor-registry attestation | `loomd`, at startup |
//! | [`KeyRole::Release`] | the offline update bundle manifest | the enclave, before applying |
//! | [`KeyRole::BackupRoot`] | the backup manifest | the independent verifier job |
//!
//! A check that accepts any valid key is not an authorization decision — it says *someone* signed
//! this, not *the party we trust for this role* signed it. This crate makes the key an identity: a
//! named entry, in a role, with an algorithm, a status, and a ceremony record behind it.
//!
//! # What this crate is, in one paragraph
//!
//! A [`TrustRootRegister`] is a file the deployment mounts read-only. It names trust roots per role
//! and records each one's status. A [`KeyDirectory`] answers the only question a verifier has —
//! *may this key authorize this role right now?* — offline, with no network and no KMS reachable.
//! A [`Signer`] produces a signature over **exact caller-supplied bytes**; it never encodes, never
//! re-encodes, and therefore cannot change any signed format.
//!
//! # Why the signer signs bytes and nothing else
//!
//! Every signed format in this workspace predates this crate and must survive it unchanged: the
//! bundle manifest's bincode, the backup manifest's exact bytes, the actor-attestation's
//! domain-separated payload. So the interface is deliberately anaemic. A backend that formats
//! anything is a backend that can change what a signature means, and swapping custody must never be
//! able to invalidate an artifact signed before the swap.
//!
//! # Rotation is a sequence, not a swap
//!
//! ```text
//!   expand  →  activate  →  (verify)  →  revoke
//!   Pending    Active         drill       Revoked
//!              (old → Retired)            (the old key)
//! ```
//!
//! [`KeyStatus::Pending`] is staged and trusted for nothing. [`KeyStatus::Retired`] still verifies
//! artifacts signed before the rotation but signs nothing new — that grace window is why a rotation
//! does not invalidate last week's backups. [`KeyStatus::Revoked`] is refused outright, and that is
//! the whole point: a revoked key's material still verifies mathematically, so refusing it has to be
//! a decision the directory makes, not a property of the cryptography.
//!
//! # What this crate does not do
//!
//! It does not run a ceremony, hold a private key in hardware, or make a software key into a
//! hardware one. [`Backend`] labels which kind of signer produced a signature so a receipt cannot
//! overstate its custody, and [`Backend::AwsKms`] is *declared and not implemented* — a register
//! entry claiming it is refused by [`SoftwareSigner`] rather than quietly signed in software.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(rust_2018_idioms)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[cfg(feature = "aws-kms")]
pub mod aws_kms;
mod directory;
mod error;
mod register;
mod rotation;
mod signer;

pub use directory::KeyDirectory;
pub use error::{KeyError, Result};
pub use register::{Approval, Ceremony, TrustRoot, TrustRootRegister, REGISTER_SCHEMA_VERSION};
pub use rotation::{activate, expand, retire, revoke};
pub use signer::{decode_receipt_signature, SignedReceipt, Signer, SoftwareSigner};

use serde::{Deserialize, Serialize};

/// Which authority a key speaks for.
///
/// Roles are separate keys, not one key used three ways: a compromise of the party that signs
/// releases must not also be able to appoint writers into a tenant's store, and the reverse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyRole {
    /// Signs the actor-registry attestation. `loomd` only ever *verifies* with it; the private half
    /// never touches an engine host.
    ActorGovernance,
    /// Signs offline update bundles — the product authenticity anchor for software and policy.
    Release,
    /// Signs backup manifests. Held by the backup writer; the verifier holds only its public half.
    BackupRoot,
}

impl KeyRole {
    /// The role's stable wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyRole::ActorGovernance => "actor-governance",
            KeyRole::Release => "release",
            KeyRole::BackupRoot => "backup-root",
        }
    }
}

impl std::fmt::Display for KeyRole {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The signature algorithm a trust root uses.
///
/// One variant today, and the enum exists anyway for two reasons. It binds the algorithm into the
/// verification path, so a key cannot be used under an algorithm it was not registered for. And it
/// makes adding one a deliberate, reviewable change rather than a string comparison someone relaxes
/// — which matters, because **every loomDB signing path is Ed25519 and AWS KMS's asymmetric key
/// specs are RSA and ECDSA only**. A KMS-backed ceremony therefore needs either an Ed25519-capable
/// backend (CloudHSM) or an algorithm migration that changes signed formats. See
/// `docs/key-custody.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Algorithm {
    /// Ed25519 — what every loomDB signed format uses today.
    Ed25519,
}

impl Algorithm {
    /// The algorithm's stable wire name, as it appears in signed records.
    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "ed25519",
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Where a key's private half lives.
///
/// This labels custody so a receipt cannot overstate it. A drill run against a software key proves
/// the *sequence* works; it does not prove anything about hardware custody, and an auditor reading
/// a receipt must be able to see which one produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    /// A key file on disk. Correct for drills and development; **not** a custody claim.
    Software,
    /// AWS KMS. Declared so a register can express the intended production custody, and
    /// deliberately not implemented here — see [`Algorithm`] for why it is not a drop-in.
    AwsKms,
}

impl Backend {
    /// The backend's stable wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Backend::Software => "software",
            Backend::AwsKms => "aws-kms",
        }
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Where a trust root sits in the rotation sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyStatus {
    /// Staged by `expand`, trusted for nothing yet. Distributing a key and trusting it are two
    /// separate acts, so that a key can reach every verifier before it starts authorizing anything.
    Pending,
    /// Signs new artifacts and verifies them.
    Active,
    /// Verifies artifacts signed before the rotation, signs nothing new. The grace window that
    /// stops a rotation from invalidating every backup taken last week.
    Retired,
    /// Refused. The material still verifies mathematically — refusing it is a decision this
    /// directory makes, which is exactly why revocation has to live somewhere explicit.
    Revoked,
}

impl KeyStatus {
    /// Whether a signature from this key may still be accepted.
    pub fn verifies(&self) -> bool {
        matches!(self, KeyStatus::Active | KeyStatus::Retired)
    }

    /// Whether this key may sign something new.
    pub fn signs(&self) -> bool {
        matches!(self, KeyStatus::Active)
    }

    /// The status's stable wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyStatus::Pending => "pending",
            KeyStatus::Active => "active",
            KeyStatus::Retired => "retired",
            KeyStatus::Revoked => "revoked",
        }
    }
}

impl std::fmt::Display for KeyStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Decode `2 * N` hex characters, trimming the trailing newline a key file usually carries.
pub(crate) fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let text = text.trim();
    if text.len() != N * 2 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let pair = std::str::from_utf8(pair).ok()?;
        out[index] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// Hex-encode bytes for a register entry or a receipt.
pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_names_are_stable() {
        assert_eq!(KeyRole::ActorGovernance.as_str(), "actor-governance");
        assert_eq!(Algorithm::Ed25519.as_str(), "ed25519");
        assert_eq!(Backend::AwsKms.as_str(), "aws-kms");
        assert_eq!(KeyStatus::Revoked.as_str(), "revoked");
    }

    /// The status table is the whole trust model; spell it out so a change is deliberate.
    #[test]
    fn only_active_and_retired_verify_and_only_active_signs() {
        assert!(!KeyStatus::Pending.verifies() && !KeyStatus::Pending.signs());
        assert!(KeyStatus::Active.verifies() && KeyStatus::Active.signs());
        assert!(KeyStatus::Retired.verifies() && !KeyStatus::Retired.signs());
        assert!(!KeyStatus::Revoked.verifies() && !KeyStatus::Revoked.signs());
    }

    #[test]
    fn hex_round_trips_and_refuses_the_wrong_width() {
        assert_eq!(decode_hex::<2>("00ff"), Some([0x00, 0xff]));
        assert_eq!(decode_hex::<2>("00ff\n"), Some([0x00, 0xff]));
        assert_eq!(decode_hex::<2>("00f"), None);
        assert_eq!(encode_hex(&[0x00, 0xff]), "00ff");
    }
}
