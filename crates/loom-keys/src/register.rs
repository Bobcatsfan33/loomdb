//! The trust-root register: the file that says which keys speak for which role.
//!
//! # Why a file, and why it is not signed
//!
//! Verifiers run inside enclaves with no network and no KMS reachable, so the register has to be
//! something a read-only mount can deliver. It is deliberately *not* self-signed: a register signed
//! by a key that the register itself names is a circular argument, and one signed by a further key
//! only moves the question. It is delivered exactly the way every other trust root is — through an
//! independent, authenticated channel onto a read-only mount — and it is validated fail-closed on
//! load.
//!
//! What it buys over the bare public key it replaces is everything a bare key cannot express:
//! *which role* this key speaks for, *which algorithm* it is registered under, *whether it is still
//! trusted*, and *who approved making it so*. A file an attacker can rewrite was already game over
//! when it was one public key; now the same file can also say "revoked", which is a capability the
//! old shape simply did not have.

use std::collections::BTreeSet;
use std::path::Path;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::{decode_hex, Algorithm, Backend, KeyError, KeyRole, KeyStatus, Result};

/// The register format this crate reads.
pub const REGISTER_SCHEMA_VERSION: u32 = 1;

/// The largest register that will be read. A register lists an organization's trust roots, not a
/// directory of users.
const MAX_REGISTER_BYTES: u64 = 256 * 1024;

/// How many distinct approvers a transition that changes what verifies must carry.
const DUAL_CONTROL: usize = 2;

/// One person's recorded approval of a ceremony step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Approval {
    /// Who approved. Distinctness is checked on this field, so it must identify a person or a role
    /// account, not a shared label.
    pub approver: String,
    /// When, in Unix seconds. Advisory — the approval is what authorizes, not the timestamp.
    pub at_unix: u64,
}

/// The auditable record behind a trust root's current status.
///
/// loomDB does not run the ceremony. It requires that one happened and that the register says where
/// to find the evidence, so a reviewer can join a key in a running system to a document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ceremony {
    /// A stable pointer to the ceremony record — a ticket, a minute, a signed PDF's digest.
    pub reference: String,
    /// Who approved this key's current status.
    pub approvals: Vec<Approval>,
}

impl Ceremony {
    /// The distinct approvers on record.
    pub fn approvers(&self) -> BTreeSet<&str> {
        self.approvals
            .iter()
            .map(|approval| approval.approver.as_str())
            .collect()
    }
}

/// One named trust root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustRoot {
    /// The operator-chosen identity of this key, bound into verification and into every receipt.
    pub key_id: String,
    /// Which authority it speaks for.
    pub role: KeyRole,
    /// The algorithm it is registered under. An artifact claiming a different one is refused.
    pub algorithm: Algorithm,
    /// The public half, hex-encoded.
    pub public_key: String,
    /// Where the private half lives. Labels custody; never widens it.
    pub backend: Backend,
    /// Where this key sits in the rotation sequence.
    pub status: KeyStatus,
    /// Monotonic within a role. `activate` requires a strictly higher generation than the key it
    /// supersedes, so a rotation cannot be replayed backwards by re-presenting an older register.
    pub generation: u64,
    /// The ceremony behind the current status.
    pub ceremony: Ceremony,
    /// Why the key was revoked. Required when — and only when — the status is `revoked`, so an
    /// unexplained revocation cannot be reviewed or reversed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
}

impl TrustRoot {
    /// Decode the public half.
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        let bytes =
            decode_hex::<32>(&self.public_key).ok_or_else(|| KeyError::RegisterInvalid {
                detail: format!(
                    "trust root {:?} public key must be 64 hexadecimal characters",
                    self.key_id
                ),
            })?;
        VerifyingKey::from_bytes(&bytes).map_err(|error| KeyError::RegisterInvalid {
            detail: format!(
                "trust root {:?} public key is not on the curve: {error}",
                self.key_id
            ),
        })
    }

    /// Whether the ceremony record carries enough distinct approvers for a trusted status.
    pub(crate) fn dual_control_satisfied(&self) -> bool {
        self.ceremony.approvers().len() >= DUAL_CONTROL
    }
}

/// Every trust root a deployment knows about, across roles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustRootRegister {
    /// Register format version.
    pub schema_version: u32,
    /// The roots, in no significant order.
    pub roots: Vec<TrustRoot>,
}

impl TrustRootRegister {
    /// An empty register, for building one up in tooling and tests.
    pub fn empty() -> Self {
        TrustRootRegister {
            schema_version: REGISTER_SCHEMA_VERSION,
            roots: Vec::new(),
        }
    }

    /// **Load and validate a register from a read-only mount.**
    ///
    /// Fail-closed on the same grounds as every other trust material this product reads: a regular
    /// file, size-bounded, never a symlink an attacker could repoint between restarts, and never
    /// group- or world-writable.
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| KeyError::Io {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;
        if !metadata.file_type().is_file() {
            return Err(KeyError::RegisterUnusable {
                path: path.display().to_string(),
                detail: "must be a regular file, not a symlink, directory, or device".into(),
            });
        }
        if metadata.len() > MAX_REGISTER_BYTES {
            return Err(KeyError::RegisterUnusable {
                path: path.display().to_string(),
                detail: format!("exceeds the {MAX_REGISTER_BYTES} byte limit"),
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(KeyError::RegisterUnusable {
                    path: path.display().to_string(),
                    detail: "must not be group- or world-writable; anything that can rewrite the \
                             register can appoint its own trust roots"
                        .into(),
                });
            }
        }
        let bytes = std::fs::read(path).map_err(|error| KeyError::Io {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;
        let register: TrustRootRegister =
            serde_json::from_slice(&bytes).map_err(|error| KeyError::RegisterUnusable {
                path: path.display().to_string(),
                detail: format!("is not a valid trust-root register: {error}"),
            })?;
        register.validate()?;
        Ok(register)
    }

    /// Write the register atomically. Used by the rotation tooling, never by a verifier.
    pub fn write(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let body = serde_json::to_vec_pretty(self).map_err(|error| KeyError::RegisterInvalid {
            detail: format!("cannot encode the register: {error}"),
        })?;
        let partial = path.with_extension("partial");
        std::fs::write(&partial, &body).map_err(|error| KeyError::Io {
            path: partial.display().to_string(),
            detail: error.to_string(),
        })?;
        std::fs::rename(&partial, path).map_err(|error| KeyError::Io {
            path: path.display().to_string(),
            detail: error.to_string(),
        })
    }

    /// **Everything that must be true of a register before anything trusts it.**
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != REGISTER_SCHEMA_VERSION {
            return Err(KeyError::RegisterInvalid {
                detail: format!(
                    "schemaVersion {} is not the supported {REGISTER_SCHEMA_VERSION}",
                    self.schema_version
                ),
            });
        }
        if self.roots.is_empty() {
            return Err(KeyError::RegisterInvalid {
                detail: "registers no trust roots; an empty register trusts nothing at all".into(),
            });
        }

        let mut seen = BTreeSet::new();
        for root in &self.roots {
            if root.key_id.trim().is_empty() || root.key_id.len() > 128 {
                return Err(KeyError::RegisterInvalid {
                    detail: format!(
                        "key id {:?} must contain 1..=128 non-blank bytes",
                        root.key_id
                    ),
                });
            }
            // A key id is an identity. Two entries sharing one id in the same role would make
            // "which key is this" unanswerable, and revocation ambiguous.
            if !seen.insert((root.role, root.key_id.as_str())) {
                return Err(KeyError::RegisterInvalid {
                    detail: format!(
                        "key id {:?} appears twice in the {} role",
                        root.key_id, root.role
                    ),
                });
            }
            root.verifying_key()?;
            if root.ceremony.reference.trim().is_empty() {
                return Err(KeyError::RegisterInvalid {
                    detail: format!(
                        "trust root {:?} records no ceremony reference; a key nobody can trace to \
                         an approval is not custodied",
                        root.key_id
                    ),
                });
            }
            // Dual control applies to the statuses that change what verifies. `pending` and
            // `retired` are reachable only *through* those, so gating them twice would add
            // ceremony without adding control.
            if matches!(root.status, KeyStatus::Active | KeyStatus::Revoked)
                && !root.dual_control_satisfied()
            {
                return Err(KeyError::DualControlRequired {
                    key_id: root.key_id.clone(),
                    status: root.status,
                    approvals: root.ceremony.approvers().len(),
                    required: DUAL_CONTROL,
                });
            }
            match (root.status, &root.revocation_reason) {
                (KeyStatus::Revoked, None) => {
                    return Err(KeyError::RegisterInvalid {
                        detail: format!(
                            "trust root {:?} is revoked with no recorded reason; an unexplained \
                             revocation cannot be reviewed or reversed",
                            root.key_id
                        ),
                    })
                }
                (status, Some(_)) if status != KeyStatus::Revoked => {
                    return Err(KeyError::RegisterInvalid {
                        detail: format!(
                            "trust root {:?} is {status} but carries a revocation reason; a stale \
                             reason must not outlive the revocation it described",
                            root.key_id
                        ),
                    })
                }
                _ => {}
            }
        }

        // At most one active signer per role. Two would make "which key signs" a coin flip, and the
        // rotation sequence exists precisely so there is never a moment of ambiguity.
        for role in [
            KeyRole::ActorGovernance,
            KeyRole::Release,
            KeyRole::BackupRoot,
        ] {
            let active: Vec<&TrustRoot> = self
                .roots
                .iter()
                .filter(|root| root.role == role && root.status == KeyStatus::Active)
                .collect();
            if active.len() > 1 {
                return Err(KeyError::RegisterInvalid {
                    detail: format!(
                        "the {role} role has {} active trust roots ({}); exactly one key signs at \
                         a time, and rotation moves the old one to retired",
                        active.len(),
                        active
                            .iter()
                            .map(|root| root.key_id.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                });
            }
        }
        Ok(())
    }

    /// Every root in one role.
    pub fn in_role(&self, role: KeyRole) -> impl Iterator<Item = &TrustRoot> {
        self.roots.iter().filter(move |root| root.role == role)
    }

    /// Find one root by role and id, whatever its status.
    pub fn find(&self, role: KeyRole, key_id: &str) -> Option<&TrustRoot> {
        self.in_role(role).find(|root| root.key_id == key_id)
    }
}

#[cfg(test)]
pub(crate) mod fixture {
    use super::*;
    use ed25519_dalek::SigningKey;

    pub(crate) fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    pub(crate) fn ceremony(approvers: &[&str]) -> Ceremony {
        Ceremony {
            reference: "CEREMONY-2026-08-01".into(),
            approvals: approvers
                .iter()
                .map(|approver| Approval {
                    approver: (*approver).to_string(),
                    at_unix: 1_800_000_000,
                })
                .collect(),
        }
    }

    pub(crate) fn root(
        key_id: &str,
        role: KeyRole,
        status: KeyStatus,
        generation: u64,
        seed: u8,
    ) -> TrustRoot {
        TrustRoot {
            key_id: key_id.into(),
            role,
            algorithm: Algorithm::Ed25519,
            public_key: crate::encode_hex(signing_key(seed).verifying_key().as_bytes()),
            backend: Backend::Software,
            status,
            generation,
            ceremony: ceremony(&["pki-officer", "security-lead"]),
            revocation_reason: match status {
                KeyStatus::Revoked => Some("drill".into()),
                _ => None,
            },
        }
    }

    pub(crate) fn register(roots: Vec<TrustRoot>) -> TrustRootRegister {
        TrustRootRegister {
            schema_version: REGISTER_SCHEMA_VERSION,
            roots,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;

    #[test]
    fn a_well_formed_register_validates() {
        let register = register(vec![root(
            "release-2026-q3",
            KeyRole::Release,
            KeyStatus::Active,
            1,
            1,
        )]);
        assert!(register.validate().is_ok());
    }

    /// **Dual control.** One person must not be able to make a key authoritative.
    #[test]
    fn one_approver_cannot_activate_a_trust_root() {
        let mut entry = root("release-2026-q3", KeyRole::Release, KeyStatus::Active, 1, 1);
        entry.ceremony = ceremony(&["pki-officer"]);
        let error = register(vec![entry]).validate().expect_err("must refuse");
        assert!(
            matches!(error, KeyError::DualControlRequired { required: 2, .. }),
            "{error}"
        );
    }

    /// The same person twice is one person.
    #[test]
    fn the_same_approver_twice_is_not_dual_control() {
        let mut entry = root("release-2026-q3", KeyRole::Release, KeyStatus::Active, 1, 1);
        entry.ceremony = ceremony(&["pki-officer", "pki-officer"]);
        assert!(register(vec![entry]).validate().is_err());
    }

    #[test]
    fn a_revocation_must_record_why() {
        let mut entry = root("release-old", KeyRole::Release, KeyStatus::Revoked, 1, 1);
        entry.revocation_reason = None;
        let error = register(vec![entry]).validate().expect_err("must refuse");
        assert!(format!("{error}").contains("no recorded reason"), "{error}");
    }

    #[test]
    fn a_stale_revocation_reason_cannot_outlive_the_revocation() {
        let mut entry = root("release-2026-q3", KeyRole::Release, KeyStatus::Active, 1, 1);
        entry.revocation_reason = Some("used to be revoked".into());
        assert!(register(vec![entry]).validate().is_err());
    }

    /// Exactly one key signs at a time, per role.
    #[test]
    fn two_active_keys_in_one_role_are_refused() {
        let error = register(vec![
            root("release-a", KeyRole::Release, KeyStatus::Active, 1, 1),
            root("release-b", KeyRole::Release, KeyStatus::Active, 2, 2),
        ])
        .validate()
        .expect_err("must refuse");
        assert!(format!("{error}").contains("active trust roots"), "{error}");
    }

    /// Two roles may each have their own active key; they are separate authorities.
    #[test]
    fn different_roles_hold_their_own_active_keys() {
        assert!(register(vec![
            root("release-a", KeyRole::Release, KeyStatus::Active, 1, 1),
            root("backup-a", KeyRole::BackupRoot, KeyStatus::Active, 1, 2),
            root("gov-a", KeyRole::ActorGovernance, KeyStatus::Active, 1, 3),
        ])
        .validate()
        .is_ok());
    }

    #[test]
    fn a_duplicate_key_id_in_one_role_is_refused() {
        assert!(register(vec![
            root("release-a", KeyRole::Release, KeyStatus::Active, 1, 1),
            root("release-a", KeyRole::Release, KeyStatus::Retired, 2, 2),
        ])
        .validate()
        .is_err());
    }

    #[test]
    fn a_key_with_no_ceremony_reference_is_refused() {
        let mut entry = root("release-a", KeyRole::Release, KeyStatus::Active, 1, 1);
        entry.ceremony.reference = "  ".into();
        assert!(register(vec![entry]).validate().is_err());
    }

    #[test]
    fn an_empty_register_trusts_nothing_and_says_so() {
        assert!(TrustRootRegister::empty().validate().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_group_writable_register_is_refused() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("trust-roots.json");
        register(vec![root("a", KeyRole::Release, KeyStatus::Active, 1, 1)]).write(&path)?;
        let mut permissions = std::fs::metadata(&path)?.permissions();
        permissions.set_mode(0o664);
        std::fs::set_permissions(&path, permissions)?;
        let error = TrustRootRegister::load(&path).expect_err("must refuse");
        assert!(
            format!("{error}").contains("group- or world-writable"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn a_register_round_trips_through_a_file() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("trust-roots.json");
        let original = register(vec![root("a", KeyRole::Release, KeyStatus::Active, 1, 1)]);
        original.write(&path)?;
        assert_eq!(TrustRootRegister::load(&path)?, original);
        Ok(())
    }
}
