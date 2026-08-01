//! The verifier's view of custody: *may this key authorize this role, right now?*
//!
//! Everything here is offline by construction. A directory is a loaded register and a role; it
//! opens no socket and reaches no KMS, because the parties that verify — an enclave applying an
//! update, the backup verifier job, `loomd` at startup — are exactly the parties least likely to
//! have a route to one.

use ed25519_dalek::{Signature, Verifier};

use crate::{Algorithm, KeyError, KeyRole, KeyStatus, Result, TrustRoot, TrustRootRegister};

/// The trust roots of one role, and the questions a verifier asks of them.
#[derive(Clone, Debug)]
pub struct KeyDirectory {
    register: TrustRootRegister,
    role: KeyRole,
}

impl KeyDirectory {
    /// Take the view of `role` over an already-validated register.
    pub fn new(register: TrustRootRegister, role: KeyRole) -> Result<Self> {
        register.validate()?;
        Ok(KeyDirectory { register, role })
    }

    /// Load a register from a read-only mount and take the view of `role`.
    pub fn load(path: &std::path::Path, role: KeyRole) -> Result<Self> {
        Ok(KeyDirectory {
            register: TrustRootRegister::load(path)?,
            role,
        })
    }

    /// The role this directory speaks for.
    pub fn role(&self) -> KeyRole {
        self.role
    }

    /// The register behind it.
    pub fn register(&self) -> &TrustRootRegister {
        &self.register
    }

    /// Every root in this role that may still verify, newest generation first.
    pub fn trusted(&self) -> Vec<&TrustRoot> {
        let mut roots: Vec<&TrustRoot> = self
            .register
            .in_role(self.role)
            .filter(|root| root.status.verifies())
            .collect();
        roots.sort_by_key(|root| std::cmp::Reverse(root.generation));
        roots
    }

    /// The one root that may sign for this role.
    pub fn signing_root(&self) -> Result<&TrustRoot> {
        self.register
            .in_role(self.role)
            .find(|root| root.status.signs())
            .ok_or(KeyError::NoActiveSigner { role: self.role })
    }

    /// **Resolve a key id to a root that may verify, or say precisely why not.**
    ///
    /// The four refusals are different facts and are reported as different errors: the id is
    /// unknown, it belongs to another role, it was revoked, or it is staged and not yet trusted. A
    /// verifier that collapses these into "invalid signature" leaves an operator unable to tell a
    /// rotation mistake from an attack.
    pub fn resolve(&self, key_id: &str) -> Result<&TrustRoot> {
        // Look across *all* roles first, so a key that exists but speaks for another authority is
        // reported as the role error it is rather than as an unknown id.
        if let Some(root) = self.register.find(self.role, key_id) {
            return match root.status {
                KeyStatus::Revoked => Err(KeyError::KeyRevoked {
                    key_id: root.key_id.clone(),
                    generation: root.generation,
                    reason: root
                        .revocation_reason
                        .clone()
                        .unwrap_or_else(|| "no reason recorded".into()),
                }),
                KeyStatus::Pending => Err(KeyError::KeyNotTrusted {
                    key_id: root.key_id.clone(),
                    status: root.status,
                }),
                KeyStatus::Active | KeyStatus::Retired => Ok(root),
            };
        }
        if let Some(elsewhere) = self
            .register
            .roots
            .iter()
            .find(|root| root.key_id == key_id)
        {
            return Err(KeyError::RoleMismatch {
                key_id: key_id.to_string(),
                expected: self.role,
                found: elsewhere.role,
            });
        }
        Err(KeyError::UnknownKeyId {
            key_id: key_id.to_string(),
            role: self.role,
        })
    }

    /// **Verify a signature against a named key.**
    ///
    /// `claimed_algorithm` is what the artifact says it used. Binding it here is the difference
    /// between "a key verified this" and "the key we registered for this purpose, under the
    /// algorithm we registered it for, verified this".
    pub fn verify(
        &self,
        key_id: &str,
        claimed_algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<&TrustRoot> {
        let root = self.resolve(key_id)?;
        if claimed_algorithm != root.algorithm.as_str() {
            return Err(KeyError::AlgorithmMismatch {
                key_id: root.key_id.clone(),
                expected: root.algorithm,
                found: claimed_algorithm.to_string(),
            });
        }
        verify_against(root, message, signature)?;
        Ok(root)
    }

    /// **Verify a signature that does not name its key.**
    ///
    /// The actor-registry attestation and the release bundle carry no key id — adding one would
    /// change a signed format, which this increment must not do. So each trusted root in the role
    /// is tried, newest generation first, and the one that verified is returned for the audit log.
    ///
    /// Revoked and staged keys are never tried. That is the whole mechanism by which a revoked key
    /// stops working: its material still verifies, and this loop simply never offers it.
    pub fn verify_any(&self, message: &[u8], signature: &[u8]) -> Result<&TrustRoot> {
        let trusted = self.trusted();
        for root in &trusted {
            if verify_against(root, message, signature).is_ok() {
                return Ok(root);
            }
        }
        Err(KeyError::NoTrustedKey {
            role: self.role,
            tried: trusted.len(),
        })
    }
}

fn verify_against(root: &TrustRoot, message: &[u8], signature: &[u8]) -> Result<()> {
    match root.algorithm {
        Algorithm::Ed25519 => {
            let bytes: [u8; 64] = signature
                .try_into()
                .map_err(|_| KeyError::SignatureInvalid {
                    key_id: root.key_id.clone(),
                    detail: format!(
                        "an ed25519 signature is 64 bytes; this one is {}",
                        signature.len()
                    ),
                })?;
            root.verifying_key()?
                .verify(message, &Signature::from_bytes(&bytes))
                .map_err(|error| KeyError::SignatureInvalid {
                    key_id: root.key_id.clone(),
                    detail: error.to_string(),
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::register::fixture::*;
    use ed25519_dalek::Signer as _;

    const MESSAGE: &[u8] = b"the exact bytes a caller asked to have signed";

    fn sign(seed: u8) -> Vec<u8> {
        signing_key(seed).sign(MESSAGE).to_bytes().to_vec()
    }

    fn directory(roots: Vec<TrustRoot>, role: KeyRole) -> KeyDirectory {
        KeyDirectory::new(register(roots), role).expect("a valid register")
    }

    #[test]
    fn an_active_key_verifies_and_is_reported_by_name() {
        let directory = directory(
            vec![root(
                "release-2026-q3",
                KeyRole::Release,
                KeyStatus::Active,
                2,
                7,
            )],
            KeyRole::Release,
        );
        let matched = directory
            .verify("release-2026-q3", "ed25519", MESSAGE, &sign(7))
            .expect("verifies");
        assert_eq!(matched.key_id, "release-2026-q3");
    }

    /// **The property revocation exists for.** The key material is unchanged and still verifies
    /// mathematically; the directory refuses it anyway, and says so by name.
    #[test]
    fn a_revoked_key_is_refused_even_though_its_signature_is_valid() {
        let directory = directory(
            vec![
                root("release-old", KeyRole::Release, KeyStatus::Revoked, 1, 7),
                root("release-new", KeyRole::Release, KeyStatus::Active, 2, 8),
            ],
            KeyRole::Release,
        );
        // Sanity: the signature really is valid for the revoked key's material.
        let revoked = directory
            .register
            .find(KeyRole::Release, "release-old")
            .unwrap();
        assert!(verify_against(revoked, MESSAGE, &sign(7)).is_ok());

        let error = directory
            .verify("release-old", "ed25519", MESSAGE, &sign(7))
            .expect_err("must refuse");
        assert!(matches!(error, KeyError::KeyRevoked { .. }), "{error}");
        // And it is not reachable through the unnamed path either.
        let error = directory
            .verify_any(MESSAGE, &sign(7))
            .expect_err("must refuse");
        assert!(matches!(error, KeyError::NoTrustedKey { .. }), "{error}");
    }

    #[test]
    fn a_staged_key_authorizes_nothing_yet() {
        let directory = directory(
            vec![root(
                "release-next",
                KeyRole::Release,
                KeyStatus::Pending,
                2,
                8,
            )],
            KeyRole::Release,
        );
        let error = directory
            .verify("release-next", "ed25519", MESSAGE, &sign(8))
            .expect_err("must refuse");
        assert!(matches!(error, KeyError::KeyNotTrusted { .. }), "{error}");
    }

    /// A retired key still verifies what it signed before the rotation.
    #[test]
    fn a_retired_key_still_verifies_but_may_not_sign() {
        let directory = directory(
            vec![
                root("release-old", KeyRole::Release, KeyStatus::Retired, 1, 7),
                root("release-new", KeyRole::Release, KeyStatus::Active, 2, 8),
            ],
            KeyRole::Release,
        );
        assert_eq!(
            directory
                .verify_any(MESSAGE, &sign(7))
                .expect("verifies")
                .key_id,
            "release-old"
        );
        assert_eq!(
            directory.signing_root().expect("one signer").key_id,
            "release-new"
        );
    }

    #[test]
    fn an_unknown_key_id_and_a_wrong_role_are_different_refusals() {
        let directory = directory(
            vec![
                root("release-a", KeyRole::Release, KeyStatus::Active, 1, 7),
                root("backup-a", KeyRole::BackupRoot, KeyStatus::Active, 1, 8),
            ],
            KeyRole::Release,
        );
        assert!(matches!(
            directory.resolve("nobody").expect_err("unknown"),
            KeyError::UnknownKeyId { .. }
        ));
        assert!(matches!(
            directory.resolve("backup-a").expect_err("wrong role"),
            KeyError::RoleMismatch {
                expected: KeyRole::Release,
                found: KeyRole::BackupRoot,
                ..
            }
        ));
    }

    /// An algorithm the key was not registered under is not a key you have checked.
    #[test]
    fn an_algorithm_the_key_is_not_registered_for_is_refused() {
        let directory = directory(
            vec![root("release-a", KeyRole::Release, KeyStatus::Active, 1, 7)],
            KeyRole::Release,
        );
        let error = directory
            .verify("release-a", "ecdsa-p256", MESSAGE, &sign(7))
            .expect_err("must refuse");
        assert!(
            matches!(error, KeyError::AlgorithmMismatch { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_signature_from_the_wrong_key_does_not_verify() {
        let directory = directory(
            vec![root("release-a", KeyRole::Release, KeyStatus::Active, 1, 7)],
            KeyRole::Release,
        );
        let error = directory
            .verify("release-a", "ed25519", MESSAGE, &sign(9))
            .expect_err("must refuse");
        assert!(
            matches!(error, KeyError::SignatureInvalid { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_truncated_signature_is_refused_before_the_curve_sees_it() {
        let directory = directory(
            vec![root("release-a", KeyRole::Release, KeyStatus::Active, 1, 7)],
            KeyRole::Release,
        );
        let error = directory
            .verify("release-a", "ed25519", MESSAGE, &sign(7)[..32])
            .expect_err("must refuse");
        assert!(format!("{error}").contains("64 bytes"), "{error}");
    }

    #[test]
    fn a_role_with_no_active_key_has_no_signer() {
        let directory = directory(
            vec![root(
                "release-old",
                KeyRole::Release,
                KeyStatus::Retired,
                1,
                7,
            )],
            KeyRole::Release,
        );
        assert!(matches!(
            directory.signing_root().expect_err("sealed"),
            KeyError::NoActiveSigner { .. }
        ));
    }
}
