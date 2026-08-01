//! The signer interface, and the software-backed stand-in that implements it.
//!
//! # The interface signs bytes, and that is all it does
//!
//! Every signed format in this workspace predates this crate and must survive it byte for byte: the
//! bundle manifest's bincode encoding, the backup manifest's exact bytes, the actor-attestation's
//! domain-separated payload. So [`Signer`] takes `&[u8]` and returns a signature. It does not
//! serialize, canonicalize, wrap, or timestamp anything.
//!
//! That anaemia is the design. A backend that formats anything is a backend that can change what a
//! signature *means*, and swapping custody — software today, hardware after the ceremony — must
//! never be able to invalidate an artifact signed before the swap, or silently change the bytes a
//! future artifact commits to.
//!
//! # Custody is labelled, never assumed
//!
//! [`SignedReceipt`] records which backend produced each signature. A drill against a software key
//! proves the *sequence* works — expand, activate, verify, revoke — and proves nothing whatsoever
//! about hardware custody. Labelling is what stops a green drill from reading like a satisfied
//! hardware gate.

use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};

use crate::{decode_hex, Algorithm, Backend, KeyError, KeyRole, Result, TrustRoot};

/// Something that can produce a signature for a trust root.
///
/// Implemented here by [`SoftwareSigner`]. A KMS or HSM backend implements the same trait in its own
/// crate, so it never enters a verifier's dependency graph — verifiers must stay offline.
pub trait Signer {
    /// The identity of the key that signs, bound into every receipt.
    fn key_id(&self) -> &str;

    /// Which authority it speaks for.
    fn role(&self) -> KeyRole;

    /// The algorithm it signs with.
    fn algorithm(&self) -> Algorithm;

    /// Where the private half lives. Labels custody; never widens it.
    fn backend(&self) -> Backend;

    /// **Sign exactly these bytes.**
    ///
    /// The caller owns the format. An implementation that hashes, wraps, or re-encodes `message`
    /// before signing is a broken implementation, because the verifier will check the caller's
    /// bytes.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;

    /// Sign, and return the signature with the custody facts attached.
    fn sign_receipt(&self, message: &[u8]) -> Result<SignedReceipt> {
        Ok(SignedReceipt {
            key_id: self.key_id().to_string(),
            role: self.role(),
            algorithm: self.algorithm(),
            backend: self.backend(),
            signature: crate::encode_hex(&self.sign(message)?),
        })
    }
}

/// A signature plus the custody facts an auditor needs to weigh it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReceipt {
    /// Which key signed.
    pub key_id: String,
    /// Which authority it spoke for.
    pub role: KeyRole,
    /// Under which algorithm.
    pub algorithm: Algorithm,
    /// **And on which backend.** A software signature is not a hardware one, and a receipt that
    /// omitted this would let a drill be mistaken for a ceremony.
    pub backend: Backend,
    /// The signature, hex-encoded.
    pub signature: String,
}

/// Decode a receipt's hex signature back to bytes.
pub fn decode_receipt_signature(receipt: &SignedReceipt) -> Result<Vec<u8>> {
    decode_hex::<64>(&receipt.signature)
        .map(|bytes| bytes.to_vec())
        .ok_or_else(|| KeyError::SignatureInvalid {
            key_id: receipt.key_id.clone(),
            detail: "the receipt signature is not 128 hexadecimal characters".into(),
        })
}

/// A signer backed by a key file on disk.
///
/// Correct for local drills, development, and CI. **Not a custody claim**: the private key is
/// readable by whoever can read the file, which is precisely what a hardware backend exists to stop.
/// `EXT-HSM` stays open however green this is.
pub struct SoftwareSigner {
    key_id: String,
    role: KeyRole,
    algorithm: Algorithm,
    signing_key: SigningKey,
}

/// Redacted by hand rather than derived.
///
/// A derived `Debug` on a type holding a private key puts that key one `dbg!`, one `{:?}` in a log
/// line, or one panic message away from an incident. The identity is useful in a diagnostic; the
/// seed never is.
impl std::fmt::Debug for SoftwareSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SoftwareSigner")
            .field("key_id", &self.key_id)
            .field("role", &self.role)
            .field("algorithm", &self.algorithm)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl SoftwareSigner {
    /// Build a signer for `root` from a hex-encoded private key file.
    ///
    /// Refuses in three ways that matter:
    ///
    /// * the register asks for a backend this binary cannot drive — it is **not** silently signed in
    ///   software instead, because a receipt claiming hardware custody must come from hardware;
    /// * the key file is readable beyond its owner;
    /// * the private key does not match the public half the register publishes, which would produce
    ///   signatures nothing can verify.
    pub fn from_file(root: &TrustRoot, path: &std::path::Path) -> Result<Self> {
        if root.backend != Backend::Software {
            return Err(KeyError::BackendUnavailable {
                key_id: root.key_id.clone(),
                backend: root.backend,
            });
        }
        if !root.status.signs() {
            return Err(KeyError::KeyNotTrusted {
                key_id: root.key_id.clone(),
                status: root.status,
            });
        }
        let metadata = std::fs::symlink_metadata(path).map_err(|error| KeyError::Io {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;
        if !metadata.file_type().is_file() {
            return Err(KeyError::SigningKeyUnusable {
                key_id: root.key_id.clone(),
                detail: "the key file must be a regular file, not a symlink or device".into(),
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(KeyError::SigningKeyUnusable {
                    key_id: root.key_id.clone(),
                    detail: format!(
                        "the key file is readable beyond its owner (mode 0{:o}); a private key \
                         must be 0400 or 0600",
                        metadata.permissions().mode() & 0o777
                    ),
                });
            }
        }
        let text = std::fs::read_to_string(path).map_err(|error| KeyError::Io {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;
        let seed = decode_hex::<32>(&text).ok_or_else(|| KeyError::SigningKeyUnusable {
            key_id: root.key_id.clone(),
            detail: "the key file must contain 64 hexadecimal characters".into(),
        })?;
        let signing_key = SigningKey::from_bytes(&seed);

        // A private key that does not match the published public half would produce signatures no
        // verifier accepts — a failure that would otherwise surface as "everything is broken" long
        // after the ceremony, rather than here.
        if signing_key.verifying_key() != root.verifying_key()? {
            return Err(KeyError::SigningKeyUnusable {
                key_id: root.key_id.clone(),
                detail: "the private key does not match the public key the register publishes"
                    .into(),
            });
        }
        Ok(SoftwareSigner {
            key_id: root.key_id.clone(),
            role: root.role,
            algorithm: root.algorithm,
            signing_key,
        })
    }

    /// Build a signer directly from key material, for drills and tests.
    pub fn from_key(root: &TrustRoot, signing_key: SigningKey) -> Result<Self> {
        if root.backend != Backend::Software {
            return Err(KeyError::BackendUnavailable {
                key_id: root.key_id.clone(),
                backend: root.backend,
            });
        }
        if signing_key.verifying_key() != root.verifying_key()? {
            return Err(KeyError::SigningKeyUnusable {
                key_id: root.key_id.clone(),
                detail: "the private key does not match the public key the register publishes"
                    .into(),
            });
        }
        Ok(SoftwareSigner {
            key_id: root.key_id.clone(),
            role: root.role,
            algorithm: root.algorithm,
            signing_key,
        })
    }
}

impl Signer for SoftwareSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn role(&self) -> KeyRole {
        self.role
    }

    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn backend(&self) -> Backend {
        Backend::Software
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.signing_key.sign(message).to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::register::fixture::*;
    use crate::{KeyDirectory, KeyStatus};

    const MESSAGE: &[u8] = b"exact bytes";

    #[test]
    fn a_software_signer_produces_a_signature_the_directory_accepts() {
        let entry = root("release-a", KeyRole::Release, KeyStatus::Active, 1, 7);
        let signer = SoftwareSigner::from_key(&entry, signing_key(7)).expect("builds");
        let receipt = signer.sign_receipt(MESSAGE).expect("signs");
        assert_eq!(receipt.backend, Backend::Software);
        assert_eq!(receipt.key_id, "release-a");

        let directory =
            KeyDirectory::new(register(vec![entry]), KeyRole::Release).expect("valid register");
        let signature = crate::decode_hex::<64>(&receipt.signature).expect("hex");
        assert!(directory
            .verify("release-a", "ed25519", MESSAGE, &signature)
            .is_ok());
    }

    /// **The signer signs the caller's bytes and nothing else.** If an implementation ever wrapped
    /// or re-encoded the message, this fails — and every signed format in the workspace would have
    /// silently changed meaning.
    #[test]
    fn the_signer_signs_exactly_the_bytes_it_was_given() {
        use ed25519_dalek::Signer as _;

        let entry = root("release-a", KeyRole::Release, KeyStatus::Active, 1, 7);
        let signer = SoftwareSigner::from_key(&entry, signing_key(7)).expect("builds");
        let through_interface = signer.sign(MESSAGE).expect("signs");
        let directly = signing_key(7).sign(MESSAGE).to_bytes().to_vec();
        assert_eq!(through_interface, directly);
    }

    /// A backend this binary cannot drive is refused, not quietly downgraded to software.
    #[test]
    fn a_hardware_backed_root_is_not_signed_in_software_instead() {
        let mut entry = root("release-a", KeyRole::Release, KeyStatus::Active, 1, 7);
        entry.backend = Backend::AwsKms;
        let error = SoftwareSigner::from_key(&entry, signing_key(7)).expect_err("must refuse");
        assert!(
            matches!(
                error,
                KeyError::BackendUnavailable {
                    backend: Backend::AwsKms,
                    ..
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn a_private_key_that_does_not_match_the_register_is_refused() {
        let entry = root("release-a", KeyRole::Release, KeyStatus::Active, 1, 7);
        let error = SoftwareSigner::from_key(&entry, signing_key(9)).expect_err("must refuse");
        assert!(format!("{error}").contains("does not match"), "{error}");
    }

    #[test]
    fn a_retired_key_cannot_be_asked_to_sign() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("key.hex");
        std::fs::write(&path, crate::encode_hex(&signing_key(7).to_bytes()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        let entry = root("release-old", KeyRole::Release, KeyStatus::Retired, 1, 7);
        let error = SoftwareSigner::from_file(&entry, &path).expect_err("must refuse");
        assert!(matches!(error, KeyError::KeyNotTrusted { .. }), "{error}");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_group_readable_private_key_is_refused(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("key.hex");
        std::fs::write(&path, crate::encode_hex(&signing_key(7).to_bytes()))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))?;
        let entry = root("release-a", KeyRole::Release, KeyStatus::Active, 1, 7);
        let error = SoftwareSigner::from_file(&entry, &path).expect_err("must refuse");
        assert!(
            format!("{error}").contains("readable beyond its owner"),
            "{error}"
        );
        Ok(())
    }
}
