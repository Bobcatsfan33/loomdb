//! The AWS KMS signer backend.
//!
//! # Why this is behind a feature, and must stay behind one
//!
//! `loom-keys` is in `loomd`'s dependency graph, and `loomd` ships in an air-gap flavour whose whole
//! claim is that it links no network client. An AWS SDK in the default graph would break that claim
//! for every verifier in the fleet — and verifiers are exactly the parties that must keep working
//! with no route anywhere.
//!
//! So the SDK is optional and off by default. Enable `--features aws-kms` in the *signing* tool
//! only. `scripts/verify_build_flavours.sh` asserts the air-gap graph contains no `aws-sdk` crate,
//! so this cannot regress quietly.
//!
//! # What it does
//!
//! `kms:Sign` with `ED25519_SHA_512` and `MessageType: RAW` — pure Ed25519 (FIPS 186-5 §7.6), which
//! is byte-compatible with what `ed25519_dalek::VerifyingKey::verify_strict` checks. Verified
//! against real KMS during P9.1; see `docs/drills/kms-roundtrip.json`.
//!
//! **Never `ED25519_PH_SHA_512`.** That is HashEdDSA (§7.8, `MessageType: DIGEST`), a different
//! signature scheme producing signatures this codebase will not verify. Both algorithms are offered
//! on an `ECC_NIST_EDWARDS25519` key and they sit one line apart in the API reference, so the choice
//! is made here in code, once, rather than left to a caller.
//!
//! # What it does not do
//!
//! It never handles private key material — that is the point of KMS, and there is nothing here that
//! could log a key because nothing here has one. It logs no credentials either: the AWS provider
//! chain resolves them, this code never inspects them, and every error surfaces as
//! [`KeyError::BackendUnavailable`] naming the backend rather than the failure's contents.

use crate::{Algorithm, Backend, KeyError, KeyRole, Result, Signer, TrustRoot};

/// The signing algorithm loomDB uses on an `ECC_NIST_EDWARDS25519` key.
///
/// Pure EdDSA. See the module docs for why the prehash variant is not an option.
pub const KMS_SIGNING_ALGORITHM: &str = "ED25519_SHA_512";
/// The message type pure Ed25519 requires. KMS rejects `DIGEST` with this algorithm.
pub const KMS_MESSAGE_TYPE: &str = "RAW";
/// The largest message `kms:Sign` accepts.
///
/// The reason [`crate::KeyRole::BackupRoot`] needed a signed-format change at all — see
/// `docs/design/backup-signature-v2.md`.
pub const KMS_MAX_MESSAGE_BYTES: usize = 4096;

/// A signer that asks AWS KMS to sign, over the network, with a non-exportable key.
pub struct KmsSigner {
    key_id: String,
    role: KeyRole,
    algorithm: Algorithm,
    client: aws_sdk_kms::Client,
    runtime: tokio::runtime::Runtime,
}

impl std::fmt::Debug for KmsSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No client internals, no credentials. The identity is useful in a diagnostic; nothing else
        // in this struct is safe to render.
        formatter
            .debug_struct("KmsSigner")
            .field("key_id", &self.key_id)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl KmsSigner {
    /// Build a signer for a register entry that declares the `aws-kms` backend.
    ///
    /// Credentials come from the standard AWS provider chain — environment, profile, SSO, instance
    /// role — and are never read, stored, or logged by this code. A failure to resolve them, or to
    /// reach the endpoint, is reported as [`KeyError::BackendUnavailable`]: from the caller's point
    /// of view the backend simply cannot be driven, and the reason belongs in the operator's AWS
    /// tooling rather than in a loomDB error string that might reach a log.
    pub fn for_root(root: &TrustRoot) -> Result<Self> {
        if root.backend != Backend::AwsKms {
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
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|_| KeyError::BackendUnavailable {
                key_id: root.key_id.clone(),
                backend: Backend::AwsKms,
            })?;
        let config = runtime.block_on(aws_config::load_from_env());
        Ok(KmsSigner {
            key_id: root.key_id.clone(),
            role: root.role,
            algorithm: root.algorithm,
            client: aws_sdk_kms::Client::new(&config),
            runtime,
        })
    }

    fn unavailable(&self) -> KeyError {
        KeyError::BackendUnavailable {
            key_id: self.key_id.clone(),
            backend: Backend::AwsKms,
        }
    }
}

impl Signer for KmsSigner {
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
        Backend::AwsKms
    }

    /// Sign exactly these bytes with the KMS key.
    ///
    /// The 4096-byte ceiling is checked here rather than left to the service, so a payload that
    /// cannot be signed fails with something an operator can act on instead of a generic API error
    /// — and so the constraint that shaped the v2 backup format is visible at the call site.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        if message.is_empty() || message.len() > KMS_MAX_MESSAGE_BYTES {
            return Err(KeyError::SigningKeyUnusable {
                key_id: self.key_id.clone(),
                detail: format!(
                    "kms:Sign accepts 1..={KMS_MAX_MESSAGE_BYTES} bytes with MessageType RAW, and \
                     this payload is {}. Sign a digest instead — see \
                     docs/design/backup-signature-v2.md",
                    message.len()
                ),
            });
        }
        let response = self
            .runtime
            .block_on(
                self.client
                    .sign()
                    .key_id(&self.key_id)
                    .message(aws_sdk_kms::primitives::Blob::new(message.to_vec()))
                    .message_type(aws_sdk_kms::types::MessageType::Raw)
                    .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::Ed25519Sha512)
                    .send(),
            )
            // Deliberately not `{error}`: an SDK error can carry request context, and this string
            // reaches logs. The backend is unavailable; the detail belongs in AWS tooling.
            .map_err(|_| self.unavailable())?;
        let signature = response.signature().ok_or_else(|| self.unavailable())?;
        Ok(signature.as_ref().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ceremony, KeyStatus, TrustRootRegister};

    fn root(backend: Backend, status: KeyStatus) -> TrustRoot {
        TrustRoot {
            key_id: "arn:aws:kms:us-east-1:111122223333:key/abc".into(),
            role: KeyRole::Release,
            algorithm: Algorithm::Ed25519,
            public_key: "00".repeat(32),
            backend,
            status,
            generation: 1,
            ceremony: Ceremony {
                reference: "CEREMONY".into(),
                approvals: Vec::new(),
            },
            revocation_reason: None,
        }
    }

    /// A software-backed entry is refused by the KMS driver, the mirror of `SoftwareSigner`
    /// refusing an `aws-kms` entry. Neither backend silently covers for the other.
    #[test]
    fn the_kms_driver_refuses_a_software_backed_root() {
        let error = KmsSigner::for_root(&root(Backend::Software, KeyStatus::Active))
            .expect_err("must refuse");
        assert!(
            matches!(
                error,
                KeyError::BackendUnavailable {
                    backend: Backend::Software,
                    ..
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn a_key_that_may_not_sign_is_refused_before_any_network_call() {
        for status in [KeyStatus::Pending, KeyStatus::Retired, KeyStatus::Revoked] {
            let error = KmsSigner::for_root(&root(Backend::AwsKms, status)).expect_err("refused");
            assert!(
                matches!(error, KeyError::KeyNotTrusted { .. }),
                "{status}: {error}"
            );
        }
    }

    /// The constants are the ones the AWS API reference names. A typo here is a signature scheme
    /// this codebase cannot verify, so they are pinned.
    #[test]
    fn the_algorithm_is_pure_ed25519_not_the_prehash_variant() {
        assert_eq!(KMS_SIGNING_ALGORITHM, "ED25519_SHA_512");
        assert_ne!(KMS_SIGNING_ALGORITHM, "ED25519_PH_SHA_512");
        assert_eq!(KMS_MESSAGE_TYPE, "RAW");
        assert_eq!(KMS_MAX_MESSAGE_BYTES, 4096);
        assert_eq!(
            aws_sdk_kms::types::SigningAlgorithmSpec::Ed25519Sha512.as_str(),
            KMS_SIGNING_ALGORITHM
        );
        assert_eq!(
            aws_sdk_kms::types::MessageType::Raw.as_str(),
            KMS_MESSAGE_TYPE
        );
        let _ = TrustRootRegister::empty();
    }
}
