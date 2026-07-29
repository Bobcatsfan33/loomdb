//! **Signed offline update bundles.** How an air-gapped LoomDB deployment receives an update it can
//! trust without a network.
//!
//! An enclave that never touches the internet still has to receive things: a renewed license, a new
//! policy, a model artifact, a software update. Those arrive on physical media, carried by a person, so
//! the only thing standing between the enclave and a tampered or forged update is a signature it can
//! check **offline**, against a public key it already holds.
//!
//! A [`Bundle`] is exactly that: a small [`BundleManifest`] describing the payload, the payload itself,
//! and an Ed25519 signature. Verification ([`Bundle::verify`]) checks two things, and both matter:
//!
//! 1. the signature is valid over the manifest — so the manifest was not altered and was signed by the
//!    holder of the private key;
//! 2. the payload's BLAKE3 hash matches the hash **inside** the signed manifest — so the payload cannot
//!    be swapped for a different one under a genuine signature.
//!
//! # The private key never lives here
//!
//! This crate signs with whatever [`SigningKey`](ed25519_dalek::SigningKey) it is handed, and the CLI
//! (`loom-bundle-tool sign --key <path>`) reads that key from a **file path**. The production signing
//! key is provided to the release pipeline at that path from a secret; it never enters the code, the
//! repository, or a build log. Tests use a throwaway dev key generated in-process. See
//! `docs/operations.md`.

// CLAUDE-style rule: no panics in library code — this verifies updates for a facility that cannot call
// support. A panic here is an update that dies instead of being cleanly rejected.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The bundle format version this build writes and understands. A reader refuses a newer format rather
/// than guess at it — an enclave must never half-apply an update it does not fully understand.
pub const FORMAT_VERSION: u32 = 1;

/// Everything that can go wrong verifying or building a bundle. Each message names the next action,
/// because the person reading it is often on the far side of an airlock with no way to ask.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BundleError {
    /// The bundle was written by a format version this build does not understand.
    #[error(
        "this bundle is format version {found}, but this build understands version {expected}. \
         Use a loom-bundle-tool build that matches the bundle, or re-issue the bundle at version {expected}."
    )]
    UnsupportedFormat {
        /// The version found in the bundle.
        found: u32,
        /// The version this build supports.
        expected: u32,
    },

    /// The signature does not verify against the provided public key.
    #[error(
        "the bundle signature does not verify against this public key. The bundle was altered after \
         signing, was signed by a different key, or the wrong public key was supplied. Do NOT apply it."
    )]
    Signature,

    /// The payload does not match the hash the signed manifest commits to.
    #[error(
        "the bundle's payload does not match the hash in its signed manifest (expected {expected}, \
         got {actual}). The payload was swapped after signing. Do NOT apply it."
    )]
    PayloadHashMismatch {
        /// The hash the signed manifest commits to.
        expected: String,
        /// The hash actually computed over the payload.
        actual: String,
    },

    /// The bundle is authentic but is not the exact artifact the operator authorized.
    #[error(
        "the signed bundle's {claim} is {actual:?}, but this operation requires {expected:?}. \
         The bundle may be genuine, but it is not authorized for this operation. Do NOT apply it."
    )]
    ClaimMismatch {
        /// The manifest field that did not match.
        claim: &'static str,
        /// The exact value required by the change authorization.
        expected: String,
        /// The signed value carried by the bundle.
        actual: String,
    },

    /// A key was not 32 bytes.
    #[error("expected a 32-byte {what} key, got {len} bytes")]
    KeyLength {
        /// `"signing"` or `"verifying"`.
        what: &'static str,
        /// How many bytes were supplied.
        len: usize,
    },

    /// A stored signature was not 64 bytes.
    #[error("the bundle signature is {len} bytes, not the 64 an Ed25519 signature must be")]
    SignatureLength {
        /// How many bytes were present.
        len: usize,
    },

    /// A hex string could not be decoded.
    #[error("could not decode hex for {what}: {detail}")]
    Hex {
        /// What was being decoded.
        what: &'static str,
        /// Why it failed.
        detail: String,
    },

    /// Serialization / deserialization of the bundle failed.
    #[error("failed to {op} the bundle: {detail}")]
    Codec {
        /// `"encode"` or `"decode"`.
        op: &'static str,
        /// Why.
        detail: String,
    },
}

/// The result type.
pub type Result<T> = std::result::Result<T, BundleError>;

/// What a bundle carries, described. This is the part that is signed; because it commits to the
/// payload's hash, signing it signs the payload too.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    /// The bundle format version (see [`FORMAT_VERSION`]).
    pub format_version: u32,
    /// A stable identifier for this bundle (e.g. `"policy-2026-07"`), for the operator's audit log.
    pub id: String,
    /// What kind of thing the payload is: `"license"`, `"policy"`, `"model-artifact"`, `"software"`,
    /// or any string a deployment agrees on. A free string, not an enum, so a new kind of update never
    /// requires a new bundle-format release — the enclave decides what it will apply.
    pub kind: String,
    /// The payload's own version, opaque to this crate (the applier interprets it).
    pub version: String,
    /// When the bundle was signed, ms since the Unix epoch. Advisory (for the audit log); the signature,
    /// not the timestamp, is what authorizes the update.
    pub created_ms: u64,
    /// BLAKE3 of the payload, hex. The link between the signed manifest and the bytes — swapping the
    /// payload breaks this.
    pub payload_blake3: String,
    /// The payload's length in bytes, so truncation is caught even before hashing.
    pub payload_len: u64,
}

impl BundleManifest {
    /// The exact bytes that get signed. Deterministic (bincode over fixed-order scalar/string fields),
    /// or a signature would mean nothing.
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| BundleError::Codec {
            op: "encode",
            detail: format!("manifest: {e}"),
        })
    }
}

/// A signed offline update bundle: a described payload plus an Ed25519 signature over its description.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    /// The signed description.
    pub manifest: BundleManifest,
    /// The bytes being delivered.
    pub payload: Vec<u8>,
    /// Ed25519 signature over [`BundleManifest::signing_bytes`].
    pub ed25519: Vec<u8>,
}

impl Bundle {
    /// Build and sign a bundle around `payload`. Computes the payload hash, fills the manifest, and
    /// signs it with `key`. The caller supplies `created_ms` (the signing tool passes the wall clock).
    pub fn create(
        id: impl Into<String>,
        kind: impl Into<String>,
        version: impl Into<String>,
        created_ms: u64,
        payload: Vec<u8>,
        key: &SigningKey,
    ) -> Result<Bundle> {
        let payload_blake3 = blake3::hash(&payload).to_hex().to_string();
        let manifest = BundleManifest {
            format_version: FORMAT_VERSION,
            id: id.into(),
            kind: kind.into(),
            version: version.into(),
            created_ms,
            payload_blake3,
            payload_len: payload.len() as u64,
        };
        let signature = key.sign(&manifest.signing_bytes()?);
        Ok(Bundle {
            manifest,
            payload,
            ed25519: signature.to_bytes().to_vec(),
        })
    }

    /// Verify the bundle against a public key. Returns `Ok(())` only if the format is understood, the
    /// signature verifies over the manifest, AND the payload matches the hash the manifest commits to.
    ///
    /// A caller that gets `Ok(())` may apply the payload. Any `Err` means **do not apply it**.
    pub fn verify(&self, public: &VerifyingKey) -> Result<()> {
        if self.manifest.format_version != FORMAT_VERSION {
            return Err(BundleError::UnsupportedFormat {
                found: self.manifest.format_version,
                expected: FORMAT_VERSION,
            });
        }

        // Signature over the manifest first: if this fails, nothing the manifest says can be trusted,
        // including the hash we would otherwise check the payload against.
        let sig_bytes: [u8; 64] =
            self.ed25519
                .as_slice()
                .try_into()
                .map_err(|_| BundleError::SignatureLength {
                    len: self.ed25519.len(),
                })?;
        public
            .verify(
                &self.manifest.signing_bytes()?,
                &Signature::from_bytes(&sig_bytes),
            )
            .map_err(|_| BundleError::Signature)?;

        // Now the payload must match the hash the (now-trusted) manifest commits to — so a genuine
        // signature over one payload cannot be reused to bless a different one.
        let actual = blake3::hash(&self.payload).to_hex().to_string();
        if actual != self.manifest.payload_blake3 {
            return Err(BundleError::PayloadHashMismatch {
                expected: self.manifest.payload_blake3.clone(),
                actual,
            });
        }
        Ok(())
    }

    /// Verify authenticity and bind it to the exact artifact approved for this
    /// operation.
    ///
    /// A valid signature says that the release key signed *some* bundle. It
    /// does not by itself prevent a genuine policy, model, old software
    /// release, or differently named artifact from being supplied at the
    /// wrong update door. Production appliers must call this method with the
    /// id, kind, and version from the approved change record.
    pub fn verify_for(
        &self,
        public: &VerifyingKey,
        required_id: &str,
        required_kind: &str,
        required_version: &str,
    ) -> Result<()> {
        self.verify(public)?;
        require_claim("id", required_id, &self.manifest.id)?;
        require_claim("kind", required_kind, &self.manifest.kind)?;
        require_claim("version", required_version, &self.manifest.version)
    }

    /// Serialize the whole bundle to bytes for transport on physical media.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| BundleError::Codec {
            op: "encode",
            detail: e.to_string(),
        })
    }

    /// Parse a bundle from bytes. Does **not** verify it — call [`verify`](Self::verify) next.
    pub fn from_bytes(bytes: &[u8]) -> Result<Bundle> {
        bincode::deserialize(bytes).map_err(|e| BundleError::Codec {
            op: "decode",
            detail: e.to_string(),
        })
    }
}

fn require_claim(claim: &'static str, expected: &str, actual: &str) -> Result<()> {
    if expected == actual {
        return Ok(());
    }
    Err(BundleError::ClaimMismatch {
        claim,
        expected: expected.to_owned(),
        actual: actual.to_owned(),
    })
}

/// Load a 32-byte Ed25519 **signing** key from a hex string (64 hex chars). This is what the release
/// pipeline hands in from its secret slot; the string is read from a file path, never embedded.
pub fn signing_key_from_hex(hex_str: &str) -> Result<SigningKey> {
    let bytes = hex_decode(hex_str.trim(), "signing key")?;
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| BundleError::KeyLength {
            what: "signing",
            len: bytes.len(),
        })?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Load a 32-byte Ed25519 **verifying** (public) key from a hex string (64 hex chars). This is the key
/// the enclave holds and checks bundles against; it is safe to ship in the clear.
pub fn verifying_key_from_hex(hex_str: &str) -> Result<VerifyingKey> {
    let bytes = hex_decode(hex_str.trim(), "verifying key")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| BundleError::KeyLength {
            what: "verifying",
            len: bytes.len(),
        })?;
    VerifyingKey::from_bytes(&arr).map_err(|e| BundleError::Hex {
        what: "verifying key",
        detail: e.to_string(),
    })
}

/// Hex-encode bytes (lowercase). Used to write keys the pipeline stores as string secrets.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Two hex digits per byte. Boring on purpose.
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
    }
    s
}

fn hex_decode(s: &str, what: &'static str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(BundleError::Hex {
            what,
            detail: format!("odd number of hex digits ({})", s.len()),
        });
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char)
            .to_digit(16)
            .ok_or_else(|| BundleError::Hex {
                what,
                detail: format!("not a hex digit: {:?}", bytes[i] as char),
            })?;
        let lo = (bytes[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| BundleError::Hex {
                what,
                detail: format!("not a hex digit: {:?}", bytes[i + 1] as char),
            })?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev_key() -> SigningKey {
        // A fixed, throwaway dev key. Real bundles are signed with the production key the pipeline reads
        // from its secret slot — never a key that lives in the source tree.
        SigningKey::from_bytes(&[42u8; 32])
    }

    #[test]
    fn a_signed_bundle_round_trips_and_verifies() {
        let key = dev_key();
        let bundle = Bundle::create(
            "policy-2026-07",
            "policy",
            "3",
            1_700_000_000_000,
            b"the new policy bytes".to_vec(),
            &key,
        )
        .unwrap();

        // On-the-wire round trip preserves it, and it verifies against the matching public key.
        let bytes = bundle.to_bytes().unwrap();
        let parsed = Bundle::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, bundle);
        parsed.verify(&key.verifying_key()).unwrap();
    }

    #[test]
    fn a_swapped_payload_is_rejected_even_though_the_signature_is_genuine() {
        let key = dev_key();
        let mut bundle =
            Bundle::create("b", "software", "1", 0, b"real update".to_vec(), &key).unwrap();
        // Keep the genuine signature/manifest, swap the payload. The hash commitment must catch it.
        bundle.payload = b"malicious update".to_vec();
        match bundle.verify(&key.verifying_key()) {
            Err(BundleError::PayloadHashMismatch { .. }) => {}
            other => panic!("a swapped payload must be rejected, got {other:?}"),
        }
    }

    #[test]
    fn a_tampered_manifest_breaks_the_signature() {
        let key = dev_key();
        let mut bundle = Bundle::create("b", "license", "1", 0, b"x".to_vec(), &key).unwrap();
        bundle.manifest.version = "999".into(); // change a signed field
        match bundle.verify(&key.verifying_key()) {
            Err(BundleError::Signature) => {}
            other => panic!("a tampered manifest must fail the signature, got {other:?}"),
        }
    }

    #[test]
    fn the_wrong_public_key_rejects_a_genuine_bundle() {
        let bundle = Bundle::create("b", "policy", "1", 0, b"x".to_vec(), &dev_key()).unwrap();
        let other = SigningKey::from_bytes(&[7u8; 32]);
        match bundle.verify(&other.verifying_key()) {
            Err(BundleError::Signature) => {}
            other => panic!("the wrong key must reject, got {other:?}"),
        }
    }

    #[test]
    fn an_authentic_bundle_for_a_different_operation_is_refused() {
        let key = dev_key();
        let bundle = Bundle::create(
            "loomd-abc123",
            "software",
            "v1.2.3",
            0,
            b"binary".to_vec(),
            &key,
        )
        .unwrap();

        bundle
            .verify_for(&key.verifying_key(), "loomd-abc123", "software", "v1.2.3")
            .unwrap();

        for (id, kind, version, claim) in [
            ("loomd-other", "software", "v1.2.3", "id"),
            ("loomd-abc123", "policy", "v1.2.3", "kind"),
            ("loomd-abc123", "software", "v1.2.2", "version"),
        ] {
            match bundle.verify_for(&key.verifying_key(), id, kind, version) {
                Err(BundleError::ClaimMismatch { claim: actual, .. }) => assert_eq!(actual, claim),
                other => panic!("a wrong signed claim must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn hex_round_trips_and_loads_keys() {
        let key = dev_key();
        let hex = hex_encode(key.to_bytes().as_slice());
        assert_eq!(hex.len(), 64);
        let loaded = signing_key_from_hex(&hex).unwrap();
        assert_eq!(loaded.to_bytes(), key.to_bytes());
        // And the public key round-trips too.
        let pub_hex = hex_encode(key.verifying_key().as_bytes());
        let loaded_pub = verifying_key_from_hex(&pub_hex).unwrap();
        assert_eq!(loaded_pub.as_bytes(), key.verifying_key().as_bytes());
    }

    #[test]
    fn a_future_format_version_is_refused_not_guessed() {
        let key = dev_key();
        let mut bundle = Bundle::create("b", "software", "1", 0, b"x".to_vec(), &key).unwrap();
        bundle.manifest.format_version = FORMAT_VERSION + 1;
        // Re-sign so the signature is valid — the point is the version gate, not a bad signature.
        let sig = key.sign(&bundle.manifest.signing_bytes().unwrap());
        bundle.ed25519 = sig.to_bytes().to_vec();
        match bundle.verify(&key.verifying_key()) {
            Err(BundleError::UnsupportedFormat { found, expected }) => {
                assert_eq!(found, FORMAT_VERSION + 1);
                assert_eq!(expected, FORMAT_VERSION);
            }
            other => panic!("a newer format must be refused, got {other:?}"),
        }
    }
}
