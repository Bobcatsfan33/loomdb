//! **Golden bytes: the signed bundle format, pinned.**
//!
//! Companion to `crates/loom-branch/tests/golden_format.rs`, which carries the reasoning and the
//! format contract in full. The short version: bincode 1.3 is unmaintained (RUSTSEC-2025-0141,
//! issue #50), and the ordinary test suite cannot tell a compatible successor from an incompatible
//! one, because it writes and reads with the same build.
//!
//! What is at stake **here** is not a database on disk — it is a signature. `BundleManifest`'s
//! bincode encoding is the exact Ed25519 payload for an offline update bundle, so a serializer whose
//! output differs by one byte invalidates every bundle already cut and shipped on physical media.
//! Those cannot be re-signed by anyone downstream. `Bundle::to_bytes` is the transport form the media
//! actually carry.
//!
//! ```text
//! LOOMDB_UPDATE_GOLDEN=1 cargo test -p loom-bundle --test golden_format
//! ```

use std::path::PathBuf;

use ed25519_dalek::{Signer, SigningKey};

use loom_bundle::{Bundle, BundleManifest, FORMAT_VERSION};

mod fixture;
use fixture::{Case, Fixtures};

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/format-v1.golden")
}

/// A fixed key, so the fixture is reproducible. Test-only, and obviously so.
fn key() -> SigningKey {
    SigningKey::from_bytes(&[3u8; 32])
}

fn a_manifest(payload: &[u8]) -> BundleManifest {
    BundleManifest {
        format_version: FORMAT_VERSION,
        id: "policy-2026-07".to_string(),
        kind: "policy".to_string(),
        // Multi-byte UTF-8 in a signed string: the length prefix counts bytes, not characters.
        version: "0.1.0-café".to_string(),
        created_ms: 1_700_000_000_000,
        payload_blake3: blake3::hash(payload).to_hex().to_string(),
        payload_len: payload.len() as u64,
    }
}

fn cases() -> Vec<Case> {
    let payload = b"the payload".to_vec();
    let manifest = a_manifest(&payload);
    let empty_manifest = BundleManifest {
        format_version: FORMAT_VERSION,
        id: String::new(),
        kind: String::new(),
        version: String::new(),
        created_ms: 0,
        payload_blake3: String::new(),
        payload_len: 0,
    };
    let bundle = Bundle::create(
        "policy-2026-07",
        "policy",
        "0.1.0-caf\u{e9}",
        1_700_000_000_000,
        payload,
        &key(),
    )
    .expect("create");
    let empty_bundle =
        Bundle::create("empty", "policy", "0", 0, Vec::new(), &key()).expect("create");

    vec![
        Case::new(
            "bundle_manifest",
            "loom_bundle::BundleManifest",
            "the Ed25519 signing payload — seven fields, no field names on the wire",
            manifest.clone(),
            bincode::serialize(&manifest).expect("encode"),
        ),
        Case::new(
            "bundle_manifest_empty",
            "loom_bundle::BundleManifest",
            "every string empty — four bare 8-byte zero length prefixes",
            empty_manifest.clone(),
            bincode::serialize(&empty_manifest).expect("encode"),
        ),
        Case::new(
            "bundle_transport",
            "loom_bundle::Bundle",
            "the whole bundle as it travels on physical media: manifest, payload, 64-byte signature",
            bundle.clone(),
            bundle.to_bytes().expect("to_bytes"),
        ),
        Case::new(
            "bundle_transport_empty_payload",
            "loom_bundle::Bundle",
            "a zero-length payload — the length prefix with nothing after it",
            empty_bundle.clone(),
            empty_bundle.to_bytes().expect("to_bytes"),
        ),
    ]
}

/// **The gate.** Every case, both directions, in one report.
#[test]
fn the_signed_bundle_format_has_not_changed() {
    let cases = cases();
    let path = path();

    if fixture::updating() {
        Fixtures::write(&path, &cases).expect("write fixtures");
        eprintln!("regenerated {} ({} cases)", path.display(), cases.len());
        return;
    }

    let fixtures = Fixtures::load(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}\nIf you are ADDING a case, run:\n  \
             LOOMDB_UPDATE_GOLDEN=1 cargo test -p loom-bundle --test golden_format",
            path.display()
        )
    });
    fixtures.check_all(&cases, "loom-bundle");
}

/// **The manifest fixture, bound to the real signing path.**
///
/// `BundleManifest::signing_bytes` is private, so prove it the other way round: sign the
/// **committed** bytes with the fixed key, put that signature on a bundle, and require `verify` to
/// accept it. It does so only if `signing_bytes()` still produces exactly the committed fixture — a
/// serializer change where `create` and `verify` merely agree with *each other* fails here.
#[test]
fn a_signature_over_the_committed_bytes_still_verifies() {
    if fixture::updating() {
        return; // the fixture is (re)written by the gate test in the same run
    }

    let payload = b"the payload".to_vec();
    let committed = Fixtures::load(&path())
        .expect("fixtures")
        .bytes("bundle_manifest");

    let bundle = Bundle {
        manifest: a_manifest(&payload),
        payload,
        ed25519: key().sign(&committed).to_bytes().to_vec(),
    };

    bundle.verify(&key().verifying_key()).expect(
        "a signature over the COMMITTED manifest bytes must still verify: if this fails, \
         BundleManifest::signing_bytes no longer produces the pinned encoding and every bundle \
         already shipped on physical media is now unverifiable",
    );

    // And the binding is real: the same signature over a different payload is still refused.
    let tampered = Bundle {
        payload: b"a different payload".to_vec(),
        ..bundle
    };
    assert!(tampered.verify(&key().verifying_key()).is_err());
}
