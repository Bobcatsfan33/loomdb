//! **What became of the provisioned KMS keys, checked rather than described.**
//!
//! This file used to assert that `deploy/reference/trust-roots/production.json` named two real AWS
//! KMS key ARNs, carried their exported public halves, and held both at `pending` so they authorized
//! nothing before a ceremony.
//!
//! On **2026-08-08 the AWS account was closed and both keys were destroyed with it.** No dual-control
//! ceremony was ever held, neither key was ever activated, and neither ever signed a release.
//!
//! The register was **removed**, not edited to say `revoked`. `loom-keys` refuses at load time to
//! accept a revoked entry with no recorded approvers — revocation is a decision somebody signs for —
//! so making the file load again would have meant inventing two approvers for a ceremony that never
//! happened. That is the exact failure this subsystem exists to prevent, so the file went instead.
//!
//! What these tests hold in place is the *record*: the exported public halves are still here and
//! still match the hashes from the provisioning receipt, and the receipt still says the keys were
//! decommissioned. Both are easy to lose by accident — a cleanup that deletes "unused" DER files, or
//! an edit that quietly drops the decommissioning note and leaves a reader thinking those keys are
//! live.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// **There is no committed production trust-root register, and there should not be.**
///
/// If this fails, someone has committed a register for a trust root that does not exist. Either the
/// keys are real again — in which case the round-trip receipt and `docs/key-custody.md` §5 need
/// updating in the same change — or the file is a fabrication.
#[test]
fn no_production_trust_root_register_is_committed() {
    let register = repo_root().join("deploy/reference/trust-roots/production.json");
    assert!(
        !register.exists(),
        "deploy/reference/trust-roots/production.json is back. The KMS keys it named were destroyed \
         with the AWS account on 2026-08-08. If a real trust root exists again, say so in \
         docs/key-custody.md §5 and docs/drills/kms-roundtrip.json in the same change; if not, this \
         file names keys nobody holds."
    );
    let readme = repo_root().join("deploy/reference/trust-roots/README.md");
    assert!(
        readme.is_file(),
        "the directory must explain why it holds no register"
    );
}

/// The exported public halves are retained, and still hash to what the provisioning receipt recorded.
///
/// The private halves are gone, so these prove no live capability. They keep the *record* checkable:
/// anyone can confirm the SPKI hashes in `docs/drills/kms-roundtrip.json` describe these exact bytes.
#[test]
fn the_exported_public_halves_are_retained_and_unaltered() {
    // (der file, the Ed25519 public key it carries, the SPKI SHA-256 in the provisioning record)
    //
    // The raw key is pinned rather than recomputing the SHA-256 here: `loom-keys` has no hash
    // dependency and a test-only shell-out to `shasum`/`sha256sum` is a portability trap for the
    // sake of a value that never changes. Equal bytes imply an equal digest, and the digest itself
    // is pinned as a string so the receipt and these files cannot drift apart silently. The pairing
    // was confirmed by hand: sha256(actor-governance-pub.der) = 3d9bb68a…, and
    // sha256(release-signing-pub.der) = 7570462a…, matching the 2026-08-02 record.
    const PROVISIONED: &[(&str, &str, &str)] = &[
        (
            "actor-governance-pub.der",
            "79508603b6c2abf19fd47dad88a6a77ec9ce088ed525cab11d93f270f0c5b8cd",
            "3d9bb68ae2ed17b0190c0038c965440f6825f7ea17677a4842ca7f14b99bb9d6",
        ),
        (
            "release-signing-pub.der",
            "848e66eceb8800841cb7577a648d1c79ac9c944040e3d1b36dfb5978c705e0ef",
            "7570462a00fd47f356c3ae5e4488579f8fbf981e9507d0267b156854810133fa",
        ),
    ];
    // RFC 8410 Ed25519 SubjectPublicKeyInfo: SEQ{ SEQ{ OID 1.3.101.112 }, BITSTRING{ 00 || key } }
    const SPKI_PREFIX: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    let receipt: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("docs/drills/kms-roundtrip.json"))
            .expect("the round-trip receipt is retained"),
    )
    .expect("valid JSON");

    for (index, (der_name, expected_key, expected_hash)) in PROVISIONED.iter().enumerate() {
        let path = repo_root()
            .join("deploy/reference/trust-roots")
            .join(der_name);
        let der = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("{der_name} is retained as evidence: {error}"));

        assert_eq!(der.len(), 44, "{der_name}: not a 44-byte Ed25519 SPKI");
        assert_eq!(&der[..12], SPKI_PREFIX, "{der_name}: not an Ed25519 SPKI");

        let carried: String = der[12..].iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            &carried, expected_key,
            "{der_name}: the retained public half has been altered"
        );

        assert_eq!(
            receipt["keys"][index]["spkiSha256"],
            serde_json::json!(expected_hash),
            "{der_name}: the receipt's recorded SPKI hash no longer matches the provisioning record"
        );
    }
}

/// The round-trip receipt must keep saying the keys were decommissioned.
///
/// Without this, the file reads as a live capability: two provisioned KMS keys, signatures verified
/// offline, everything PASS. It is all true, and all about keys that no longer exist.
#[test]
fn the_kms_receipt_records_that_the_keys_were_destroyed() {
    let path = repo_root().join("docs/drills/kms-roundtrip.json");
    let body = std::fs::read_to_string(&path).expect("the round-trip receipt is retained");
    let receipt: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    let decommissioned = receipt
        .get("decommissioned")
        .expect("the receipt must record what became of these keys, not just that they worked");

    assert_eq!(decommissioned["ceremonyHeld"], serde_json::json!(false));
    assert_eq!(decommissioned["everActivated"], serde_json::json!(false));
    assert_eq!(
        decommissioned["everSignedARelease"],
        serde_json::json!(false)
    );
    assert_eq!(decommissioned["onDate"], serde_json::json!("2026-08-08"));
    assert!(
        decommissioned["replacedBy"]
            .as_str()
            .is_some_and(|text| text.contains("SOFTWARE-BACKED")),
        "the receipt must say what replaced these keys, and that it is weaker custody"
    );
}
