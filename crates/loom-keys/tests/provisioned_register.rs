//! The committed production trust-root register, checked against the keys AWS actually holds.
//!
//! These entries name **real** KMS key ARNs and carry the public halves exported from them. The
//! register is committed because public keys are not secret and because a verifier must be able to
//! check a signature with no network — which is only true if the key material travels with the
//! deployment rather than being fetched.
//!
//! Both keys are `pending`: created and distributed, authorizing nothing. That is the honest state
//! before a dual-control ceremony, and it is why `EXT-HSM` is still open — the register says so
//! structurally rather than in prose a reader has to find.

use loom_keys::{Backend, KeyDirectory, KeyError, KeyRole, KeyStatus, TrustRootRegister};

fn register() -> TrustRootRegister {
    TrustRootRegister::load(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/reference/trust-roots/production.json"
    )))
    .expect("the committed register loads and validates")
}

/// The public key in the register must be the one the DER file carries, and the DER file must be
/// the one AWS exported — pinned by the SPKI hash from the provisioning record.
#[test]
fn every_registered_key_matches_its_exported_der_and_the_provisioned_hash() {
    const PROVISIONED: &[(&str, &str, &str)] = &[
        (
            "actor-governance",
            "actor-governance-pub.der",
            "3d9bb68ae2ed17b0190c0038c965440f6825f7ea17677a4842ca7f14b99bb9d6",
        ),
        (
            "release",
            "release-signing-pub.der",
            "7570462a00fd47f356c3ae5e4488579f8fbf981e9507d0267b156854810133fa",
        ),
    ];
    // RFC 8410 Ed25519 SubjectPublicKeyInfo: SEQ{ SEQ{ OID 1.3.101.112 }, BITSTRING{ 00 || key } }
    const SPKI_PREFIX: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    let register = register();
    for (role_name, der_name, expected_hash) in PROVISIONED {
        let der = std::fs::read(format!(
            "{}/../../deploy/reference/trust-roots/{der_name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("the exported public key is committed beside the register");

        assert_eq!(
            blake3_free_sha256(&der),
            *expected_hash,
            "{der_name}: the committed DER is not the one AWS exported"
        );
        assert_eq!(der.len(), 44, "{der_name}: not a 44-byte Ed25519 SPKI");
        assert_eq!(&der[..12], SPKI_PREFIX, "{der_name}: not an Ed25519 SPKI");

        let role = match *role_name {
            "actor-governance" => KeyRole::ActorGovernance,
            "release" => KeyRole::Release,
            other => panic!("unexpected role {other}"),
        };
        let root = register
            .in_role(role)
            .next()
            .unwrap_or_else(|| panic!("{role_name} is registered"));
        assert_eq!(
            root.public_key,
            der[12..]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "{role_name}: the register's public key is not the exported one"
        );
        assert_eq!(root.backend, Backend::AwsKms);
        assert!(root
            .key_id
            .starts_with("arn:aws:kms:us-east-1:913524920694:key/"));
    }
}

/// **EXT-HSM is open, and the register encodes that rather than asserting it.**
///
/// Provisioning a key and trusting it are different acts. No dual-control ceremony has been held, so
/// both entries are `pending`: they authorize nothing, they cannot sign, and a signature made by
/// either would not verify through this directory.
#[test]
fn the_provisioned_keys_authorize_nothing_until_the_ceremony() {
    let register = register();
    for root in &register.roots {
        assert_eq!(root.status, KeyStatus::Pending, "{}", root.key_id);
        assert!(!root.status.verifies() && !root.status.signs());
        assert!(
            root.ceremony.approvals.is_empty(),
            "no approvals may be recorded before a ceremony has been held"
        );
    }
    for role in [KeyRole::ActorGovernance, KeyRole::Release] {
        let directory = KeyDirectory::new(register.clone(), role).expect("valid");
        assert!(
            matches!(
                directory.signing_root(),
                Err(KeyError::NoActiveSigner { .. })
            ),
            "{role} must have no active signer before the ceremony"
        );
        assert!(directory.trusted().is_empty(), "{role} trusts nothing yet");
    }
}

/// Activating either key requires two distinct approvers — the ceremony, expressed as a check.
#[test]
fn activation_requires_the_dual_control_ceremony() {
    let register = register();
    let error = loom_keys::activate(
        &register,
        KeyRole::ActorGovernance,
        "arn:aws:kms:us-east-1:913524920694:key/e8f90cea-7da1-4c58-b527-fe91b9a93747",
    )
    .expect_err("activation without approvals must be refused");
    assert!(
        matches!(
            error,
            KeyError::DualControlRequired {
                required: 2,
                approvals: 0,
                ..
            }
        ),
        "{error}"
    );
}

/// backup-root is deliberately absent: its key is created in phase 2, after the digest-signing
/// format lands. A register entry for a key that does not exist would be a lie.
#[test]
fn backup_root_is_not_yet_registered() {
    assert_eq!(register().in_role(KeyRole::BackupRoot).count(), 0);
}

fn blake3_free_sha256(bytes: &[u8]) -> String {
    // A tiny SHA-256 so this test needs no new dependency: it pins an external fact (what AWS
    // exported) and must not be able to drift with a hashing crate upgrade.
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("shasum")
        .args(["-a", "256"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("shasum is available");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(bytes)
        .expect("write");
    let out = child.wait_with_output().expect("shasum runs");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string()
}
