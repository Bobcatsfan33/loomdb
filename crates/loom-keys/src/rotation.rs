//! Rotation as a sequence, not a swap.
//!
//! ```text
//!   expand          activate            (drill)          revoke
//!   ──────          ────────            ───────          ──────
//!   add the new     new → Active        sign and         old → Revoked
//!   key, Pending    old → Retired       verify with
//!                                       both
//! ```
//!
//! # Why four steps and not one
//!
//! Swapping a trust root in one move means there is an instant where some verifiers hold the new
//! key and some do not, and every artifact signed in that window verifies for only half the fleet.
//! The sequence removes that instant:
//!
//! * **expand** distributes the key while it authorizes nothing, so a verifier that has not caught
//!   up yet is not yet wrong;
//! * **activate** moves signing to the new key and the old key to `Retired`, where it still
//!   verifies — so last week's backups and yesterday's bundles keep verifying;
//! * the **drill** proves both halves before anything is thrown away;
//! * **revoke** is the only step that invalidates anything, and it is deliberately last and
//!   separately approved.
//!
//! Every step returns a **new** register. Nothing is mutated in place, so a failed step cannot leave
//! custody half-rotated.

use crate::{KeyError, KeyRole, KeyStatus, Result, TrustRoot, TrustRootRegister};

/// Stage a new trust root. It authorizes nothing until [`activate`].
///
/// Requires a generation strictly above every key already in the role, so a rotation cannot be
/// replayed backwards by re-presenting an older register.
pub fn expand(register: &TrustRootRegister, mut new_root: TrustRoot) -> Result<TrustRootRegister> {
    if register.find(new_root.role, &new_root.key_id).is_some() {
        return Err(KeyError::RegisterInvalid {
            detail: format!(
                "key id {:?} is already registered for the {} role",
                new_root.key_id, new_root.role
            ),
        });
    }
    let highest = register
        .in_role(new_root.role)
        .map(|root| root.generation)
        .max()
        .unwrap_or(0);
    if new_root.generation <= highest {
        return Err(KeyError::RegisterInvalid {
            detail: format!(
                "generation {} does not exceed the {} role's highest ({highest}); a rotation must \
                 move forward or it can be replayed backwards",
                new_root.generation, new_root.role
            ),
        });
    }
    // Staged, whatever the caller asked for. Expanding and trusting are separate acts and this
    // function performs only the first.
    new_root.status = KeyStatus::Pending;
    new_root.revocation_reason = None;

    let mut next = register.clone();
    next.roots.push(new_root);
    next.validate()?;
    Ok(next)
}

/// Promote a staged key to signing, and retire the key it supersedes.
///
/// Dual control applies here: this is the step that changes what signs.
pub fn activate(
    register: &TrustRootRegister,
    role: KeyRole,
    key_id: &str,
) -> Result<TrustRootRegister> {
    let candidate = register
        .find(role, key_id)
        .ok_or_else(|| KeyError::UnknownKeyId {
            key_id: key_id.to_string(),
            role,
        })?;
    if candidate.status != KeyStatus::Pending {
        return Err(KeyError::InvalidTransition {
            key_id: key_id.to_string(),
            from: candidate.status,
            to: KeyStatus::Active,
            detail: "only a staged key is activated; expand it first".into(),
        });
    }
    if !candidate.dual_control_satisfied() {
        return Err(KeyError::DualControlRequired {
            key_id: key_id.to_string(),
            status: KeyStatus::Active,
            approvals: candidate.ceremony.approvers().len(),
            required: 2,
        });
    }
    let generation = candidate.generation;

    let mut next = register.clone();
    for root in next.roots.iter_mut().filter(|root| root.role == role) {
        if root.key_id == key_id {
            root.status = KeyStatus::Active;
        } else if root.status == KeyStatus::Active {
            // The superseded key keeps verifying. Retiring it rather than revoking it is what stops
            // a rotation from invalidating every artifact signed before today.
            if root.generation >= generation {
                return Err(KeyError::InvalidTransition {
                    key_id: key_id.to_string(),
                    from: KeyStatus::Pending,
                    to: KeyStatus::Active,
                    detail: format!(
                        "generation {generation} does not exceed the active key {:?} at generation \
                         {}",
                        root.key_id, root.generation
                    ),
                });
            }
            root.status = KeyStatus::Retired;
        }
    }
    next.validate()?;
    Ok(next)
}

/// Stop a key signing while leaving it able to verify.
///
/// Useful on its own when a role is being wound down and nothing new should be signed for it.
pub fn retire(
    register: &TrustRootRegister,
    role: KeyRole,
    key_id: &str,
) -> Result<TrustRootRegister> {
    let candidate = register
        .find(role, key_id)
        .ok_or_else(|| KeyError::UnknownKeyId {
            key_id: key_id.to_string(),
            role,
        })?;
    if candidate.status != KeyStatus::Active {
        return Err(KeyError::InvalidTransition {
            key_id: key_id.to_string(),
            from: candidate.status,
            to: KeyStatus::Retired,
            detail: "only an active key retires".into(),
        });
    }
    let mut next = register.clone();
    for root in next.roots.iter_mut() {
        if root.role == role && root.key_id == key_id {
            root.status = KeyStatus::Retired;
        }
    }
    next.validate()?;
    Ok(next)
}

/// **Revoke a key. The only step that invalidates anything.**
///
/// `reason` is required and recorded: a revocation nobody can explain cannot be reviewed or
/// reversed. Revoking the last key that verifies for a role **seals** it — nothing signed for that
/// role will ever verify again — so it is refused unless the caller says that is what they mean.
/// That is a legitimate incident posture, and it must be deliberate.
pub fn revoke(
    register: &TrustRootRegister,
    role: KeyRole,
    key_id: &str,
    reason: &str,
    allow_seal: bool,
) -> Result<TrustRootRegister> {
    if reason.trim().is_empty() {
        return Err(KeyError::RegisterInvalid {
            detail: format!(
                "revoking {key_id:?} needs a recorded reason; an unexplained revocation cannot be \
                 reviewed or reversed"
            ),
        });
    }
    let candidate = register
        .find(role, key_id)
        .ok_or_else(|| KeyError::UnknownKeyId {
            key_id: key_id.to_string(),
            role,
        })?;
    if candidate.status == KeyStatus::Revoked {
        return Err(KeyError::InvalidTransition {
            key_id: key_id.to_string(),
            from: KeyStatus::Revoked,
            to: KeyStatus::Revoked,
            detail: "already revoked".into(),
        });
    }
    if !candidate.dual_control_satisfied() {
        return Err(KeyError::DualControlRequired {
            key_id: key_id.to_string(),
            status: KeyStatus::Revoked,
            approvals: candidate.ceremony.approvers().len(),
            required: 2,
        });
    }

    let survivors = register
        .in_role(role)
        .filter(|root| root.key_id != key_id && root.status.verifies())
        .count();
    if survivors == 0 && !allow_seal {
        return Err(KeyError::InvalidTransition {
            key_id: key_id.to_string(),
            from: candidate.status,
            to: KeyStatus::Revoked,
            detail: format!(
                "this is the last {role} key that verifies; revoking it seals the role and nothing \
                 signed for it will verify again. Rotate a replacement in first, or say explicitly \
                 that sealing is intended"
            ),
        });
    }

    let mut next = register.clone();
    for root in next.roots.iter_mut() {
        if root.role == role && root.key_id == key_id {
            root.status = KeyStatus::Revoked;
            root.revocation_reason = Some(reason.to_string());
        }
    }
    next.validate()?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::register::fixture::*;
    use crate::{Algorithm, Backend, KeyDirectory};
    use ed25519_dalek::Signer as _;

    const MESSAGE: &[u8] = b"an artifact signed before the rotation";

    fn pending(key_id: &str, generation: u64, seed: u8) -> TrustRoot {
        TrustRoot {
            key_id: key_id.into(),
            role: KeyRole::ActorGovernance,
            algorithm: Algorithm::Ed25519,
            public_key: crate::encode_hex(signing_key(seed).verifying_key().as_bytes()),
            backend: Backend::Software,
            status: KeyStatus::Pending,
            generation,
            ceremony: ceremony(&["pki-officer", "security-lead"]),
            revocation_reason: None,
        }
    }

    fn sign(seed: u8) -> Vec<u8> {
        signing_key(seed).sign(MESSAGE).to_bytes().to_vec()
    }

    fn directory(register: &TrustRootRegister) -> KeyDirectory {
        KeyDirectory::new(register.clone(), KeyRole::ActorGovernance).expect("valid")
    }

    /// **The whole sequence, and what each step changes about what verifies.**
    ///
    /// This is the drill: an artifact signed by the outgoing key before the rotation must keep
    /// verifying right up until the revoke step, and must stop the instant it lands.
    #[test]
    fn expand_activate_drill_revoke() {
        let old_artifact = sign(1);
        let start = register(vec![root(
            "gov-2026-q3",
            KeyRole::ActorGovernance,
            KeyStatus::Active,
            1,
            1,
        )]);
        assert_eq!(
            directory(&start)
                .verify_any(MESSAGE, &old_artifact)
                .expect("verifies")
                .key_id,
            "gov-2026-q3"
        );

        // EXPAND — the new key exists and authorizes nothing.
        let expanded = expand(&start, pending("gov-2026-q4", 2, 2)).expect("expands");
        assert!(matches!(
            directory(&expanded)
                .resolve("gov-2026-q4")
                .expect_err("staged"),
            KeyError::KeyNotTrusted { .. }
        ));
        assert_eq!(
            directory(&expanded).signing_root().expect("signer").key_id,
            "gov-2026-q3"
        );

        // ACTIVATE — signing moves; the old key retires and still verifies.
        let activated =
            activate(&expanded, KeyRole::ActorGovernance, "gov-2026-q4").expect("activates");
        assert_eq!(
            directory(&activated).signing_root().expect("signer").key_id,
            "gov-2026-q4"
        );
        assert_eq!(
            directory(&activated)
                .verify_any(MESSAGE, &old_artifact)
                .expect("still verifies")
                .key_id,
            "gov-2026-q3",
            "an artifact signed before the rotation must not stop verifying at activate"
        );

        // DRILL — the new key signs something and it verifies.
        let new_artifact = sign(2);
        assert_eq!(
            directory(&activated)
                .verify_any(MESSAGE, &new_artifact)
                .expect("verifies")
                .key_id,
            "gov-2026-q4"
        );

        // REVOKE — and only now does the old artifact stop verifying.
        let revoked = revoke(
            &activated,
            KeyRole::ActorGovernance,
            "gov-2026-q3",
            "superseded at the 2026-Q4 ceremony",
            false,
        )
        .expect("revokes");
        let error = directory(&revoked)
            .verify_any(MESSAGE, &old_artifact)
            .expect_err("refused");
        assert!(matches!(error, KeyError::NoTrustedKey { .. }), "{error}");
        assert_eq!(
            directory(&revoked)
                .verify_any(MESSAGE, &new_artifact)
                .expect("verifies")
                .key_id,
            "gov-2026-q4"
        );
    }

    #[test]
    fn a_rotation_cannot_be_replayed_backwards() {
        let start = register(vec![root(
            "gov-b",
            KeyRole::ActorGovernance,
            KeyStatus::Active,
            5,
            1,
        )]);
        let error = expand(&start, pending("gov-a", 4, 2)).expect_err("must refuse");
        assert!(format!("{error}").contains("does not exceed"), "{error}");
    }

    #[test]
    fn a_staged_key_must_be_expanded_before_it_is_activated() {
        let start = register(vec![root(
            "gov-a",
            KeyRole::ActorGovernance,
            KeyStatus::Active,
            1,
            1,
        )]);
        assert!(matches!(
            activate(&start, KeyRole::ActorGovernance, "gov-a").expect_err("already active"),
            KeyError::InvalidTransition { .. }
        ));
        assert!(matches!(
            activate(&start, KeyRole::ActorGovernance, "nobody").expect_err("unknown"),
            KeyError::UnknownKeyId { .. }
        ));
    }

    /// One person cannot promote or revoke a key.
    #[test]
    fn dual_control_gates_activate_and_revoke() {
        let start = register(vec![root(
            "gov-a",
            KeyRole::ActorGovernance,
            KeyStatus::Active,
            1,
            1,
        )]);
        let mut lone = pending("gov-b", 2, 2);
        lone.ceremony = ceremony(&["pki-officer"]);
        let expanded = expand(&start, lone).expect("staging needs no dual control");
        assert!(matches!(
            activate(&expanded, KeyRole::ActorGovernance, "gov-b").expect_err("one approver"),
            KeyError::DualControlRequired { required: 2, .. }
        ));

        let mut solo = root("gov-c", KeyRole::ActorGovernance, KeyStatus::Retired, 1, 3);
        solo.ceremony = ceremony(&["pki-officer"]);
        let two = register(vec![
            root("gov-a", KeyRole::ActorGovernance, KeyStatus::Active, 2, 1),
            solo,
        ]);
        assert!(matches!(
            revoke(&two, KeyRole::ActorGovernance, "gov-c", "why", false)
                .expect_err("one approver"),
            KeyError::DualControlRequired { .. }
        ));
    }

    /// **Sealing a role must be deliberate.** Revoking the last key that verifies means nothing
    /// signed for that role will ever verify again.
    #[test]
    fn revoking_the_last_verifying_key_seals_the_role_and_is_refused_by_default() {
        let start = register(vec![root(
            "gov-a",
            KeyRole::ActorGovernance,
            KeyStatus::Active,
            1,
            1,
        )]);
        let error = revoke(
            &start,
            KeyRole::ActorGovernance,
            "gov-a",
            "compromised",
            false,
        )
        .expect_err("must refuse");
        assert!(format!("{error}").contains("seals the role"), "{error}");

        // ...but it is available as an explicit incident posture.
        let sealed = revoke(
            &start,
            KeyRole::ActorGovernance,
            "gov-a",
            "compromised",
            true,
        )
        .expect("sealing is allowed when it is what you mean");
        let error = directory(&sealed)
            .verify_any(MESSAGE, &sign(1))
            .expect_err("sealed");
        assert!(
            matches!(error, KeyError::NoTrustedKey { tried: 0, .. }),
            "{error}"
        );
    }

    #[test]
    fn a_revocation_records_its_reason() {
        let start = register(vec![
            root("gov-a", KeyRole::ActorGovernance, KeyStatus::Active, 2, 1),
            root(
                "gov-old",
                KeyRole::ActorGovernance,
                KeyStatus::Retired,
                1,
                3,
            ),
        ]);
        assert!(revoke(&start, KeyRole::ActorGovernance, "gov-old", "   ", false).is_err());
        let revoked = revoke(
            &start,
            KeyRole::ActorGovernance,
            "gov-old",
            "ceremony 2026-Q4",
            false,
        )
        .expect("revokes");
        let entry = revoked
            .find(KeyRole::ActorGovernance, "gov-old")
            .expect("present");
        assert_eq!(entry.revocation_reason.as_deref(), Some("ceremony 2026-Q4"));
    }

    #[test]
    fn revoking_twice_is_refused() {
        let start = register(vec![
            root("gov-a", KeyRole::ActorGovernance, KeyStatus::Active, 2, 1),
            root(
                "gov-old",
                KeyRole::ActorGovernance,
                KeyStatus::Revoked,
                1,
                3,
            ),
        ]);
        assert!(matches!(
            revoke(&start, KeyRole::ActorGovernance, "gov-old", "again", false)
                .expect_err("already revoked"),
            KeyError::InvalidTransition { .. }
        ));
    }

    #[test]
    fn retire_stops_signing_without_stopping_verification() {
        let start = register(vec![root(
            "gov-a",
            KeyRole::ActorGovernance,
            KeyStatus::Active,
            1,
            1,
        )]);
        let retired = retire(&start, KeyRole::ActorGovernance, "gov-a").expect("retires");
        assert!(directory(&retired).signing_root().is_err());
        assert_eq!(
            directory(&retired)
                .verify_any(MESSAGE, &sign(1))
                .expect("verifies")
                .key_id,
            "gov-a"
        );
    }

    #[test]
    fn expanding_a_duplicate_key_id_is_refused() {
        let start = register(vec![root(
            "gov-a",
            KeyRole::ActorGovernance,
            KeyStatus::Active,
            1,
            1,
        )]);
        let mut duplicate = pending("gov-a", 2, 2);
        duplicate.key_id = "gov-a".into();
        assert!(expand(&start, duplicate).is_err());
    }

    /// Rotation never mutates in place: a refused step leaves the caller's register untouched.
    #[test]
    fn a_refused_step_leaves_the_register_unchanged() {
        let start = register(vec![root(
            "gov-a",
            KeyRole::ActorGovernance,
            KeyStatus::Active,
            1,
            1,
        )]);
        let before = start.clone();
        let _ = expand(&start, pending("gov-a", 0, 2));
        let _ = revoke(&start, KeyRole::ActorGovernance, "gov-a", "", false);
        assert_eq!(start, before);
    }
}
