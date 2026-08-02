//! The incident path, as a scripted tabletop.
//!
//! # What is being exercised, and what is not
//!
//! The **content** of a notification is derivable from a drill receipt: what was lost, how far back
//! the recovery point sat, how long recovery took, which backup was consumed, which trust root
//! verified it. Generating that from measured facts rather than from a template someone fills in at
//! 3am is a real thing to test, and it is what this module does.
//!
//! What is **not** exercised, and cannot be from here: a named on-call rota, a paging system that
//! actually pages, a customer-communications channel with someone accountable for it, and the
//! judgement about whether an incident is notifiable at all. Those are `EXT-OPERATIONS` and stay
//! open. This module produces the text; it does not send it, and nothing here should be read as
//! evidence that anybody would receive it.
//!
//! # Why generate rather than template
//!
//! A notification that says "recovery completed within objectives" is worth nothing to the person
//! reading it, and is exactly the sentence that gets written when the numbers were never measured.
//! Every figure below comes out of the receipt, including the ones that are unflattering.

use crate::receipt::{human_bytes, human_duration, DrillReceipt};

/// Who a notification is for. Different audiences are owed different things.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audience {
    /// The people fixing it. Wants identifiers and next actions.
    Operations,
    /// The affected tenant. Wants the window of lost work and what to do about it.
    Customer,
}

/// A generated notification: a subject, a body, and the facts it was derived from.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Notification {
    /// Who it is for.
    pub audience: String,
    /// Subject line.
    pub subject: String,
    /// Body text.
    pub body: String,
    /// **Whether this was actually sent to anyone.** Always false here, and present so a generated
    /// artifact can never be mistaken for a delivered one.
    pub delivered: bool,
    /// What delivery would require, recorded beside the artifact that lacks it.
    pub delivery_requires: Vec<String>,
}

/// Generate the notification content a drill's facts support.
pub fn notify(receipt: &DrillReceipt, audience: Audience) -> Notification {
    let lost = &receipt.recovery_point;
    let took = &receipt.recovery_time;
    let (name, subject, body) = match audience {
        Audience::Operations => (
            "operations",
            format!(
                "[DRILL] loomDB recovery exercise — tenant {} — {} topology",
                receipt.tenant,
                receipt.topology.as_str()
            ),
            format!(
                "This is a DRILL. No production system was affected.\n\
                 \n\
                 Tenant:            {tenant}\n\
                 Topology:          {topology}\n\
                 Signer backend:    {backend}\n\
                 \n\
                 Recovery point:    {rp} of work was not in the clone in this drill{rp_verdict}\n\
                 Production RPO:    bounded by the backup interval, {rp_bound} (target \
                 {rp_target}) - the drill measures the boundary, not the interval\n\
                 Recovery time:     {rt} to a verified, attested, servable store on {bytes} \
                 (target {rt_target}){rt_verdict}\n\
                 \n\
                 Backup consumed:   {backup}\n\
                 Manifest BLAKE3:   {digest}\n\
                 Verified by:       trust root {key} ({role} role)\n\
                 Restored heads:    {heads}\n\
                 Integrity:         {integrity}\n\
                 Known-answer:      {ka_pass}/{ka_total} matched\n\
                 Faults injected:   {faults} — all refused: {faults_ok}\n\
                 \n\
                 Not exercised by this topology:\n{not_exercised}\n",
                tenant = receipt.tenant,
                topology = receipt.topology.as_str(),
                backend = receipt.backend,
                rp = lost.human,
                rp_target = human_duration(lost.target_seconds as f64),
                rp_bound = human_duration(receipt.recovery_point_bounded_by_seconds as f64),
                rp_verdict = verdict(lost.within_target),
                rt = took.human,
                rt_target = human_duration(took.target_seconds as f64),
                rt_verdict = verdict(took.within_target),
                bytes = human_bytes(receipt.restored_bytes),
                backup = receipt.backup.name,
                digest = receipt.backup.manifest_blake3,
                key = receipt.backup.verified_by_key_id,
                role = receipt.backup.verified_by_role,
                heads = receipt
                    .restored_heads
                    .iter()
                    .map(|(branch, head)| format!("{branch}={}", &head[..head.len().min(12)]))
                    .collect::<Vec<_>>()
                    .join(" "),
                integrity = if receipt.integrity_healthy {
                    "clean"
                } else {
                    "DAMAGED"
                },
                ka_pass = receipt
                    .known_answers
                    .iter()
                    .filter(|answer| answer.matched)
                    .count(),
                ka_total = receipt.known_answers.len(),
                faults = receipt.faults.len(),
                faults_ok = receipt.faults.iter().all(|fault| fault.refused),
                not_exercised = receipt
                    .not_exercised
                    .iter()
                    .map(|item| format!("  - {item}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
        ),
        Audience::Customer => (
            "customer",
            format!("[DRILL] Recovery exercise for {}", receipt.tenant),
            format!(
                "This is a DRILL. Your data was not affected and no action is required.\n\
                 \n\
                 Had this been real, the recovery would have restored your data to the most recent \
                 backup. Backups are taken every {rp_bound}, so up to that much recent work would \
                 not have been recovered and would need to be re-entered.\n\
                 \n\
                 Service was restored to a verified state in {rt}.\n\
                 \n\
                 The restored data was checked against its cryptographic signature before being \
                 brought back, and its integrity was verified as {integrity}.\n",
                rp_bound = human_duration(receipt.recovery_point_bounded_by_seconds as f64),
                rt = took.human,
                integrity = if receipt.integrity_healthy {
                    "intact"
                } else {
                    "DAMAGED"
                },
            ),
        ),
    };

    Notification {
        audience: name.to_string(),
        subject,
        body,
        // Never true from this module. Generating text and delivering it are different acts, and
        // only one of them is in scope here.
        delivered: false,
        delivery_requires: vec![
            "a named on-call rota with contracted response targets".into(),
            "a paging system wired to that rota".into(),
            "a customer-communications channel with an accountable owner".into(),
            "a documented decision on whether an incident is notifiable".into(),
            "all of the above are EXT-OPERATIONS and remain open".into(),
        ],
    }
}

fn verdict(within: bool) -> &'static str {
    if within {
        ""
    } else {
        " — OVER TARGET"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{
        BackupConsumed, KnownAnswer, Measured, Topology, RPO_TARGET_SECONDS, RTO_TARGET_SECONDS,
    };

    fn receipt() -> DrillReceipt {
        let mut heads = std::collections::BTreeMap::new();
        heads.insert("main".to_string(), "abcdef0123456789".to_string());
        let mut receipt = DrillReceipt {
            schema_version: crate::RECEIPT_SCHEMA_VERSION,
            topology: Topology::LocalFilesystemCopyClone,
            not_exercised: Topology::LocalFilesystemCopyClone
                .not_exercised()
                .iter()
                .map(ToString::to_string)
                .collect(),
            backend: "software".into(),
            tenant: "acme".into(),
            clone_taken_unix: 1_800_000_000,
            failure_unix: 1_800_001_560,
            recovery_point: Measured::new(1560.0, RPO_TARGET_SECONDS),
            recovery_point_bounded_by_seconds: 86_400,
            recovery_time: Measured::new(252.0, RTO_TARGET_SECONDS),
            backup: BackupConsumed {
                name: "acme-1800000000".into(),
                manifest_blake3: "deadbeef".into(),
                verified_by_key_id: "backup-2026-q3".into(),
                verified_by_role: "backup-root".into(),
                files: 12,
                bytes: 4096,
                signed_payload_bytes: 1200,
                fits_kms_raw_sign_limit: true,
                signature_format_version: 2,
            },
            restored_heads: heads,
            integrity_healthy: true,
            attested_open: true,
            known_answers: vec![KnownAnswer::compare("head", "a", "a")],
            faults: Vec::new(),
            restored_bytes: 2_254_857_830,
            all_checks_held: false,
        };
        receipt.evaluate();
        receipt
    }

    /// **Every figure comes out of the receipt.** A notification that could be written without the
    /// measurements is a notification that will be.
    #[test]
    fn the_operations_notification_carries_the_measured_numbers() {
        let notification = notify(&receipt(), Audience::Operations);
        assert!(
            notification.body.contains("26m00.00s"),
            "{}",
            notification.body
        );
        assert!(
            notification.body.contains("4m12.00s"),
            "{}",
            notification.body
        );
        assert!(
            notification.body.contains("2.10 GiB"),
            "{}",
            notification.body
        );
        assert!(
            notification.body.contains("backup-2026-q3"),
            "{}",
            notification.body
        );
        assert!(
            notification.body.contains("deadbeef"),
            "{}",
            notification.body
        );
    }

    /// The customer is told the window of work they lost, in their terms, without a verdict.
    /// The customer is told the window in the terms that actually bound it — the backup interval,
    /// not how fast a drill happened to run on a laptop.
    #[test]
    fn the_customer_notification_names_the_lost_window() {
        let notification = notify(&receipt(), Audience::Customer);
        assert!(
            notification.body.contains("24h00m00.00s"),
            "{}",
            notification.body
        );
        assert!(notification.body.contains("would need to be re-entered"));
        assert!(!notification.body.contains("within objectives"));
    }

    /// **A generated notification is never a delivered one.**
    #[test]
    fn nothing_generated_here_claims_to_have_been_sent() {
        for audience in [Audience::Operations, Audience::Customer] {
            let notification = notify(&receipt(), audience);
            assert!(!notification.delivered);
            assert!(notification
                .delivery_requires
                .iter()
                .any(|item| item.contains("EXT-OPERATIONS")));
            assert!(notification.subject.starts_with("[DRILL]"));
        }
    }

    /// A number over target is stated, not softened.
    #[test]
    fn an_over_target_measurement_is_called_out() {
        let mut over = receipt();
        over.recovery_time = Measured::new(5.0 * 3600.0, RTO_TARGET_SECONDS);
        let notification = notify(&over, Audience::Operations);
        assert!(
            notification.body.contains("OVER TARGET"),
            "{}",
            notification.body
        );
    }

    /// The topology's blind spots travel with the notification.
    #[test]
    fn the_notification_carries_what_the_topology_did_not_exercise() {
        let notification = notify(&receipt(), Audience::Operations);
        assert!(notification.body.contains("customer-scale data volumes"));
        assert!(notification.body.contains("CSI volume snapshots"));
    }
}
