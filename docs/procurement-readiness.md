# Enterprise procurement and deployment decision

The authoritative buyer-facing index is
[`enterprise-readiness.json`](enterprise-readiness.json). It names the exact repository evidence for
each control domain, the inherited deployment responsibilities, every blocking external gate, and an
expiry date. CI validates the index on every change and fails if evidence is missing, symlinked, stale,
internally inconsistent, or represented as approved while a blocking gate remains open.

The current decision is **not approved for a Fortune 500 production deployment**. The software is a
release candidate, not a completed vendor-risk decision. Commissioned penetration testing,
customer-topology RPO/RTO proof, non-exportable HSM/KMS custody, staffed support/incident operations,
and the buyer-required organizational and contractual package remain external gates. No repository
test can manufacture those approvals.

## Evaluation baseline

The evidence index is organized for the review methods commonly requested during large-enterprise
software acquisition:

- [NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final) for secure development and supplier
  evidence;
- [SLSA 1.2](https://slsa.dev/spec/v1.2/) for build provenance and release integrity;
- [OWASP ASVS 5.0.0](https://owasp.org/www-project-application-security-verification-standard/) as
  the technical application-security verification baseline for any host API or management plane;
- [CSA CCM/CAIQ 4.1](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) and
  [AI-CAIQ 1.0.2](https://cloudsecurityalliance.org/artifacts/ai-consensus-assessments-initiative-questionnaire-ai-caiq)
  for cloud/shared-responsibility and AI vendor questionnaires; and
- [NIST AI RMF 1.0](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10)
  for Govern, Map, Measure, and Manage evidence. NIST is revising AI RMF 1.0, so the pinned version is
  explicit and must be reassessed when the revision is final.

SOC 2/ISO 27001 reports, Shared Assessments SIG answers, legal terms, data-processing terms, insurance,
financial viability, sanctions, accessibility, support, and reference checks assess the vendor and
offering, not only this source tree. They are retained as external evidence and must never be inferred
from passing CI.

## Shared-responsibility boundary

loomDB is an embedded, one-tenant-per-process engine. The engine proves storage integrity,
authorization invariants, provenance, taint containment, bounded request admission, signed backups,
and release authenticity. The deploying organization owns network identity, TLS, host hardening,
resource isolation, encryption and key delivery, backup scheduling/retention, recovery objectives,
telemetry routing, privacy/residency, and human incident response. A managed offering would need to
move those responsibilities into its own audited control environment before answering CAIQ as a cloud
service provider.

For the deployment-owned half, [`host-profile.md`](host-profile.md) is the supported reference posture:
network identity and authenticated TLS, process and filesystem isolation, resource ceilings,
default-deny networking, digest-pinned artifacts with offline bundle verification, and
one-tenant-per-process-and-store routing — rendered as configuration in
[`deploy/reference`](../deploy/reference) and gated in CI. It is a reference, not a deployed or
independently assessed environment, and it does not change the decision above.

Run the exact gates locally:

```sh
python3 scripts/verify_enterprise_readiness.py
python3 scripts/verify_host_profile.py
```
