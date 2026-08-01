//! **loomd — the LoomDB MCP server.**
//!
//! The front door: an agent client speaks JSON-RPC (the Model Context Protocol) to `loomd`, which
//! drives the engine. This crate is where the acceptance demo (docs/04 §3.1) is scripted verbatim, and
//! where AT-019 (token scope) and AT-027 (no execute-for-an-agent) are re-proven at the MCP boundary —
//! because a new front door is exactly the place a guarantee proven at the store can quietly leak.

// ── THE SUPPORTED BUILD FLAVOURS ────────────────────────────────────────────────────────────────
//
// Storage posture and telemetry are **orthogonal**. Four flavours, all supported:
//
//   --features remote                                     connected; object-storage sleep/wake
//   --features remote,observability                       connected, with the OTLP exporter
//   --no-default-features --features airgap               air-gapped; no exporter compiled at all
//   --no-default-features --features airgap,observability air-gapped, exporter, still no S3 client
//
// **P7.1 decision.** This block used to reject `airgap` + `observability` outright. That
// combination is the *documented connected flavour* of the reference host profile
// (`docs/host-profile.md` §4.6): telemetry to an in-enclave collector, with still no object-storage
// client anywhere in the graph. The guard therefore made a supported, documented build
// uncompilable — the profile validator accepted a build string that could not be produced. The
// guard was refined rather than obeyed.
//
// What it was reaching for survives in two narrower forms, both of which reject something real.

// 1. `remote` is the ONLY edge in this workspace that links an object-storage client. That — not
//    telemetry — is what an enclave must exclude, and asking for both postures at once is a
//    contradiction about the artifact rather than a preference.
#[cfg(all(feature = "remote", feature = "airgap"))]
compile_error!(
    "features `remote` and `airgap` are mutually exclusive: `remote` links the object-storage \
     client an air-gapped build exists to amputate. Use `--no-default-features --features airgap`."
);

// 2. A posture must be **declared**. A build with neither feature is one whose air-gap status
//    cannot be read off the artifact, which defeats auditing the artifact instead of trusting the
//    deployment that produced it. This was previously unguarded and compiled silently.
#[cfg(not(any(feature = "remote", feature = "airgap")))]
compile_error!(
    "loom-mcp must declare exactly one storage posture: `remote` (connected) or \
     `--no-default-features --features airgap` (air-gapped). A build declaring neither cannot be \
     audited from its own dependency graph, which is how this product expects to be checked."
);

// The remaining half of the old guard — "the pure air-gap build carries no exporter" — is not a
// feature contradiction at all: with `observability` off, the exporter is not compiled. It is
// enforced where it can actually be falsified, by the dependency inspection over *every* flavour in
// `scripts/verify_build_flavours.sh`, which CI runs on each push.

mod admission;
mod hex;
mod protocol;
mod server;
#[cfg(feature = "observability")]
mod telemetry;

pub use admission::{read_bounded_line, AdmissionConfig, AdmissionController, BoundedLine};
pub use hex::decode_hex;
pub use protocol::{codes, Request, Response, RpcError};
pub use server::LoomServer;
#[cfg(feature = "observability")]
pub use telemetry::{OtlpTelemetry, RequestObservation, RequestObserver};
