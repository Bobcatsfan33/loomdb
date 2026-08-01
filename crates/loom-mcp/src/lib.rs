//! **loomd — the LoomDB MCP server.**
//!
//! The front door: an agent client speaks JSON-RPC (the Model Context Protocol) to `loomd`, which
//! drives the engine. This crate is where the acceptance demo (docs/04 §3.1) is scripted verbatim, and
//! where AT-019 (token scope) and AT-027 (no execute-for-an-agent) are re-proven at the MCP boundary —
//! because a new front door is exactly the place a guarantee proven at the store can quietly leak.

#[cfg(all(feature = "remote", feature = "airgap"))]
compile_error!("features `remote` and `airgap` are mutually exclusive; use --no-default-features");
#[cfg(all(feature = "airgap", feature = "observability"))]
compile_error!(
    "feature `observability` carries an OTLP network client and cannot enter an airgap build"
);

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
