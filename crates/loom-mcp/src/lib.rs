//! **loomd — the LoomDB MCP server.**
//!
//! The front door: an agent client speaks JSON-RPC (the Model Context Protocol) to `loomd`, which
//! drives the engine. This crate is where the acceptance demo (docs/04 §3.1) is scripted verbatim, and
//! where AT-019 (token scope) and AT-027 (no execute-for-an-agent) are re-proven at the MCP boundary —
//! because a new front door is exactly the place a guarantee proven at the store can quietly leak.

mod protocol;
mod server;

pub use protocol::{codes, Request, Response, RpcError};
pub use server::LoomServer;
