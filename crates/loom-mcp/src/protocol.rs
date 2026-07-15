//! JSON-RPC 2.0, the wire the MCP surface speaks.
//!
//! Minimal on purpose — enough of the protocol to carry `initialize`, `tools/list`, and `tools/call`,
//! which is the whole of what an agent client needs. The point of going through this boundary rather
//! than calling the engine directly is that **the MCP server is a new front door**, and AT-019 (token
//! scope) and AT-027 (no execute-for-an-agent) are written to hold "through every API surface including
//! MCP". A guarantee that holds at the store but leaks through the front door is not a guarantee.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A JSON-RPC request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// The correlation id. Absent for notifications; we always answer requests that carry one.
    #[serde(default)]
    pub id: Option<Value>,
    /// The method: `initialize`, `tools/list`, `tools/call`.
    pub method: String,
    /// Method parameters.
    #[serde(default)]
    pub params: Value,
}

/// A JSON-RPC response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// Echoes the request id.
    pub id: Option<Value>,
    /// The result, on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// The error, on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// A JSON-RPC error object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcError {
    /// The code.
    pub code: i64,
    /// The message — for LoomDB, this states the corrective action, the same as the engine's errors.
    pub message: String,
}

/// Standard-ish codes. `DENIED` is ours: a request the policy or a capability refused, which is a
/// *decision*, not a malformed call — a client must be able to tell "you may not" from "you sent
/// garbage".
pub mod codes {
    /// Malformed request.
    pub const INVALID_REQUEST: i64 = -32600;
    /// No such method or tool.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// Bad parameters.
    pub const INVALID_PARAMS: i64 = -32602;
    /// The engine refused: out of token scope, policy deny, stale evidence. Not a protocol error — a
    /// decision the client asked for and got.
    pub const DENIED: i64 = -32000;
}

impl Response {
    /// A success.
    pub fn ok(id: Option<Value>, result: Value) -> Self {
        Response {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// An error.
    pub fn err(id: Option<Value>, code: i64, message: impl Into<String>) -> Self {
        Response {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
            }),
        }
    }
}
