//! Bitemporal claim history — the versions that make "what did you believe last week" answerable.
//!
//! # Two time axes, and why keeping history is not optional
//!
//! A claim has two intervals: **valid** (when it holds in the world) and **known** (when *we* believed
//! it). An audit database that overwrites a claim on correction can answer "what is true now" but not
//! "what did you believe when you made that decision" — and the second question is the one a regulator,
//! an incident responder, or a court actually asks. So corrections never overwrite: they **close** the
//! prior known interval and **open** a new one, and every version stays queryable forever (AT-005).
//!
//! Each assertion of a `(subject, predicate)` appends a [`ClaimVersion`] to an append-only log and
//! closes the previous open version's known interval. An as-of query walks the log and returns the
//! version whose known interval contains the asked `known_at` and whose valid interval contains
//! `valid_at`. Nothing is ever mutated in place; the log only grows.

use serde::{Deserialize, Serialize};

use crate::value::Claim;
use crate::Key;

/// The reserved prefix under which claim version history lives. Reserved: hidden from `scan`, kept per
/// branch. Ordered by `(subject, predicate, seq)` so a scan reads a claim's versions in order.
pub const RESERVED_HISTORY_PREFIX: &[u8] = b"\x00loom/clmhist/";

/// One version of a claim, as believed over one `known` interval.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClaimVersion {
    /// The claim as asserted. Its `known` interval is the authoritative record of *when we believed
    /// this*; on correction it is closed rather than overwritten.
    pub claim: Claim,
    /// The order this version was appended in, within its `(subject, predicate)`. Monotonic, so the
    /// latest open version is the one with the highest seq.
    pub seq: u64,
}

impl ClaimVersion {
    /// The key a version is stored at: `<prefix><subject>\0<predicate>\0<seq, big-endian>`.
    ///
    /// The NUL separators keep `subject="a", predicate="bc"` from colliding with `subject="ab",
    /// predicate="c"` — the same defence the append-ordered provenance keys use. Big-endian seq so the
    /// versions sort in the order they were written.
    pub fn storage_key(subject: &str, predicate: &str, seq: u64) -> Key {
        let mut k = RESERVED_HISTORY_PREFIX.to_vec();
        k.extend_from_slice(subject.as_bytes());
        k.push(0);
        k.extend_from_slice(predicate.as_bytes());
        k.push(0);
        k.extend_from_slice(&seq.to_be_bytes());
        k
    }

    /// The prefix that matches every version of one `(subject, predicate)`.
    pub fn history_prefix(subject: &str, predicate: &str) -> Key {
        let mut k = RESERVED_HISTORY_PREFIX.to_vec();
        k.extend_from_slice(subject.as_bytes());
        k.push(0);
        k.extend_from_slice(predicate.as_bytes());
        k.push(0);
        k
    }

    /// Encode for storage.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Decode from storage.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}
