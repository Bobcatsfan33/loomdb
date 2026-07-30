//! Resource admission controls for the single-tenant `loomd` process.
//!
//! Each daemon is one tenant's isolation boundary. These controls bound memory consumed by one
//! request and the rate at which that tenant can enter the engine. Platform-level connection and
//! storage quotas remain the responsibility of the supervisor in front of `loomd`.

use std::io::{self, BufRead};
use std::time::Instant;

/// Conservative defaults suitable for an agent-facing JSON-RPC process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionConfig {
    /// Maximum bytes in one newline-delimited JSON request, excluding the newline.
    pub max_request_bytes: usize,
    /// Sustained requests admitted each second.
    pub requests_per_second: u32,
    /// Maximum immediately available request burst.
    pub burst: u32,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            max_request_bytes: 1024 * 1024,
            requests_per_second: 100,
            burst: 200,
        }
    }
}

impl AdmissionConfig {
    /// Read bounded operator configuration. Invalid values are rejected instead of silently falling
    /// back, because a misspelled production limit must not disable the control.
    pub fn from_env() -> Result<Self, String> {
        let defaults = Self::default();
        Ok(Self {
            max_request_bytes: env_bounded_usize(
                "LOOM_MAX_REQUEST_BYTES",
                defaults.max_request_bytes,
                256,
                16 * 1024 * 1024,
            )?,
            requests_per_second: env_bounded_u32(
                "LOOM_REQUESTS_PER_SECOND",
                defaults.requests_per_second,
                1,
                100_000,
            )?,
            burst: env_bounded_u32("LOOM_REQUEST_BURST", defaults.burst, 1, 1_000_000)?,
        })
    }
}

fn env_bounded_usize(name: &str, default: usize, min: usize, max: usize) -> Result<usize, String> {
    let Some(raw) = std::env::var_os(name) else {
        return Ok(default);
    };
    let raw = raw
        .into_string()
        .map_err(|_| format!("{name} must be valid UTF-8"))?;
    let value = raw
        .parse::<usize>()
        .map_err(|_| format!("{name} must be an integer in {min}..={max}"))?;
    if !(min..=max).contains(&value) {
        return Err(format!("{name} must be in {min}..={max}"));
    }
    Ok(value)
}

fn env_bounded_u32(name: &str, default: u32, min: u32, max: u32) -> Result<u32, String> {
    let value = env_bounded_usize(name, default as usize, min as usize, max as usize)?;
    u32::try_from(value).map_err(|_| format!("{name} is too large"))
}

/// The result of reading one bounded newline-delimited request.
#[derive(Debug, Eq, PartialEq)]
pub enum BoundedLine {
    /// Clean end of input.
    Eof,
    /// One complete request, with CRLF normalized.
    Line(Vec<u8>),
    /// The entire oversized request was drained through its newline.
    TooLarge,
}

/// Read one line without ever allocating more than `max_bytes`.
///
/// `BufRead::lines` and `read_line` grow without a limit. This implementation consumes an oversized
/// frame through its delimiter while retaining at most `max_bytes`, so the following request remains
/// parseable and an attacker cannot force an unbounded allocation.
pub fn read_bounded_line<R: BufRead>(reader: &mut R, max_bytes: usize) -> io::Result<BoundedLine> {
    let mut line = Vec::with_capacity(max_bytes.min(8 * 1024));
    let mut oversized = false;
    let mut saw_input = false;

    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if !saw_input {
                return Ok(BoundedLine::Eof);
            }
            break;
        }
        saw_input = true;
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        let payload = newline.map_or(available, |index| &available[..index]);

        if !oversized {
            let remaining = max_bytes.saturating_sub(line.len());
            if payload.len() > remaining {
                line.extend_from_slice(&payload[..remaining]);
                oversized = true;
            } else {
                line.extend_from_slice(payload);
            }
        }
        reader.consume(consumed);
        if newline.is_some() {
            break;
        }
    }

    if oversized {
        Ok(BoundedLine::TooLarge)
    } else {
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Ok(BoundedLine::Line(line))
    }
}

/// Per-process token-bucket limiter. Since one `loomd` serves one tenant, this is a tenant admission
/// limit without a high-cardinality tenant map in the trusted process.
#[derive(Debug)]
pub struct AdmissionController {
    config: AdmissionConfig,
    tokens: f64,
    last_refill: Instant,
}

impl AdmissionController {
    /// Create a full bucket so a healthy client may use the configured burst after startup.
    pub fn new(config: AdmissionConfig) -> Self {
        Self {
            config,
            tokens: f64::from(config.burst),
            last_refill: Instant::now(),
        }
    }

    /// Admit one request or reject it without entering the database.
    pub fn admit(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * f64::from(self.config.requests_per_second))
            .min(f64::from(self.config.burst));
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn bounded_reader_drains_an_oversized_frame_and_recovers() {
        let mut input = Cursor::new(b"123456789\nok\r\nunterminated".to_vec());
        assert_eq!(
            read_bounded_line(&mut input, 4).unwrap(),
            BoundedLine::TooLarge
        );
        assert_eq!(
            read_bounded_line(&mut input, 4).unwrap(),
            BoundedLine::Line(b"ok".to_vec())
        );
        assert_eq!(
            read_bounded_line(&mut input, 32).unwrap(),
            BoundedLine::Line(b"unterminated".to_vec())
        );
        assert_eq!(read_bounded_line(&mut input, 32).unwrap(), BoundedLine::Eof);
    }

    #[test]
    fn token_bucket_enforces_burst_without_entering_engine() {
        let mut limiter = AdmissionController::new(AdmissionConfig {
            max_request_bytes: 256,
            requests_per_second: 1,
            burst: 2,
        });
        assert!(limiter.admit());
        assert!(limiter.admit());
        assert!(!limiter.admit());
    }
}
