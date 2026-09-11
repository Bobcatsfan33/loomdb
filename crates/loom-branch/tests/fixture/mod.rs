//! The golden-fixture harness: one committed file per crate, hex, both directions.
//!
//! # Why one file and not one per case
//!
//! A serializer change breaks *many* types at once. Thirty-odd separate `#[test]`s would report
//! whichever one the harness happened to run first; a single file checked by a single test reports
//! **everything that moved**, which is the difference between "something changed" and "here is the
//! shape of the change". It also means regeneration is one atomic write rather than thirty racing
//! ones, and it makes the committed bytes reviewable in one place.
//!
//! # Why hex and not a binary blob
//!
//! A format change should show up in review as a *readable diff*, not as "Binary files differ".
//!
//! This file is duplicated verbatim in `crates/loom-bundle/tests/fixture/mod.rs`. Integration tests
//! cannot share a module across crates, and a shared crate for ~150 lines of test scaffolding would
//! cost more than the duplication does.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Serialize;

/// Is this run allowed to (re)write the fixture file?
pub fn updating() -> bool {
    std::env::var_os("LOOMDB_UPDATE_GOLDEN").is_some()
}

/// Decode arbitrary bytes as one case's concrete type and compare against the pinned value.
type DecodeCheck = Box<dyn Fn(&[u8]) -> Result<(), String>>;

/// One pinned value: what it is, the bytes the production encoder produces for it today, and a
/// closure that can decode arbitrary bytes back into its type and compare.
///
/// The closure is what makes direction 2 possible without the harness being generic over every type
/// at once — it captures the concrete `T` and the expected value.
pub struct Case {
    pub name: &'static str,
    pub type_path: &'static str,
    pub description: &'static str,
    pub encoded: Vec<u8>,
    decode_and_compare: DecodeCheck,
}

impl Case {
    pub fn new<T>(
        name: &'static str,
        type_path: &'static str,
        description: &'static str,
        value: T,
        encoded: Vec<u8>,
    ) -> Case
    where
        T: Serialize + DeserializeOwned + PartialEq + Debug + 'static,
    {
        Case {
            name,
            type_path,
            description,
            encoded,
            decode_and_compare: Box::new(move |bytes| match bincode::deserialize::<T>(bytes) {
                Err(e) => Err(format!(
                    "CANNOT READ EXISTING DATA: the committed bytes no longer decode: {e}"
                )),
                Ok(decoded) if decoded != value => Err(format!(
                    "SILENT MISREAD: the committed bytes decoded, but to a DIFFERENT value \
                     (this is worse than a decode failure).\n      expected: {value:?}\n      \
                     got:      {decoded:?}"
                )),
                Ok(_) => Ok(()),
            }),
        }
    }
}

/// The parsed contents of a committed fixture file.
pub struct Fixtures {
    entries: BTreeMap<String, Vec<u8>>,
}

impl Fixtures {
    /// Parse a committed fixture file.
    pub fn load(path: &Path) -> Result<Fixtures, String> {
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut entries = BTreeMap::new();
        let mut current: Option<(String, Vec<u8>)> = None;

        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                if let Some((name, bytes)) = current.take() {
                    entries.insert(name, bytes);
                }
                current = Some((name.to_string(), Vec::new()));
                continue;
            }
            // Metadata lines are for the reader, not the parser. Matched by an explicit key list
            // rather than "contains a colon", so a corrupted hex line is an error rather than
            // something quietly skipped.
            if ["type:", "case:", "len:"]
                .iter()
                .any(|key| line.starts_with(key))
            {
                continue;
            }
            let (_, bytes) = current.as_mut().ok_or_else(|| {
                format!("{}:{}: hex before any [name] header", path.display(), n + 1)
            })?;
            bytes.extend(parse_hex_line(line, path, n + 1)?);
        }
        if let Some((name, bytes)) = current.take() {
            entries.insert(name, bytes);
        }
        Ok(Fixtures { entries })
    }

    /// The committed bytes for one case. Panics if absent — callers are tests that need it.
    pub fn bytes(&self, name: &str) -> Vec<u8> {
        self.entries
            .get(name)
            .unwrap_or_else(|| panic!("no committed fixture named {name}"))
            .clone()
    }

    /// **Check every case, both directions, and report all failures together.**
    pub fn check_all(&self, cases: &[Case], crate_name: &str) {
        let mut problems: Vec<String> = Vec::new();

        for case in cases {
            let Some(expected) = self.entries.get(case.name) else {
                problems.push(format!(
                    "  {} ({}): NO COMMITTED FIXTURE",
                    case.name, case.type_path
                ));
                continue;
            };

            // Direction 1: today's code still produces the bytes a previous build committed.
            if &case.encoded != expected {
                problems.push(format!(
                    "  {} ({}) — {}\n      the encoder no longer produces the committed bytes{}",
                    case.name,
                    case.type_path,
                    case.description,
                    describe_diff(expected, &case.encoded),
                ));
            }

            // Direction 2: bytes a previous build wrote still decode to the value they meant. This
            // is the assertion a serializer swap actually has to survive, so it runs even when
            // direction 1 already failed.
            if let Err(detail) = (case.decode_and_compare)(expected) {
                problems.push(format!(
                    "  {} ({}) — {}\n      {detail}",
                    case.name, case.type_path, case.description
                ));
            }
        }

        for name in self.entries.keys() {
            if !cases.iter().any(|c| c.name == name) {
                problems.push(format!(
                    "  {name}: committed but no longer generated — the case was removed. If the \
                     type is gone, delete the fixture deliberately; if it was renamed, the old \
                     bytes are no longer being checked."
                ));
            }
        }

        assert!(
            problems.is_empty(),
            "\n\n=== ON-DISK FORMAT CHANGE in {crate_name} — {} problem(s) ===\n\n{}\n\n\
             Every database written by an earlier build encodes these types the old way, and any \
             signature made over them no longer verifies.\n\
             Do NOT regenerate the fixtures to make this pass. Read \
             docs/design/serialization-format.md first (issue #50).\n",
            problems.len(),
            problems.join("\n"),
        );
    }

    /// Render the whole fixture file. Only ever called under `LOOMDB_UPDATE_GOLDEN`.
    pub fn write(path: &Path, cases: &[Case]) -> std::io::Result<()> {
        let mut out = String::new();
        out.push_str("# LoomDB golden format fixtures — format v1.\n#\n");
        out.push_str("# GENERATED. Do not edit by hand, and do not regenerate to make a test\n");
        out.push_str("# pass: a diff here is an ON-DISK FORMAT CHANGE, and for a storage engine\n");
        out.push_str("# that is data loss. See docs/design/serialization-format.md (issue #50).\n");
        out.push_str("#\n");
        out.push_str("# These are the bytes bincode 1.3.3 produces with its default settings:\n");
        out.push_str("#   * integers fixed-width and little-endian, never varint\n");
        out.push_str("#   * every length prefix a bare u64 (8 bytes), for any size\n");
        out.push_str("#   * enum discriminants a u32 of the variant's DECLARATION INDEX\n");
        out.push_str("#   * Option a one-byte tag; bool one byte\n");
        out.push_str(
            "#   * structs a bare concatenation — no field names, no count, no type tag\n",
        );
        out.push_str("#\n");
        out.push_str("# To ADD a case (never to bless a diff):\n");
        out.push_str("#   LOOMDB_UPDATE_GOLDEN=1 cargo test --test golden_format\n");

        for case in cases {
            out.push_str(&format!("\n[{}]\n", case.name));
            out.push_str(&format!("type: {}\n", case.type_path));
            out.push_str(&format!("case: {}\n", case.description));
            out.push_str(&format!("len:  {} bytes\n", case.encoded.len()));
            if case.encoded.is_empty() {
                out.push_str("(empty)\n");
            }
            for chunk in case.encoded.chunks(32) {
                out.push_str(&chunk.iter().map(|b| format!("{b:02x}")).collect::<String>());
                out.push('\n');
            }
        }
        std::fs::create_dir_all(path.parent().expect("fixture dir"))?;
        std::fs::write(path, out)
    }
}

/// A one-line summary of *how* two byte strings differ — enough to tell "the whole framing moved"
/// from "one field changed" without printing kilobytes of hex.
fn describe_diff(expected: &[u8], actual: &[u8]) -> String {
    let mut s = String::new();
    if expected.len() != actual.len() {
        s.push_str(&format!(
            "\n      length: committed {} bytes, now {} bytes",
            expected.len(),
            actual.len()
        ));
    }
    if let Some(at) = expected
        .iter()
        .zip(actual)
        .position(|(a, b)| a != b)
        .or_else(|| (expected.len() != actual.len()).then_some(expected.len().min(actual.len())))
    {
        let end = (at + 8).min(expected.len().max(actual.len()));
        s.push_str(&format!(
            "\n      first difference at byte {at}:\n        committed: {}\n        now:       {}",
            hex_window(expected, at, end),
            hex_window(actual, at, end),
        ));
    }
    s
}

fn hex_window(bytes: &[u8], from: usize, to: usize) -> String {
    if from >= bytes.len() {
        return "<end of data>".to_string();
    }
    let slice = &bytes[from..to.min(bytes.len())];
    let hex: String = slice.iter().map(|b| format!("{b:02x} ")).collect();
    format!("{}…", hex.trim_end())
}

fn is_hex(line: &str) -> bool {
    !line.is_empty() && line.chars().all(|c| c.is_ascii_hexdigit())
}

fn parse_hex_line(line: &str, path: &Path, n: usize) -> Result<Vec<u8>, String> {
    if line == "(empty)" {
        return Ok(Vec::new());
    }
    if !is_hex(line) || !line.len().is_multiple_of(2) {
        return Err(format!("{}:{n}: not a hex line: {line:?}", path.display()));
    }
    Ok((0..line.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&line[i..i + 2], 16).expect("checked hex"))
        .collect())
}
