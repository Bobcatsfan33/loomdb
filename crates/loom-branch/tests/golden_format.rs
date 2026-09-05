//! **Golden bytes: the on-disk format, pinned.**
//!
//! # Why this file exists
//!
//! bincode 1.3 is unmaintained (RUSTSEC-2025-0141) and it encodes LoomDB's on-disk state — B-tree
//! nodes, the ref log, the HNSW graph, index and history and provenance records — plus the exact
//! byte string an Ed25519 capability token is signed over. Issue #50 tracks replacing it.
//!
//! **The trap this file exists to close.** The ordinary test suite writes and reads with the *same*
//! build, so it passes for any self-consistent encoding — including one that cannot read a single
//! byte written by the previous release. Swapping the serializer and running `cargo test` green is
//! therefore not evidence of anything. (Measured, not assumed: reordering two variants of
//! `loom_core::Value` — a source edit with no compiler error — leaves 91 existing unit tests
//! passing. Only this file goes red.) For a storage engine, a silent encoding change is data loss.
//!
//! So the format is pinned in `tests/fixtures/format-v1.golden`, as **bytes**, generated from the
//! real code, and asserted in **both directions**:
//!
//! 1. today's code encodes each representative value to exactly the committed bytes, and
//! 2. the committed bytes decode back to exactly that value.
//!
//! Direction 2 is the one that matters after a swap: it is the only assertion in the repository that
//! reads bytes a *previous* build produced. A successor serializer that passes this file is
//! byte-compatible with bincode 1.3.3 for these types. One that does not is a **format change**, and
//! must be landed as a versioned on-disk migration — see `docs/design/serialization-format.md`.
//!
//! # Do not "fix" a failure here by regenerating
//!
//! A red test in this file means the on-disk format changed. That is either a bug or a deliberate,
//! documented migration. Regenerating the fixtures makes the symptom go away and the data loss stay.
//! The escape hatch exists to *add* cases, not to bless a diff.
//!
//! ```text
//! LOOMDB_UPDATE_GOLDEN=1 cargo test -p loom-branch --test golden_format
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::Serialize;

use loom_branch::{Meta, Node, RefEdit, Refs, TokenClaims};
use loom_core::{
    ActorId, BranchId, Claim, ClaimId, ClaimStatus, ClaimVersion, CommitId, Confidence,
    DerivationNode, Embedding, HnswMeta, IndexEntry, Interval, Method, Observation, ObservationId,
    PersistedNode, PolicyDecisionId, Record, SessionId, SourceRef, TenantId, Timestamp, TrustClass,
    Value,
};

mod fixture;
use fixture::{Case, Fixtures};

// ---------------------------------------------------------------------------------------------
// Representative values. Deterministic — no clocks, no randomness, no HashMap iteration order.
// ---------------------------------------------------------------------------------------------

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/format-v1.golden")
}

fn commit(seed: u8) -> CommitId {
    CommitId::from_bytes([seed; 32])
}

/// Multi-byte UTF-8, on purpose: a length prefix that counts *bytes* and one that counts *chars*
/// differ here, and only one of them round-trips.
const UNICODE: &str = "café ☕ 日本語 🧵";

fn source(n: u8) -> SourceRef {
    SourceRef::new(format!("sys-{n}"), format!("rec-{n}"))
}

fn a_claim() -> Claim {
    Claim {
        id: ClaimId::of(b"golden-claim"),
        predicate: "identity.risk_increased".to_string(),
        subject: UNICODE.to_string(),
        object: Value::Number(0.5),
        valid: Interval::between(
            Timestamp::from_ms(1_700_000_000_000),
            Timestamp::from_ms(1_700_000_003_600),
        ),
        known: Interval::from(Timestamp::from_ms(1_700_000_001_000)),
        confidence: Confidence {
            value: 0.875,
            method: Method::LanguageModel,
            calibration: "cal-v1".to_string(),
        },
        evidence: vec![source(1), source(2)],
        status: ClaimStatus::Stale,
        policy: Some(PolicyDecisionId::new("pdc-1")),
        actor: ActorId::new("act-1"),
    }
}

/// The other end of every optionality in a `Claim`: unknown intervals, no evidence, no policy,
/// variant 0 of every enum.
fn a_bare_claim() -> Claim {
    Claim {
        id: ClaimId::of(b""),
        predicate: String::new(),
        subject: String::new(),
        object: Value::Bool(false),
        valid: Interval::unknown(),
        known: Interval::unknown(),
        confidence: Confidence {
            value: 0.0,
            method: Method::Direct,
            calibration: String::new(),
        },
        evidence: vec![],
        status: ClaimStatus::Asserted,
        policy: None,
        actor: ActorId::new(""),
    }
}

fn an_observation() -> Observation {
    Observation {
        id: ObservationId::of(b"golden-observation"),
        source: source(7),
        trust: TrustClass::Untrusted,
        observed_at: Some(Timestamp::from_ms(1_699_999_999_999)),
        ingested_at: Timestamp::from_ms(1_700_000_000_000),
        payload: (0u8..=255).collect(),
    }
}

fn token_claims() -> TokenClaims {
    TokenClaims {
        tenant: TenantId::new("tnt-golden"),
        session: SessionId::new("ses-golden"),
        scope: ["br-a", "br-b", UNICODE]
            .into_iter()
            .map(BranchId::new)
            .collect::<BTreeSet<_>>(),
        expires_at_ms: 1_700_000_000_000,
    }
}

/// A case whose production encoder is exactly `bincode::serialize`.
fn plain<T>(name: &'static str, type_path: &'static str, case: &'static str, value: T) -> Case
where
    T: Serialize + DeserializeOwned + PartialEq + Debug + 'static,
{
    let encoded = bincode::serialize(&value).expect("encode");
    Case::new(name, type_path, case, value, encoded)
}

/// **Every type that crosses the serialization boundary and lands on disk (or in a signed byte
/// string), with the edge cases that distinguish one framing from another.**
///
/// Ordering is stable, so the committed file's diff is readable.
fn cases() -> Vec<Case> {
    let full_entry = IndexEntry::new(
        b"claim/golden".to_vec(),
        UNICODE,
        Some(Embedding::new(vec![0.0f32, -1.5, 3.25, f32::MIN_POSITIVE])),
        vec![source(1), source(2)],
        true,
        TrustClass::Untrusted,
    )
    .expect("cited entry");
    let min_entry = IndexEntry::new(
        Vec::new(),
        "",
        None,
        vec![source(0)],
        false,
        TrustClass::VerifiedSystem,
    )
    .expect("cited entry");

    let parent = DerivationNode::new(
        BranchId::new("br-parent"),
        commit(0x11),
        b"claim/parent".to_vec(),
        ActorId::new("act-parent"),
        vec![],
        String::new(),
        vec![],
        vec![],
    );
    let full_node = DerivationNode::new(
        BranchId::new("br-golden"),
        commit(0xAB),
        b"claim/golden".to_vec(),
        ActorId::new("act-1"),
        vec![ActorId::new("act-a"), ActorId::new("act-b")],
        format!("because {UNICODE}"),
        vec![parent.id],
        vec![source(1), source(2)],
    );
    let empty_node = DerivationNode::new(
        BranchId::new(""),
        commit(0x00),
        Vec::new(),
        ActorId::new(""),
        vec![],
        String::new(),
        vec![],
        vec![],
    );

    let mut commits: BTreeMap<CommitId, Vec<CommitId>> = BTreeMap::new();
    commits.insert(commit(0x01), vec![]);
    commits.insert(commit(0x02), vec![commit(0x01)]);
    // A merge commit: the second parent substrate cannot store.
    commits.insert(commit(0x03), vec![commit(0x02), commit(0x01)]);
    let mut branches = BTreeMap::new();
    branches.insert("main".to_string(), commit(0x03));
    branches.insert(UNICODE.to_string(), commit(0x02));
    let mut tags = BTreeMap::new();
    tags.insert("v0.1.0".to_string(), commit(0x01));
    let refs = Refs {
        format_version: 1,
        branches,
        tags,
        commits,
    };

    vec![
        // --- loom-core: what lands in the tree under a reserved prefix -------------------------
        Case::new(
            "core_index_entry_full",
            "loom_core::IndexEntry",
            "embedding Some, two citations, stale, multi-byte UTF-8 text, TrustClass::Untrusted (tag 3)",
            full_entry.clone(),
            full_entry.encode().expect("IndexEntry::encode"),
        ),
        Case::new(
            "core_index_entry_minimal",
            "loom_core::IndexEntry",
            "empty key, empty text, embedding None, TrustClass::VerifiedSystem (tag 0)",
            min_entry.clone(),
            min_entry.encode().expect("IndexEntry::encode"),
        ),
        {
            let v = ClaimVersion {
                claim: a_claim(),
                seq: 42,
            };
            let bytes = v.encode().expect("ClaimVersion::encode");
            Case::new(
                "core_claim_version_full",
                "loom_core::ClaimVersion",
                "populated claim: closed + open intervals, two evidence refs, policy Some, status Stale",
                v,
                bytes,
            )
        },
        {
            let v = ClaimVersion {
                claim: a_bare_claim(),
                seq: 0,
            };
            let bytes = v.encode().expect("ClaimVersion::encode");
            Case::new(
                "core_claim_version_bare",
                "loom_core::ClaimVersion",
                "unknown intervals, empty evidence, policy None, every enum at variant 0",
                v,
                bytes,
            )
        },
        Case::new(
            "core_derivation_node_full",
            "loom_core::DerivationNode",
            "delegation chain, one derived_from, two sources, multi-byte UTF-8 intent",
            full_node.clone(),
            full_node.encode().expect("DerivationNode::encode"),
        ),
        Case::new(
            "core_derivation_node_empty",
            "loom_core::DerivationNode",
            "every collection empty — consecutive 8-byte zero length prefixes",
            empty_node.clone(),
            empty_node.encode().expect("DerivationNode::encode"),
        ),
        plain(
            "core_hnsw_persisted_node",
            "loom_core::PersistedNode",
            "three layers, one of them empty — nested length prefixes",
            PersistedNode {
                vector: Embedding::new(vec![1.0f32, -0.5, 0.0]),
                neighbours: vec![
                    vec![b"id-a".to_vec(), b"id-b".to_vec()],
                    vec![],
                    vec![b"id-c".to_vec()],
                ],
            },
        ),
        plain(
            "core_hnsw_meta_populated",
            "loom_core::HnswMeta",
            "entry Some, dim Some — Option tags are one byte, usize is eight",
            HnswMeta {
                entry: Some(b"entry-id".to_vec()),
                max_level: 4,
                dim: Some(768),
            },
        ),
        plain(
            "core_hnsw_meta_default",
            "loom_core::HnswMeta",
            "the empty graph: entry None, dim None",
            HnswMeta::default(),
        ),
        // The ANN write buffer stores a bare `Embedding` as the blob payload (`session.rs`), so its
        // encoding is on disk independently of `PersistedNode`.
        plain(
            "core_embedding",
            "loom_core::Embedding",
            "the ANN write-buffer blob payload — f32 little-endian, 8-byte count prefix",
            Embedding::new(vec![0.1f32, 0.2, 0.3, -0.4]),
        ),
        plain(
            "core_embedding_empty",
            "loom_core::Embedding",
            "empty vector — the length prefix alone",
            Embedding::new(Vec::<f32>::new()),
        ),
        // --- every `Record` and `Value` variant: the enum tag width is a format property --------
        plain(
            "core_record_observation",
            "loom_core::Record",
            "Record::Observation (tag 0), 256-byte payload",
            Record::Observation(Box::new(an_observation())),
        ),
        plain(
            "core_record_claim",
            "loom_core::Record",
            "Record::Claim (tag 1)",
            Record::Claim(Box::new(a_claim())),
        ),
        plain(
            "core_record_value_blob",
            "loom_core::Record",
            "Record::Value(Value::Blob) — tag 2, then tag 0",
            Record::Value(Value::Blob(vec![0xDE, 0xAD, 0xBE, 0xEF])),
        ),
        plain(
            "core_record_value_counter",
            "loom_core::Record",
            "Record::Value(Value::Counter) — tag 1, a negative i64",
            Record::Value(Value::Counter(-9_007_199_254_740_993)),
        ),
        plain(
            "core_record_value_set",
            "loom_core::Record",
            "Record::Value(Value::Set) — tag 2, a BTreeSet in sorted order, one member empty",
            Record::Value(Value::Set(
                [b"a".to_vec(), b"bb".to_vec(), Vec::new()]
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
            )),
        ),
        plain(
            "core_record_value_bool",
            "loom_core::Record",
            "Record::Value(Value::Bool(true)) — tag 3",
            Record::Value(Value::Bool(true)),
        ),
        plain(
            "core_record_value_text",
            "loom_core::Record",
            "Record::Value(Value::Text) — tag 4, multi-byte UTF-8",
            Record::Value(Value::Text(UNICODE.to_string())),
        ),
        plain(
            "core_record_value_number",
            "loom_core::Record",
            "Record::Value(Value::Number) — tag 5, f64",
            Record::Value(Value::Number(-0.125)),
        ),
        // A length a varint-framed successor would frame differently: bincode spends a full 8
        // bytes on 300 where postcard would spend 2. (`core_record_observation`'s 256-byte payload
        // is the same property on a real type; `format_contract::every_length_prefix_is_a_bare_u64`
        // asserts it for a 300-*element* collection without committing 7 KB of hex for it.)
        plain(
            "core_record_value_blob_300",
            "loom_core::Record",
            "300-byte blob — a length that does not fit in one varint byte",
            Record::Value(Value::Blob((0u32..300).map(|n| n as u8).collect())),
        ),
        // --- loom-branch: refs, the ref log, tree nodes, the token signing bytes ---------------
        Case::new(
            "branch_refs_populated",
            "loom_branch::Refs",
            "two branches (one multi-byte UTF-8), one tag, a three-node DAG with a merge commit",
            refs.clone(),
            refs.encode().expect("Refs::encode"),
        ),
        {
            let v = Refs::default();
            let bytes = v.encode().expect("Refs::encode");
            Case::new(
                "branch_refs_empty",
                "loom_branch::Refs",
                "the default: version 0 and three empty maps",
                v,
                bytes,
            )
        },
        // Every `RefEdit` variant. The ref log is append-only and replayed on startup, so a build
        // that cannot decode an edit an earlier build wrote loses branch heads and the merge DAG.
        // All seven, deliberately: a successor writing a one-byte tag would read variant 1 where
        // bincode wrote variant 4.
        plain(
            "branch_refedit_set_head",
            "loom_branch::RefEdit",
            "SetHead — variant 0, the ordinary per-commit edit",
            RefEdit::SetHead {
                branch: "main".to_string(),
                to: commit(0x03),
            },
        ),
        plain(
            "branch_refedit_create_branch",
            "loom_branch::RefEdit",
            "CreateBranch — variant 1, multi-byte UTF-8 name",
            RefEdit::CreateBranch {
                name: UNICODE.to_string(),
                at: commit(0x02),
            },
        ),
        plain(
            "branch_refedit_remove_branch",
            "loom_branch::RefEdit",
            "RemoveBranch — variant 2",
            RefEdit::RemoveBranch {
                name: "gone".to_string(),
            },
        ),
        plain(
            "branch_refedit_set_tag",
            "loom_branch::RefEdit",
            "SetTag — variant 3",
            RefEdit::SetTag {
                tag: "v0.1.0".to_string(),
                to: commit(0x01),
            },
        ),
        plain(
            "branch_refedit_remove_tag",
            "loom_branch::RefEdit",
            "RemoveTag — variant 4",
            RefEdit::RemoveTag {
                tag: "v0.0.1".to_string(),
            },
        ),
        plain(
            "branch_refedit_record_commit",
            "loom_branch::RefEdit",
            "RecordCommit — variant 5, two parents",
            RefEdit::RecordCommit {
                commit: commit(0x03),
                parents: vec![commit(0x02), commit(0x01)],
            },
        ),
        plain(
            "branch_refedit_record_commit_rootless",
            "loom_branch::RefEdit",
            "RecordCommit — variant 5 with an empty parent list",
            RefEdit::RecordCommit {
                commit: commit(0x01),
                parents: vec![],
            },
        ),
        plain(
            "branch_refedit_add_parent",
            "loom_branch::RefEdit",
            "AddParent — variant 6, the merge edge",
            RefEdit::AddParent {
                commit: commit(0x03),
                parent: commit(0x01),
            },
        ),
        plain(
            "branch_tree_meta",
            "loom_branch::Meta",
            "logical page 0 of every store — four fixed-width integers, no length prefixes at all",
            Meta {
                format_version: 1,
                root: 7,
                next_free: 19,
                count: 1_234_567,
            },
        ),
        plain(
            "branch_tree_meta_empty",
            "loom_branch::Meta",
            "a brand-new store's metadata page",
            Meta::empty(),
        ),
        plain(
            "branch_tree_node_leaf",
            "loom_branch::Node",
            "Node::Leaf (variant 0) with three entries of differing record variants",
            Node::Leaf {
                entries: vec![
                    (b"key-00000001".to_vec(), Record::Value(Value::Counter(1))),
                    (
                        UNICODE.as_bytes().to_vec(),
                        Record::Value(Value::Text("second".to_string())),
                    ),
                    (b"key-00000003".to_vec(), Record::Value(Value::Bool(false))),
                ],
            },
        ),
        plain(
            "branch_tree_node_leaf_empty",
            "loom_branch::Node",
            "the empty leaf a fresh tree's root decodes to — a variant tag and a zero length",
            Node::Leaf { entries: vec![] },
        ),
        plain(
            "branch_tree_node_internal",
            "loom_branch::Node",
            "Node::Internal (variant 1) — n keys, n+1 children",
            Node::Internal {
                keys: vec![b"key-00000100".to_vec(), b"key-00000200".to_vec()],
                children: vec![2, 3, 4],
            },
        ),
        // `token.rs`'s `canonical()` is the payload of an Ed25519 signature, so this case is
        // security-relevant and not merely compatibility-relevant. See the binding test below.
        plain(
            "branch_token_claims",
            "loom_branch::TokenClaims",
            "the Ed25519 signing payload — three-branch scope in BTreeSet order",
            token_claims(),
        ),
        plain(
            "branch_token_claims_empty_scope",
            "loom_branch::TokenClaims",
            "a token that authorizes nothing — empty scope set",
            TokenClaims {
                tenant: TenantId::new(""),
                session: SessionId::new(""),
                scope: BTreeSet::new(),
                expires_at_ms: 0,
            },
        ),
    ]
}

// ---------------------------------------------------------------------------------------------
// The assertions.
// ---------------------------------------------------------------------------------------------

/// **The gate.** Every case, both directions, in one report.
///
/// Deliberately a single test rather than one per case: a serializer change usually breaks *many*
/// types at once, and "here are the fourteen things that changed" is a far more useful failure than
/// whichever one the harness happened to run first.
#[test]
fn the_on_disk_format_has_not_changed() {
    let cases = cases();
    let path = path();

    if fixture::updating() {
        Fixtures::write(&path, &cases).expect("write fixtures");
        eprintln!("regenerated {} ({} cases)", path.display(), cases.len());
        return;
    }

    let fixtures = Fixtures::load(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}\nIf you are ADDING a case, run:\n  \
             LOOMDB_UPDATE_GOLDEN=1 cargo test -p loom-branch --test golden_format",
            path.display()
        )
    });
    fixtures.check_all(&cases, "loom-branch");
}

/// **The token fixture, bound to the real signing path.**
///
/// A golden byte string is only meaningful for `token.rs` if those are the bytes the issuer actually
/// signs. `CapabilityToken`'s signature field is private, so this proves it the other way round:
/// sign the **committed** bytes with a fixed key, assemble a token around that signature, and hand
/// it to `authorize`. Verification passes only if `canonical()` still produces exactly the committed
/// bytes — so a serializer change where `issue` and `authorize` merely agree with *each other*
/// still fails here, which is the whole point.
#[test]
fn the_committed_token_bytes_are_what_the_issuer_verifies() {
    use ed25519_dalek::{Signer, SigningKey};

    if fixture::updating() {
        return; // the fixture is (re)written by the gate test in the same run
    }

    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let issuer = loom_branch::TokenIssuer::new(signing.clone());

    let fixtures = Fixtures::load(&path()).expect("fixtures");
    let committed = fixtures.bytes("branch_token_claims");
    let signature = signing.sign(&committed).to_bytes();

    // A `CapabilityToken` is `{ claims, signature: Vec<u8> }`. Assemble one directly from the
    // committed claim bytes plus a signature over them — no constructor needed, and it exercises
    // the pinned framing (an 8-byte length prefix on the signature) as a side effect.
    let mut token_bytes = committed.clone();
    token_bytes.extend_from_slice(&(signature.len() as u64).to_le_bytes());
    token_bytes.extend_from_slice(&signature);
    let token: loom_branch::CapabilityToken =
        bincode::deserialize(&token_bytes).expect("committed bytes must frame a CapabilityToken");

    issuer
        .authorize(&token, &BranchId::new("br-a"), 1_699_999_999_999)
        .expect(
            "a signature over the COMMITTED claim bytes must still verify: if this fails, \
             token.rs::canonical() no longer produces the pinned encoding and every previously \
             minted capability token is now unverifiable",
        );

    // And the pinned scope is a real scope, not a shape that happens to decode.
    assert!(issuer
        .authorize(&token, &BranchId::new("br-not-in-scope"), 1_699_999_999_999)
        .is_err());
}

// ---------------------------------------------------------------------------------------------
// The format contract, stated as executable assertions.
// ---------------------------------------------------------------------------------------------

/// **What bincode 1.3.3's defaults actually guarantee**, probed rather than cited.
///
/// The fixtures pin *whole types*. These pin the *primitives* the fixtures are made of, so a failure
/// names the property that broke instead of leaving a reviewer to diff a few hundred bytes of hex.
/// Every number here was read off the encoder's real output, not derived from documentation — and
/// one of them (`trailing_bytes_are_silently_ignored`) is the opposite of what the docs suggest.
///
/// This is the contract `docs/design/serialization-format.md` says a successor must reproduce.
mod format_contract {
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    fn enc<T: Serialize>(v: &T) -> Vec<u8> {
        bincode::serialize(v).expect("encode")
    }

    #[test]
    fn integers_are_fixed_width_and_little_endian() {
        assert_eq!(enc(&1u8), vec![0x01]);
        assert_eq!(enc(&1u16), vec![0x01, 0x00]);
        assert_eq!(enc(&1u32), vec![0x01, 0x00, 0x00, 0x00]);
        assert_eq!(enc(&1u64), vec![0x01, 0, 0, 0, 0, 0, 0, 0]);
        // No varints: a small u64 still costs eight bytes. This is the single most consequential
        // property for LoomDB, because `tree.rs` sizes pages against it.
        assert_eq!(enc(&1u64).len(), 8);
        assert_eq!(enc(&u64::MAX).len(), 8);
        // Signed integers are two's complement, same width, same order.
        assert_eq!(enc(&-2i32), vec![0xFE, 0xFF, 0xFF, 0xFF]);
        // `usize` is encoded as a 64-bit value regardless of the host's pointer width, so a 32-bit
        // build reads a 64-bit build's stores.
        assert_eq!(enc(&1usize), enc(&1u64));
    }

    #[test]
    fn floats_are_ieee754_little_endian() {
        assert_eq!(enc(&1.0f32), 1.0f32.to_le_bytes().to_vec());
        assert_eq!(enc(&-0.125f64), (-0.125f64).to_le_bytes().to_vec());
        assert_eq!(enc(&1.0f32).len(), 4);
        assert_eq!(enc(&1.0f64).len(), 8);
    }

    #[test]
    fn every_length_prefix_is_a_bare_u64() {
        assert_eq!(&enc(&vec![7u8])[..8], &[0x01, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(enc(&Vec::<u8>::new()), vec![0u8; 8]);
        // Maps too — and a `BTreeMap` serialises in key order, which is what makes `Refs`
        // deterministic.
        let mut m = BTreeMap::new();
        m.insert(1u8, 2u8);
        assert_eq!(enc(&m), vec![0x01, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02]);
        // A length a varint encoding would spend fewer bytes on still costs eight here. This is the
        // assertion `postcard` and `rkyv` fail, and it is why they are a migration and not a swap.
        assert_eq!(&enc(&vec![0u8; 300])[..8], &300u64.to_le_bytes());
    }

    #[test]
    fn strings_are_utf8_bytes_with_a_byte_length_not_a_char_length() {
        let s = "café ☕ 日本語 🧵";
        assert_eq!(s.chars().count(), 12);
        assert_eq!(s.len(), 24);
        let bytes = enc(&s.to_string());
        assert_eq!(&bytes[..8], &24u64.to_le_bytes());
        assert_eq!(&bytes[8..], s.as_bytes());
        // Fixed-size arrays carry NO length prefix — this is why a 32-byte `CommitId` costs 32 and
        // not 40.
        assert_eq!(enc(&[9u8; 32]).len(), 32);
    }

    #[test]
    fn enum_discriminants_are_four_byte_little_endian_indices() {
        #[derive(Serialize, Deserialize)]
        enum Seven {
            A,
            B,
            C,
            D,
            E,
            F,
            G,
        }
        assert_eq!(enc(&Seven::A), vec![0, 0, 0, 0]);
        assert_eq!(enc(&Seven::G), vec![6, 0, 0, 0]);
        // Four bytes even for a two-variant enum: the width does not shrink with the variant count,
        // so a successor that packs a tag into one byte silently re-points every variant.
        #[derive(Serialize, Deserialize)]
        enum Two {
            A,
            B,
        }
        assert_eq!(enc(&Two::B), vec![1, 0, 0, 0]);
        // The discriminant is the DECLARATION INDEX. Reordering variants in a source file is
        // therefore an on-disk format change with no compiler error and no test failure anywhere
        // except the golden fixtures.
        assert_eq!(enc(&Seven::D), enc(&3u32));
    }

    #[test]
    fn option_is_a_one_byte_tag_not_a_four_byte_one() {
        // `Option` is special-cased: one byte, unlike every other enum. A successor that treats it
        // as an ordinary enum writes three extra bytes per `None`.
        assert_eq!(enc(&None::<u64>), vec![0x00]);
        assert_eq!(enc(&Some(1u64)), vec![0x01, 0x01, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(enc(&true), vec![0x01]);
        assert_eq!(enc(&false), vec![0x00]);
    }

    #[test]
    fn structs_and_tuples_are_bare_concatenation_with_no_field_names_or_count() {
        #[derive(Serialize, Deserialize)]
        struct Pair {
            a: u32,
            b: u32,
        }
        assert_eq!(enc(&Pair { a: 1, b: 2 }), enc(&(1u32, 2u32)));
        assert_eq!(enc(&Pair { a: 1, b: 2 }).len(), 8);
        // Nothing is self-describing: no field names, no field count, no type tag. **Adding,
        // removing or reordering a struct field is an on-disk format change**, and the decoder
        // cannot detect one — it reads the next field's bytes as this one's. That is why the
        // fixtures assert a decoded VALUE, not merely that decoding succeeded.
        #[derive(Serialize, Deserialize)]
        struct Newtype(u32);
        assert_eq!(enc(&Newtype(1)), enc(&1u32));
    }

    #[test]
    fn the_encoding_is_deterministic() {
        // Same value, same bytes, every time. This is what makes a signature over `token.rs`'s
        // `canonical()` — or over `loom-bundle`'s manifest — mean anything at all.
        assert_eq!(enc(&(1u64, "x".to_string())), enc(&(1u64, "x".to_string())));
        // And a `BTreeSet` iterates in key order, so a collection's encoding does not depend on
        // insertion order either.
        let a: std::collections::BTreeSet<u8> = [3u8, 1, 2].into_iter().collect();
        let b: std::collections::BTreeSet<u8> = [2u8, 3, 1].into_iter().collect();
        assert_eq!(enc(&a), enc(&b));
    }

    /// **`bincode::deserialize` IGNORES trailing bytes.** Verified, not assumed — and it is the
    /// opposite of what the name suggests.
    ///
    /// This is load-bearing in one place and a hazard in another:
    ///
    /// - `tree.rs` decodes a node from `page.as_bytes()`. Any slack past the encoded node is
    ///   silently ignored today. (`refs.rs` does **not** rely on it: a log frame carries its own
    ///   `u32` length and a BLAKE3 checksum, so a torn tail is caught by the checksum.)
    /// - **The hazard:** a successor that is strict about trailing bytes would start rejecting data
    ///   this build reads happily. That is a behaviour change with no byte-level diff, so no golden
    ///   fixture would catch it. It is pinned here instead.
    #[test]
    fn trailing_bytes_are_silently_ignored() {
        let bytes = enc(&1u32);
        assert!(bincode::deserialize::<u32>(&bytes).is_ok());

        let mut extra = bytes.clone();
        extra.extend_from_slice(&[0xAA; 16]);
        assert_eq!(
            bincode::deserialize::<u32>(&extra).expect("bincode 1.x ignores trailing bytes"),
            1u32,
            "if this ever REJECTS, the decoder became strict about slack after a value — \
             re-check every call site that decodes from a whole page or a whole file"
        );

        // A truncated value, by contrast, is a hard error — so a short read is never mistaken for a
        // small value.
        assert!(bincode::deserialize::<u32>(&bytes[..3]).is_err());
    }
}
