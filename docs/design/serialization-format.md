# Design note — the on-disk serialization format, and what may replace bincode

**Status:** the format contract below is **implemented and pinned by tests** (this PR). The
migration recommendation is **proposed**; no serializer has been swapped, and nothing in this note
authorizes swapping one.

**Decision this records:** what bincode 1.3.3 actually guarantees LoomDB's on-disk bytes, verified
empirically rather than cited; what a successor must reproduce byte-for-byte to be a *swap* rather
than a *migration*; and the sequence in which the swap may be attempted, with the golden fixtures as
the gate.

**Where this lives in the tree:**

| | |
| --- | --- |
| `crates/loom-branch/tests/golden_format.rs` | the cases, the both-directions gate, and the §2 format-contract probes |
| `crates/loom-branch/tests/fixtures/format-v1.golden` | the committed bytes for every storage type and the token signing payload |
| `crates/loom-bundle/tests/golden_format.rs` + `tests/fixtures/format-v1.golden` | the bundle signing payload and transport form |
| `crates/loom-branch/src/tree.rs` → `tests::page_fitting` | §3, the page-fitting invariant |

Tracking issue: **#50**. Related: **#9** (Dependabot's bincode 3.0.0 bump, closed — 3.0.0 is a
tombstone whose entire `src/lib.rs` is `compile_error!("https://xkcd.com/2347/")`).

---

## §1 — Why this is a storage problem, not a dependency problem

`bincode` is unmaintained as of RUSTSEC-2025-0141. `cargo audit` reports it as an allowed warning,
not a vulnerability, so nothing is on fire. The reason it is urgent anyway is that bincode 1.3
encodes **LoomDB's durable state**, and two Ed25519 signing payloads:

| Crate / module | What its bincode bytes are |
| --- | --- |
| `loom-branch/src/tree.rs` | B+tree `Node`s (every leaf and internal page) and the `Meta` page at logical page 0 |
| `loom-branch/src/refs.rs` | the `Refs` snapshot and every `RefEdit` frame in the append-only ref log |
| `loom-branch/src/ann.rs` | `PersistedNode` and `HnswMeta` — the HNSW graph, stored as blobs in the branch tree |
| `loom-branch/src/session.rs` | the ANN write buffer: a bare `Embedding` per pending vector |
| `loom-branch/src/token.rs` | **the Ed25519 signing payload** of a capability token (`canonical()`) |
| `loom-core/src/index.rs` | `IndexEntry` — what retrieval matches against |
| `loom-core/src/history.rs` | `ClaimVersion` — bitemporal claim history |
| `loom-core/src/provenance.rs` | `DerivationNode` — the derivation DAG |
| `loom-bundle/src/lib.rs` | **the Ed25519 signing payload** of an offline update bundle, and the bundle transport form |

Two of those rows are signatures, not storage. They fail differently and are worth separating:

- **Storage rows** fail as *data loss*. A successor whose bytes differ cannot read a store an
  earlier release wrote. Worse than a decode error is a decode that *succeeds into the wrong value* —
  bincode carries no field names, no field count and no type tag (§2.7), so a shifted field is read
  as the next field's bytes without complaint.
- **Signature rows** fail as *authentication loss*. `token.rs` invalidates every token minted before
  the change (in-process only, so low blast radius, but it must be a deliberate call). `loom-bundle`
  invalidates every bundle **already signed and shipped on physical media** — those cannot be
  re-signed by anyone downstream.

There is a third consequence that is neither, and is the one most likely to be missed:

- **`tree.rs` measures the encoding to decide page fitting.** `entry_cost` is
  `key.len() + bincode::serialized_size(record) + SLACK`, and `SLACK`'s comment reasons explicitly
  about "bincode length prefixes are 8 bytes each". A successor with varint framing does not merely
  change bytes on disk — it changes **how many records fit in a page**, and therefore fanout, tree
  depth and write amplification. Nothing in the behavioural test suite would notice.

### The obvious wrong fix

Swap the crate, run `cargo test --workspace`, observe green, ship. The suite writes and reads with
the **same build**, so it passes for any self-consistent encoding — including one that cannot read a
single byte the previous release wrote.

This was measured, not assumed. Reordering two variants of `loom_core::Value` — a source edit with no
compiler error — leaves **91 existing unit tests passing**. Only the golden fixtures go red.

---

## §2 — The format contract, verified empirically

Every claim below is asserted by
`crates/loom-branch/tests/golden_format.rs::format_contract`, against the encoder's real output. The
numbers were read off the encoder, not derived from documentation. Where the documentation and the
encoder could disagree, the encoder wins and §2.8 records where they nearly did.

`bincode::serialize` / `bincode::deserialize` use bincode 1.x's *default* configuration. That is not
the same as `DefaultOptions` (the builder API), which uses varints; LoomDB uses the free functions
throughout, and the free functions are fixed-int. A successor must reproduce **the free functions'**
behaviour.

### 2.1 Integers — fixed width, little-endian, no varints

`u8`→1, `u16`→2, `u32`→4, `u64`→8 bytes. Signed integers are two's complement at the same width.
`1u64` costs eight bytes and so does `u64::MAX`. `usize` is encoded as 64-bit **regardless of the
host's pointer width**, so a 32-bit build reads a 64-bit build's stores.

### 2.2 Floats — IEEE-754, little-endian

`f32`→4, `f64`→8 bytes, byte-identical to `to_le_bytes()`. This matters for `Embedding` (`Vec<f32>`),
which is the bulk of an ANN page.

### 2.3 Length prefixes — a bare `u64`, always eight bytes

Sequences, maps, strings and byte strings are `[u64 length][elements]`. The prefix does not shrink
for small collections: a 1-element vector and a 300-element vector both spend eight bytes on the
length. **This is the property `tree.rs` is built on**, and the one `postcard` does not have.

Fixed-size arrays (`[u8; 32]`, so `CommitId`, `ClaimId`, `NodeId`) carry **no** length prefix at all
— 32 bytes for 32 bytes.

### 2.4 Strings — UTF-8 bytes, with a **byte** length

`"café ☕ 日本語 🧵"` is 12 `char`s and 24 bytes; the prefix is 24. A successor that counted
characters would round-trip ASCII perfectly and corrupt everything else.

### 2.5 Enum discriminants — a four-byte little-endian **declaration index**

`u32`, always, regardless of variant count: a two-variant enum still spends four bytes on its tag.
The value is the variant's position in the source declaration.

**Therefore reordering variants in a `.rs` file is an on-disk format change** with no compiler error
and no test failure anywhere except the fixtures. `RefEdit` has seven variants and `Value` has six;
both are pinned variant-by-variant.

### 2.6 `Option` — a **one**-byte tag, unlike every other enum

`None` is `0x00`; `Some(x)` is `0x01` followed by `x`. Special-cased, so a successor that treats
`Option` as an ordinary enum writes three extra bytes per `None`. `bool` is likewise one byte.

### 2.7 Structs and tuples — bare concatenation, nothing self-describing

No field names, no field count, no type tag. `struct Pair { a: u32, b: u32 }` encodes identically to
`(u32, u32)`, and a newtype encodes identically to its inner value.

**Adding, removing or reordering a struct field is an on-disk format change that the decoder cannot
detect.** It reads the next field's bytes as this one's. This is why the fixtures assert a decoded
**value**, not merely that decoding succeeded — a test that only checked "it decodes" would pass
through exactly this failure.

### 2.8 Trailing bytes are **silently ignored**

`bincode::deserialize::<u32>(&[1,0,0,0, 0xAA,…])` returns `Ok(1)`, not an error. This is the opposite
of what the function name suggests, and it is load-bearing:

- `tree.rs` decodes a node from `page.as_bytes()`; any slack past the encoded node is ignored today.
- `refs.rs` does **not** rely on it — a log frame carries its own `u32` length and a BLAKE3 checksum,
  so a torn tail is caught by the checksum, not the decoder.
- **The hazard:** a successor that is *strict* about trailing bytes starts rejecting data this build
  reads happily. That is a behaviour change with no byte-level diff, so no golden fixture would catch
  it. It is pinned separately, in `trailing_bytes_are_silently_ignored`.

A *truncated* value, by contrast, is a hard error — a short read is never mistaken for a small value.

### 2.9 Determinism

The same value encodes to the same bytes every time, and `BTreeMap`/`BTreeSet` iterate in key order,
so a collection's encoding does not depend on insertion order. This is what makes a signature over
`token.rs::canonical()` or `BundleManifest::signing_bytes()` mean anything.

### 2.10 `serialized_size` agrees with `serialize`

`bincode::serialized_size(x) == bincode::serialize(x).len()`, verified across record shapes. This is
not decoration: `entry_cost` trusts the size oracle as a cheap stand-in for the real encode, and an
oracle that under-reports relative to its own encoder would let a node grow past its page and produce
a `PageTooLarge` at commit for an insert that looked fine.

---

## §3 — The page-fitting numbers this format produces

Pinned by `crates/loom-branch/src/tree.rs::tests::page_fitting`, for `Record::Value(Value::Counter)`
under a 12-byte key and 4096-byte pages:

| Quantity | Value | Where it comes from |
| --- | --- | --- |
| `serialized_size(record)` | 16 | 4-byte `Record` tag + 4-byte `Value` tag + 8-byte `i64` |
| true marginal cost of one leaf entry | 36 | 8-byte key length prefix + 12 key bytes + 16 record bytes |
| `entry_cost` (the running estimate) | 52 | `12 + 16 + SLACK(24)` |
| fullness limit | 2867 | `4096 × FILL_FACTOR(0.7)` |
| entries that fit in a leaf | 79 (2856 bytes) | 80 encode to 2892 and split |
| shape of a 2000-record tree | 50 leaves × 40 entries, root at page 3, 52 pages | ascending inserts |

The **invariant**, as distinct from the numbers: `SLACK` must be at least the per-entry framing that
`entry_cost` does not otherwise count (8 bytes today — the key's length prefix), so the estimate can
only ever fire *early*. `the_running_estimate_never_under_counts_a_real_leaf` asserts this as a
property across leaf sizes, so it survives a change to the constants above.

Issue #50's acceptance criterion — "`serialized_size`'s replacement re-derives the page-fitting
constants rather than inheriting the 8-byte-prefix assumption in a comment" — is **not** satisfied by
this PR. What exists now is a test that fails loudly if the constants stop holding. Re-deriving them
belongs with the swap, and §5 places it there.

---

## §4 — The candidates, honestly

### `wincode` — the only realistic *swap*

Named by bincode's own tombstone README as the bincode-compatible alternative. Compatibility is its
stated goal, which makes it the only candidate that could preserve every byte in §2 and leave §3
untouched.

**Not yet verified against LoomDB's types**, and "compatible in principle" is exactly the claim the
fixtures exist to check. The specific things to verify, because they are where a re-implementation is
most likely to differ, are: the four-byte enum tag (§2.5), the one-byte `Option` special case (§2.6),
the trailing-byte tolerance (§2.8), and whether it exposes a `serialized_size` that agrees with its
encoder (§2.10). The custom `commits_as_pairs` serde adapter in `refs.rs` and the `Box<T>` inside
`Record::Observation`/`Record::Claim` are also worth checking explicitly.

### `postcard` — well maintained, **not** format-compatible

`no_std`, actively maintained, a genuinely good format. It is varint-framed: a 300-element collection
spends 2 bytes on its length where bincode spends 8, and a 3-element one spends 1. So:

- every stored byte differs;
- **§3 changes** — more records fit per page, fanout and depth move, and the `SLACK` reasoning must
  be re-derived from scratch rather than adjusted;
- every capability token and every shipped bundle signature is invalidated.

This is a versioned on-disk migration, not a swap.

### `rkyv` — zero-copy, arguably the better long-term fit, definitely not compatible

Zero-copy access to page-resident nodes is the right shape for a B-tree — a leaf could be traversed
without decoding it at all, which would delete most of `tree.rs`'s size bookkeeping rather than
port it. It is also the largest change: a different derive, a different access model (archived types,
not owned ones), and an encoding with alignment and padding that has nothing to do with §2.

Worth wanting. Not worth coupling to an unmaintained-dependency fix.

### Doing nothing

Legitimate, and worth stating. bincode 1.3.3 is a frozen, widely-deployed, dependency-light crate
with no known vulnerability. Vendoring it (it is ~3k lines) is a smaller and more reversible action
than any swap, and it converts an unmaintained *dependency* into maintained *code we own* without
touching a byte. If §5's step 2 shows `wincode` is not byte-compatible, this is the recommendation.

---

## §5 — Recommended sequence, with the fixtures as the gate

1. **Land the fixtures first.** ← *this PR.* No serializer changes. `format-v1.golden` in each
   crate's `tests/fixtures/` records bincode 1.3.3's output for every type in §1, asserted in both
   directions, and the `page_fitting` tests record §3. Until this exists, no swap can be evaluated
   at all.

2. **Evaluate `wincode` in a throwaway branch.** Point the workspace at it, change nothing else, and
   run *only* `golden_format` and `page_fitting`. The question is binary and answered in an hour:
   does it reproduce §2 and §3, or not? Do not run the rest of the suite first — a green suite is not
   evidence (§1) and reading it as evidence is the failure mode this whole note exists to prevent.

3. **If byte-compatible:** land the swap as a mechanical change with the fixtures untouched. An
   unchanged `format-v1.golden` in the diff *is* the compatibility proof, and it is reviewable at a
   glance. Then re-derive the `SLACK` and `FILL_FACTOR` reasoning against the new encoder's actual
   framing so the comment stops asserting "8 bytes" on faith (issue #50's third criterion), and drop
   the bincode `cargo audit` allowance.

4. **If not byte-compatible**, this stops being a dependency task. Either vendor bincode 1.3.3 (§4)
   and close #50 as "no successor is compatible; the format is now ours", or commit to a versioned
   on-disk format:
   - bump `tree.rs::FORMAT_VERSION` and `refs.rs::REFS_FORMAT_VERSION`;
   - the store **refuses to open** an old format rather than misreading it — `Refs::decode` already
     does exactly this for a *future* version and is the pattern to copy;
   - keep `format-v1.golden` **as it is, forever**, and add `format-v2.golden` beside it, so the
     reader for the old format stays tested after the writer is gone;
   - `token.rs` and `loom-bundle` need separate, explicit decisions. Tokens are in-process and may
     simply be invalidated. Bundles already signed and distributed **cannot** be, so `loom-bundle`
     either keeps bincode for `signing_bytes()` regardless of what the storage layer does, or grows a
     v2 signature format that verifies v1 bundles indefinitely.

5. **Only then** run the full suite, and only as a regression check.

### What must never happen

- Regenerating a fixture to make a red test green. A red fixture means the on-disk format changed;
  regenerating removes the symptom and keeps the data loss. The `LOOMDB_UPDATE_GOLDEN=1` escape hatch
  exists to **add** cases, not to bless a diff.
- Deleting `format-v1.golden` when a v2 format lands. The v1 bytes are the only test that a v1
  reader still works. (The harness already flags a case that is committed but no longer generated,
  rather than letting it silently stop being checked.)
