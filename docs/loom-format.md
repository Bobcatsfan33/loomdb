# The LoomDB on-page format

> Format version **1**. A change here is a format change, and requires a migration path.

## Layout

LoomDB stores records in a **B+tree whose nodes are substrate pages**.

```
logical page 0   →  Meta { format_version, root, next_free, count }
logical page 1+  →  Node::Leaf | Node::Internal
```

## There is no copy-on-write code

A copy-on-write B-tree is famously fiddly: every update clones the leaf, then the parent, then the
grandparent, up to a new root, and you have to get the reference counting right.

We write none of it, because **substrate already is copy-on-write.** A node lives at a *logical* page
number; substrate maps logical pages to immutable content. Writing a node replaces the logical page's
content, and every manifest that existed before that write still points at the old content:

```
manifest v1 ──► page 3 ──► content Ab12…      (the old leaf, still perfectly readable)
manifest v2 ──► page 3 ──► content Cd34…      (the new leaf)
```

Node identity is a stable logical page number. Snapshot isolation is the manifest's problem, and it
has already solved it. This is what it means to build on the right foundation: the hard part is
missing.

## Nodes

```rust
enum Node {
    Leaf     { entries: Vec<(Key, Record)> },              // sorted by key
    Internal { keys: Vec<Key>, children: Vec<PageNo> },    // children.len() == keys.len() + 1
}
```

Encoded with bincode. A node splits when its encoding exceeds **70%** of the page size — not 100%,
because a node that fills its page exactly leaves no room for the *next* insert to be encoded before
the split is detected, and a split that cannot be encoded is a wedged database.

## Records

```rust
enum Record {
    Observation(Observation),   // what a source told us. never deleted; corrected.
    Claim(Claim),               // what we believe. possibly wrongly.
    Value(Value),               // a raw value, for stores that need no claim machinery
}

enum Value {
    Blob(Vec<u8>),              // opaque. NOT mergeable — goes to the merge policy.
    Counter(i64),               // additive. merges arithmetically.
    Set(BTreeSet<Vec<u8>>),     // additive. merges by union.
    Bool(bool), Text(String), Number(f64),
}
```

**Values are typed because the merge engine has to know how to combine them.** A blob it cannot
merge; a counter it can add; a set it can union. Typing values is what lets two agents work
concurrently without every write becoming a conflict — and most agent concurrency is a counter.

## Reserved keys

Keys beginning with `\x00loom/` belong to the engine. A leading NUL sorts before every printable key,
so they live at the front of the tree and out of everyone's way.

```
\x00loom/merged-from/<branch>   →  Blob(commit_id)   the last commit this branch absorbed from <branch>
```

They are hidden from `scan`, and **excluded from merge candidates** — the record of what a branch has
already merged must not itself be merged.

### Why that record exists

substrate's manifests have exactly **one parent**. Git's merge commits have two, and that is not a
stylistic difference: it is what makes a merge base correct the *second* time you merge.

Without it, merging twice re-applies the source's deltas, and a `+3` silently becomes a `+6`. The
database reports a clean merge and the number is wrong. So a branch remembers what it has absorbed,
and a fork inherits those records because it inherits the whole tree — which lets LoomDB reconstruct
the two-parent ancestry substrate cannot store.

The model oracle found this. It also found the two half-fixes that came before the real one.

## What is deliberately missing

**Deletes do not free logical pages.** A removed key leaves its leaf; an emptied leaf is left empty
rather than merged into a sibling and returned to a free list. This wastes logical page numbers in a
delete-heavy workload.

It is written down here rather than discovered later. Rebalancing on delete is where B-trees get most
of their bugs, and LoomDB's workload is overwhelmingly append-and-supersede: a semantic store *never*
deletes a fact, it closes the fact's validity interval. We will do it when a workload needs it, and
not before.

**Recursive merge over a virtual base.** When two branches have concurrently absorbed each other's
work, their history has more than one equally-valid merge base, and a three-way merge with any single
one of them is a guess. git merges the bases together into a virtual base. LoomDB **refuses**, loudly,
and tells the caller to merge one direction only or rebase.

That is the honest behaviour for now: a database that admits it does not know is worth considerably
more than one that guesses confidently and produces a number nobody can justify.
