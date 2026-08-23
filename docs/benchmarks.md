# Benchmarks

How to run a benchmark **on purpose**. Do **not** use `cargo test --all-targets` —
`harness = false` benches can be executed unintentionally that way.

## Index

- `loom-branch` / `ann_amplification` — `cargo bench -p loom-branch --bench ann_amplification`
- `loom-branch` / `ann_vs_scan` — `cargo bench -p loom-branch --bench ann_vs_scan`
- `loom-branch` / `branching` — `cargo bench -p loom-branch --bench branching`
- `loom-branch` / `refs_scaling` — `cargo bench -p loom-branch --bench refs_scaling`

## Examples

```sh
cargo bench -p loom-branch --bench branching
LOOM_SEED_BATCH=1000000 LOOM_BENCH_SIZES=1000000 cargo bench -p loom-branch --bench branching
```

Filter a single bench function after `--`:

```sh
cargo bench -p loom-branch --bench branching -- my_bench_name
```

