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

## Sizing a sweep

Every bench here is `harness = false` — a plain `main()`, not Criterion and not libtest. There is
therefore **no `-- <filter>` argument**: whatever follows `--` is handed to the bench binary, which
ignores it, so `cargo bench --bench branching -- some_name` silently runs the whole bench anyway.
Select the bench with `--bench`, and size the sweep with environment variables:

| bench | variables | defaults |
| --- | --- | --- |
| `branching` | `LOOM_BENCH_SIZES`, `LOOM_SEED_BATCH` | `1000,10000,100000,1000000`, `10000` |
| `ann_amplification` | `ANN_SIZES` | `1000,5000,20000` |
| `ann_vs_scan` | `ANN_VS_SCAN_SIZES` | `1000,10000,50000` |
| `refs_scaling` | `REFS_SIZES`, `REFS_SAMPLES` | `10,1000,100000`, `21` |
