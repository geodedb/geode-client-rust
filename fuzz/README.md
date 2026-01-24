# Fuzzing for geode-client

This directory contains fuzz targets for the geode-client library using
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and libFuzzer.

## Prerequisites

Fuzzing requires nightly Rust:

```bash
rustup install nightly
```

Install cargo-fuzz:

```bash
cargo install cargo-fuzz
```

## Available Fuzz Targets

| Target | Description |
|--------|-------------|
| `fuzz_value_from_json` | Tests `Value::from_json()` with arbitrary JSON |
| `fuzz_query_builder` | Tests `QueryBuilder` with arbitrary strings |
| `fuzz_pattern_builder` | Tests `PatternBuilder` with arbitrary patterns |
| `fuzz_json_parsing` | Tests JSON parsing and Value conversion |

## Running Fuzz Tests

List available targets:

```bash
cargo +nightly fuzz list
```

Run a specific target:

```bash
cargo +nightly fuzz run fuzz_value_from_json
```

Run with a time limit:

```bash
cargo +nightly fuzz run fuzz_value_from_json -- -max_total_time=60
```

Run all targets for 30 seconds each:

```bash
for target in $(cargo +nightly fuzz list); do
    echo "Fuzzing $target..."
    cargo +nightly fuzz run "$target" -- -max_total_time=30
done
```

## Corpus

The fuzzer will save interesting inputs to `fuzz/corpus/<target>/`. These
inputs represent edge cases that achieved new code coverage.

To minimize the corpus:

```bash
cargo +nightly fuzz cmin fuzz_value_from_json
```

## Crash Investigation

When the fuzzer finds a crash, it saves the input to `fuzz/artifacts/<target>/`.
To reproduce:

```bash
cargo +nightly fuzz run fuzz_value_from_json fuzz/artifacts/fuzz_value_from_json/crash-<hash>
```

## Coverage

To generate a coverage report:

```bash
cargo +nightly fuzz coverage fuzz_value_from_json
```

## Property-Based Testing Alternative

If you don't have nightly Rust, you can run property-based tests with proptest
instead:

```bash
cargo test --test proptest
```

This provides similar benefits using stable Rust.
