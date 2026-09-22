# Quick Start

Get up and running with katwalk in minutes.

## Prerequisites

- Rust 1.85 or later (required by the built-in ML-DSA implementation;
  [install via rustup](https://rustup.rs))
- A modulewrapper binary (either an external C++ modulewrapper, or a built-in
  wrapper for ML-KEM or ML-DSA)

## Installation

See [Installation](installation.md).

## 1. Query Module Capabilities

```bash
./target/release/katwalk \
  --wrapper ../build/modulewrapper/modulewrapper \
  --regcap
```

This prints the cryptographic capabilities of your module as JSON.

## 2. Process Test Vectors

Run a vector set against a wrapper and write the responses to a file:

```bash
./target/release/katwalk \
  --wrapper ../build/modulewrapper/modulewrapper \
  --in test_vectors.json \
  --out responses.json
```

## 3. Verify Responses Against Expected Results

Add `--expected` to compare the generated responses against a known-good expected results file.
Exit code is non-zero on any mismatch:

```bash
./target/release/katwalk \
  --wrapper ../build/modulewrapper/modulewrapper \
  --in  prompt.json \
  --out responses.json \
  --expected expectedResults.json
```

On success:

```
PASS
```

On failure, each mismatching field is printed before the error:

```
FAIL tgId=1 tcId=3 field=k: expected="ab12..." actual="cd34..."
Error: 1/42 field(s) did not match
```

## 4. Process a Directory of Vector Sets

```bash
./target/release/katwalk \
  --wrapper ../build/modulewrapper/modulewrapper \
  --indir  ./test_vectors/ \
  --outdir ./responses/
```

Every `.json` and `.zip` file in `--indir` is processed; output files land in `--outdir` with the same name.

## 5. Process a Test-Set Manifest

Use `--testset` to run several input/expected-result pairs in one invocation.
Every entry is verified against its own expected-results file. Relative paths in
the manifest resolve against the directory you run katwalk from, so the manifest
itself can live anywhere:

```json
{
  "tests": [
    {
      "in": "SHA3-256/prompt.json",
      "expected": "SHA3-256/expectedResults.json"
    },
    {
      "in": "SHAKE-128/prompt.json",
      "expected": "SHAKE-128/expectedResults.json",
      "out": "shake-128-responses.json"
    }
  ]
}
```

```bash
./target/release/katwalk \
  --wrapper ./target/release/fips202_wrapper \
  --testset /path/to/fips202-testset.json \
  --outdir /tmp/fips202-responses
```

Responses are written only where an entry has an `out` or `--outdir` is
supplied; otherwise entries are verified in memory. Output paths must be unique
and must not already exist.

See [Test-Set Manifests](testset.md) for the full manifest schema, path
resolution rules and failure output.

## ML-KEM with the Built-in Wrapper

`katwalk` ships a self-contained `mlkem_wrapper` binary (backed by the `mlkem-edu` library) so you can test ML-KEM without the C++ modulewrapper:

```bash
cargo build --release

# Generate responses
./target/release/katwalk \
  --wrapper ./target/release/mlkem_wrapper \
  --in  /path/to/ML-KEM-keyGen-FIPS203/prompt.json \
  --out /tmp/keygen_responses.json

# Generate and verify in one step
./target/release/katwalk \
  --wrapper ./target/release/mlkem_wrapper \
  --in  /path/to/ML-KEM-keyGen-FIPS203/prompt.json \
  --out /tmp/keygen_responses.json \
  --expected /path/to/ML-KEM-keyGen-FIPS203/expectedResults.json

./target/release/katwalk \
  --wrapper ./target/release/mlkem_wrapper \
  --in  /path/to/ML-KEM-encapDecap-FIPS203/prompt.json \
  --out /tmp/encapdecap_responses.json \
  --expected /path/to/ML-KEM-encapDecap-FIPS203/expectedResults.json
```

Both vector sets print `PASS` when all 240 FIPS-203 test cases match.

## CLI Reference

| Flag | Description |
|---|---|
| `--wrapper <path>` | Path to the modulewrapper binary **(required)** |
| `--in <file>` | Input vector set (JSON or ZIP) |
| `--out <file>` | Output responses file |
| `--expected <file>` | Expected results file; enables verification |
| `--indir <dir>` | Input directory (batch mode) |
| `--outdir <dir>` | Output directory for `--indir` or `--testset` |
| `--testset <file>` | JSON manifest of input/expected vector-set pairs |
| `--regcap` | Print module capabilities and exit |
| `--param <string>` | Optional argument forwarded to the wrapper |
| `--config <file>` | Config file for ACVP server mode (default: `config.json`) |
