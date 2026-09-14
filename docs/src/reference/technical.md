# Technical Reference

## Overview

katwalk is a Rust implementation of an ACVP (Automated Cryptographic Validation Protocol) test harness. It processes cryptographic test vectors from JSON or ZIP files, forwards operations to an external wrapper binary over a binary protocol, and optionally verifies responses against known-good expected results.

## Project Structure

```
katwalk/
├── src/
│   ├── main.rs                    # CLI entry point and orchestration
│   ├── config.rs                  # Configuration file parsing
│   ├── utils.rs                   # ZIP handling, hex encoding
│   ├── acvp/mod.rs                # ACVP server client skeleton
│   └── subprocess/
│       ├── mod.rs                 # Subprocess protocol + algorithm router
│       └── primitives.rs          # Per-algorithm vector processing
├── src/bin/
│   ├── mlkem_wrapper.rs           # Built-in ML-KEM wrapper binary
│   └── mldsa_wrapper.rs           # Built-in ML-DSA wrapper binary
├── docs/                          # mdBook documentation
├── tests/                         # Integration and CLI tests
└── Cargo.toml
```

## Subprocess Protocol

All cryptographic work is delegated to an external wrapper binary via stdin/stdout using a binary framing protocol (little-endian `u32` throughout):

**Request**
```
[num_args: u32][cmd_len: u32][arg1_len: u32]...[cmd bytes][arg1 bytes]...
```

**Response**
```
[num_results: u32][res1_len: u32]...[res1 bytes]...
```

`Subprocess::transact(cmd, args)` in `subprocess/mod.rs` implements the client side. The wrapper binary implements the server side.

## Algorithm Support

### Fully Implemented

| Algorithm | Mode / Functions |
|---|---|
| SHA2-224/256/384/512, SHA2-512/224/256 | AFT |
| SHA3-224/256/384/512 | AFT |
| SHAKE-128, SHAKE-256 | AFT (variable output length) |
| HMAC-SHA2-\*, HMAC-SHA3-\* | AFT |
| **ML-KEM** (FIPS 203) | keyGen, encapsulation, decapsulation, encapsulationKeyCheck, decapsulationKeyCheck |
| **ML-DSA** (FIPS 204) | keyGen, internal/external sigGen, internal/external sigVer |

ML-DSA registration advertises deterministic and ACVP-provided 32-byte
randomness, the internal and external signature interfaces, supplied or
internally computed `mu`, and pure or pre-hash external signatures. The
pre-hash implementation supports the SHA-2, SHA-3, and SHAKE algorithms
listed in FIPS 204's HashML-DSA profile, including SHA3-256, SHA3-512,
SHAKE-128, and SHAKE-256 for every ML-DSA parameter set.

### Stub (returns empty responses)

ECDSA, SLH-DSA, LMS, XMSS, hashDRBG, hmacDRBG, ctrDRBG, KDF, KDA, TLS-KDF, TLS-v1.3, KAS-ECC, KAS-ECC-SSC.

## ML-KEM Implementation

### Subprocess Commands

| Command | Args | Returns |
|---|---|---|
| `ML-KEM/keyGen` | `param_set`, `seed` (64 B = z‖d) | `[ek, dk]` |
| `ML-KEM/encaps` | `param_set`, `ek`, `m` (32 B) | `[c, k]` |
| `ML-KEM/decaps` | `param_set`, `dk`, `ct` | `[k]` |
| `ML-KEM/encapsulationKeyCheck` | `param_set`, `ek` | `[0x01]` or `[0x00]` |
| `ML-KEM/decapsulationKeyCheck` | `param_set`, `dk` | `[0x01]` or `[0x00]` |

Parameter sets: `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`.

### mlkem_wrapper Binary

`src/bin/mlkem_wrapper.rs` is a self-contained wrapper binary that implements the protocol above using the `mlkem-edu` Rust library (FIPS 203). It can replace the C++ modulewrapper for ML-KEM-only workloads:

```bash
katwalk --wrapper ./target/release/mlkem_wrapper --in prompt.json --out out.json
```

### Key Sizes (FIPS 203)

| Parameter Set | EK (ek) | DK (dk) | Ciphertext (c) | Shared Secret (k) |
|---|---|---|---|---|
| ML-KEM-512 | 800 B | 1632 B | 768 B | 32 B |
| ML-KEM-768 | 1184 B | 2400 B | 1088 B | 32 B |
| ML-KEM-1024 | 1568 B | 3168 B | 1568 B | 32 B |

DK internal layout (FIPS 203 §6.3): `pke_dk ‖ ek ‖ H(ek) ‖ z`.

## ML-DSA Implementation

`src/bin/mldsa_wrapper.rs` is a self-contained FIPS 204 wrapper using the
RustCrypto `ml-dsa` implementation. It accepts NIST ACVP vectors for `keyGen`,
`sigGen`, and `sigVer`:

| Command | Args | Returns |
|---|---|---|
| `ML-DSA/keyGen` | `parameter_set`, `seed` (32 B) | `[pk, sk]` |
| `ML-DSA/signInternal` | `parameter_set`, `key_format`, `key`, `message`, `rnd` (32 B) | `[signature]` |
| `ML-DSA/verifyInternal` | `parameter_set`, `pk`, `message`, `signature` | `[0x01]` or `[0x00]` |
| `ML-DSA/signMu` | `parameter_set`, `key_format`, `key`, `mu` (64 B), `rnd` (32 B) | `[signature]` |
| `ML-DSA/verifyMu` | `parameter_set`, `pk`, `mu` (64 B), `signature` | `[0x01]` or `[0x00]` |
| `ML-DSA/signExternal` | `parameter_set`, `key_format`, `key`, `message`, `context`, `pre_hash`, `hash_alg`, `rnd` (32 B) | `[signature]` |
| `ML-DSA/verifyExternal` | `parameter_set`, `pk`, `message`, `context`, `pre_hash`, `hash_alg`, `signature` | `[0x01]` or `[0x00]` |

Parameter sets: `ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87`. Expanded secret
keys are 2560, 4032, and 4896 bytes; public keys are 1312, 1952, and 2592
bytes; signatures are 2420, 3309, and 4627 bytes, respectively. The external
pre-hash path encodes `0x01 || len(context) || context || OID || PH(message)`
before internal signing, as specified by FIPS 204; contexts longer than 255
bytes and unsupported hash algorithms are rejected.

## Response Verification (`--expected`)

When `--expected <file>` is passed alongside `--in`/`--out`, `check_expected()` in `main.rs` compares every field in the expected results file against the generated output:

- **String fields** (hex values): compared case-insensitively.
- **Boolean and numeric fields**: compared exactly.
- Groups and tests are matched by `tgId` / `tcId`.

Exit code is 0 on full match (`PASS` printed to stdout). On any mismatch, each failing field is printed to stderr and the process exits non-zero:

```
FAIL tgId=1 tcId=3 field=k: expected="ab12..." actual="cd34..."
Error: 1/42 field(s) did not match
```

## Adding a New Algorithm

1. Add a `process_<algo>()` function in `subprocess/primitives.rs` following the pattern of `process_mlkem()`.
2. Register it in the `match algorithm` block in `subprocess/mod.rs`.
3. If a new wrapper binary is needed, add it under `src/bin/` and register a `[[bin]]` entry in `Cargo.toml`.

## Testing

```
cargo test                     # run all 47 tests
cargo test mlkem               # run ML-KEM unit tests only
cargo test mlkem -- --nocapture  # with subprocess output
```

The ML-KEM unit tests in `primitives.rs` spawn `mlkem_wrapper` as a real subprocess and cover:

- Known-answer correctness for keyGen, encapsulation, decapsulation
- Key validation accepting well-formed keys
- Key validation rejecting malformed keys (wrong length, non-canonical NTT coefficients, corrupt H(ek))
- Error propagation for missing fields, invalid hex, unknown mode/function

## Dependencies

| Crate | Purpose |
|---|---|
| `mlkem-edu` | ML-KEM (FIPS 203) implementation used by `mlkem_wrapper` |
| `ml-dsa` | ML-DSA (FIPS 204) implementation used by `mldsa_wrapper` |
| `serde` / `serde_json` | JSON serialization |
| `clap` | CLI argument parsing |
| `anyhow` / `thiserror` | Error handling |
| `hex` | Hex encoding/decoding |
| `zip` | ZIP archive reading |
| `tokio` | Async runtime (ACVP server mode) |
| `reqwest` | HTTP client (ACVP server mode) |
| `sha2` / `hmac` | Internal crypto |
| `totp-lite` / `x509-parser` | ACVP server authentication |
