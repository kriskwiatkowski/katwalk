# API Reference

This page documents the internal APIs and interfaces of katwalk.

## Module Structure

```
katwalk/
├── main.rs          - CLI entry point
├── config.rs        - Configuration handling
├── utils.rs         - Utility functions
├── acvp/           - ACVP server client
│   └── mod.rs
└── subprocess/     - Modulewrapper interface
    ├── mod.rs      - Protocol implementation
    └── primitives.rs - Algorithm handlers
```

## Core Modules

### main

**Entry point and CLI handling.**

#### `main()` -> `Result<()>`

Async main function that:
1. Parses CLI arguments
2. Initializes logging
3. Routes to appropriate handler
4. Returns exit code

#### `process_vectors_from_file()`

```rust
fn process_vectors_from_file(
    wrapper_path: &Path,
    param: Option<&str>,
    input: &PathBuf,
    output: &PathBuf,
) -> Result<()>
```

Processes a single test vector file (JSON or ZIP).

**Parameters:**
- `wrapper_path`: Path to modulewrapper binary
- `param`: Optional parameter for modulewrapper
- `input`: Input file path
- `output`: Output file path

**Returns:** `Result<()>`

#### `process_vectors_from_directory()`

```rust
fn process_vectors_from_directory(
    wrapper_path: &Path,
    param: Option<&str>,
    indir: &PathBuf,
    outdir: &PathBuf,
) -> Result<()>
```

Batch processes all test vector files in a directory.

**Parameters:**
- `wrapper_path`: Path to modulewrapper binary
- `param`: Optional parameter for modulewrapper
- `indir`: Input directory path
- `outdir`: Output directory path

**Returns:** `Result<()>`

### config

**Configuration file parsing.**

#### `Config`

```rust
pub struct Config {
    pub cert_pem_file: Option<String>,
    pub private_key_file: Option<String>,
    pub private_key_der_file: Option<String>,
    pub totp_secret: Option<String>,
    pub acvp_server: String,
    pub session_tokens_cache: Option<String>,
    pub log_file: Option<String>,
}
```

#### `Config::from_file()`

```rust
pub fn from_file(path: &Path) -> Result<Self>
```

Loads configuration from JSON file with comment support.

**Parameters:**
- `path`: Path to config file

**Returns:** `Result<Config>`

### utils

**Utility functions.**

#### `read_vectors_from_zip()`

```rust
pub fn read_vectors_from_zip(path: &Path) -> Result<String>
```

Reads and combines all JSON files from a ZIP archive.

**Parameters:**
- `path`: Path to ZIP file

**Returns:** `Result<String>` - Combined JSON array

#### `hex_to_bytes()`

```rust
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>>
```

Decodes hex string to bytes.

#### `bytes_to_hex()`

```rust
pub fn bytes_to_hex(bytes: &[u8]) -> String
```

Encodes bytes to hex string.

### subprocess

**Modulewrapper communication protocol.**

#### `Subprocess`

```rust
pub struct Subprocess {
    process: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}
```

Manages subprocess and implements binary protocol.

#### `Subprocess::new()`

```rust
pub fn new(wrapper_path: &Path, param: Option<&str>) -> Result<Self>
```

Spawns modulewrapper subprocess.

**Parameters:**
- `wrapper_path`: Path to modulewrapper
- `param`: Optional parameter

**Returns:** `Result<Subprocess>`

#### `Subprocess::transact()`

```rust
pub fn transact(&mut self, cmd: &str, args: &[&[u8]]) -> Result<Vec<Vec<u8>>>
```

Sends command to subprocess and receives response.

**Parameters:**
- `cmd`: Command name
- `args`: Command arguments as byte slices

**Returns:** `Result<Vec<Vec<u8>>>` - Response data

**Protocol:**
- Request: `[num_args:u32][len_cmd:u32][len_arg1:u32]...[cmd:bytes][arg1:bytes]...`
- Response: `[num_results:u32][len_res1:u32]...[res1:bytes]...`
- All integers are little-endian

#### `Subprocess::get_config()`

```rust
pub fn get_config(&mut self) -> Result<Value>
```

Retrieves module capabilities JSON.

#### `Subprocess::process_vectors()`

```rust
pub fn process_vectors(&mut self, test_vectors: &Value) -> Result<Value>
```

Processes test vectors and returns responses.

**Parameters:**
- `test_vectors`: JSON test vectors

**Returns:** `Result<Value>` - JSON responses

### subprocess::primitives

**Algorithm-specific handlers.**

Each handler follows this pattern:

```rust
pub fn process_<algorithm>(
    subprocess: &mut Subprocess,
    vector_set: &Value
) -> Result<Value>
```

**Implemented algorithms:**
- `process_hash()` - SHA-2, SHA-3
- `process_xof()` - SHAKE
- `process_hmac()` - HMAC variants
- `process_drbg()` - DRBG variants
- `process_ecdsa()` - ECDSA
- `process_mldsa()` - ML-DSA
- `process_mlkem()` - ML-KEM
- `process_slhdsa()` - SLH-DSA
- `process_lms()` - LMS
- `process_xmss()` - XMSS
- `process_kdf()` - KDF
- `process_kda()` - KDA
- `process_tls_kdf()` - TLS KDF
- `process_tls13()` - TLS 1.3
- `process_kas()` - KAS-ECC

## Error Handling

All functions return `Result<T>` using the `anyhow` crate:

```rust
use anyhow::{Context, Result};

fn example() -> Result<()> {
    let data = std::fs::read("file.txt")
        .context("Failed to read file")?;
    Ok(())
}
```

Error context is added at each level for better debugging.

## Binary Protocol

### Request Format

```
Offset  Size  Field
0       4     num_args (u32, little-endian)
4       4     len_cmd (u32, little-endian)
8       4     len_arg1 (u32, little-endian)
...     4     len_argN (u32, little-endian)
        var   cmd (bytes)
        var   arg1 (bytes)
        var   argN (bytes)
```

### Response Format

```
Offset  Size  Field
0       4     num_results (u32, little-endian)
4       4     len_res1 (u32, little-endian)
...     4     len_resN (u32, little-endian)
        var   res1 (bytes)
        var   resN (bytes)
```

### Example Transaction

Command: `"SHA2-256"` with message `[0x61, 0x62, 0x63]`

**Request bytes:**
```
02 00 00 00  // 2 args (command + message)
08 00 00 00  // command length = 8
03 00 00 00  // arg1 length = 3
53 48 41 32 2d 32 35 36  // "SHA2-256"
61 62 63  // message bytes
```

**Response bytes:**
```
01 00 00 00  // 1 result
20 00 00 00  // result length = 32
ba 78 16 bf ... // 32-byte hash
```

## JSON Formats

### Test Vector Format

```json
{
  "vsId": 12345,
  "algorithm": "SHA2-256",
  "revision": "1.0",
  "testGroups": [{
    "tgId": 1,
    "testType": "AFT",
    "tests": [{
      "tcId": 1,
      "msg": "616263"
    }]
  }]
}
```

### Response Format

```json
{
  "vsId": 12345,
  "algorithm": "SHA2-256",
  "revision": "1.0",
  "testGroups": [{
    "tgId": 1,
    "tests": [{
      "tcId": 1,
      "md": "ba7816bf..."
    }]
  }]
}
```

## Type Aliases

```rust
use serde_json::Value;
use anyhow::Result;
use std::path::{Path, PathBuf};
```

## Constants

```rust
const DEFAULT_CONFIG: &str = "config.json";
```

## CLI Arguments

See `Args` struct in `main.rs`:

```rust
#[derive(Parser)]
#[command(name = "katwalk")]
#[command(about = "ACVP client for testing cryptographic implementations")]
struct Args {
    #[arg(long)]
    regcap: bool,

    #[arg(short, long, default_value = "config.json")]
    config: String,

    #[arg(long)]
    in_file: Option<PathBuf>,

    #[arg(long)]
    out: Option<PathBuf>,

    // ... more fields
}
```

## Dependencies

Key external crates:

- `anyhow` - Error handling
- `clap` - CLI parsing
- `serde` / `serde_json` - JSON serialization
- `tokio` - Async runtime
- `reqwest` - HTTP client
- `hex` - Hex encoding
- `zip` - ZIP archive support
- `log` / `env_logger` - Logging

## Thread Safety

The `Subprocess` struct is **not** thread-safe. Create one instance per thread if parallel processing is needed.

## Performance Notes

- Binary protocol minimizes serialization overhead
- Hex encoding/decoding optimized with `hex` crate
- JSON parsing uses `serde_json` (fast and zero-copy where possible)
- Subprocess I/O is synchronous (blocking)

## Future API Considerations

Potential improvements:

1. **Async subprocess**: Use `tokio::process` for async I/O
2. **Parallel processing**: Process multiple test groups concurrently
3. **Streaming**: Process large files without loading into memory
4. **Builder pattern**: For `Subprocess` and `Config` construction
