//! MCP (Model Context Protocol) server mode.
//!
//! Exposes katwalk's vector generation and KAT-running functionality as
//! tools over stdio, so an AI coding assistant can generate adversarial
//! test vectors for a cryptographic primitive and run them against a
//! wrapper binary without a human shuttling hex blobs back and forth.

mod hqckem;
mod kat;
mod mlkem;
mod sha3;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler, ServiceExt};
use schemars::JsonSchema;
use serde::Deserialize;

/// Deterministic, non-repeating fill patterns cycled across test cases so
/// same-length/same-role vectors don't all exercise the same byte value.
/// Shared by every per-algorithm vector generator.
fn fill(pattern: usize, len: usize) -> Vec<u8> {
    match pattern % 5 {
        0 => vec![0x00; len],
        1 => vec![0xFF; len],
        2 => (0..len).map(|i| (i % 256) as u8).collect(),
        3 => (0..len)
            .map(|i| if i % 2 == 0 { 0xA5 } else { 0x5A })
            .collect(),
        _ => (0..len)
            .map(|i| (0x9E_u32 * (i as u32 + 1) % 256) as u8)
            .collect(),
    }
}

fn generate_for(req: &GenerateVectorsRequest) -> anyhow::Result<String> {
    let name = req.algorithm.to_ascii_uppercase();
    if name.starts_with("SHA3") || name.starts_with("SHAKE") {
        sha3::generate(req)
    } else if name.starts_with("ML-KEM") {
        mlkem::generate(req)
    } else if name.starts_with("HQC") {
        hqckem::generate(req)
    } else {
        anyhow::bail!(
            "Unsupported algorithm {}; expected SHA3-224/256/384/512, SHAKE-128/256, \
             ML-KEM (or ML-KEM-512/768/1024), or HQC (or HQC-128/192/256)",
            req.algorithm
        )
    }
}

#[derive(Debug, Clone)]
pub struct KatwalkMcp;

/// Starts katwalk in MCP server mode, serving tools over stdio until the
/// client disconnects.
pub async fn serve() -> anyhow::Result<()> {
    KatwalkMcp
        .serve(rmcp::transport::io::stdio())
        .await?
        .waiting()
        .await?;
    Ok(())
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GenerateVectorsRequest {
    /// Algorithm to generate adversarial test vectors for. One of:
    /// SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE-128, SHAKE-256,
    /// ML-KEM (all three parameter sets) or ML-KEM-512/768/1024,
    /// HQC (all three parameter sets) or HQC-128/192/256.
    algorithm: String,
    /// Directory to write the generated vector-set and expected-results
    /// JSON files into. Defaults to a fresh directory under the system
    /// temp directory.
    out_dir: Option<String>,
    /// SHA-3/SHAKE only: also generate a 1 MiB stress vector to catch
    /// fixed-size buffer assumptions. Slower to hash. Defaults to false.
    include_large: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct RunKatRequest {
    /// Path to the wrapper binary under test. It must speak the ACVP
    /// modulewrapper stdin/stdout framing protocol.
    wrapper: String,
    /// Optional parameter string passed to the wrapper binary.
    param: Option<String>,
    /// Path to the vector-set JSON (or .zip of JSON files) to run.
    vectors: String,
    /// Optional path to an expected-results JSON file to diff the
    /// wrapper's responses against.
    expected: Option<String>,
    /// Optional path to write the wrapper's raw responses JSON to.
    /// Defaults to a fresh file under the system temp directory.
    out: Option<String>,
}

#[tool_router]
impl KatwalkMcp {
    #[tool(
        description = "Generate adversarial/boundary test vectors designed to break an \
         implementation of SHA-3/SHAKE, ML-KEM, or HQC-KEM, together with independently \
         computed expected results (keys, ciphertexts, shared secrets, or digests -- an \
         oracle library distinct from the wrapper under test). For hash/XOF algorithms this \
         covers rate-boundary message and output lengths; for the KEMs it covers edge-case \
         keygen seeds, nominal encaps/decaps, and -- importantly -- decapsulation of \
         bit-flipped ciphertexts, which must produce a deterministic implicit-rejection \
         shared secret rather than crash or diverge. Writes both vectors and expected \
         results as JSON files -- rather than returning them, which can be large -- and \
         returns their paths plus a short summary. Feed the paths to run_kat to execute them \
         against a wrapper binary."
    )]
    async fn generate_vectors(
        &self,
        Parameters(req): Parameters<GenerateVectorsRequest>,
    ) -> Result<String, ErrorData> {
        tokio::task::spawn_blocking(move || generate_for(&req))
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
    }

    #[tool(
        description = "Run a vector-set JSON file against a wrapper binary (the ACVP \
         modulewrapper stdin/stdout protocol) and, if an expected-results file is given, \
         diff the responses against it. Returns a pass/fail summary and the path to the \
         full responses JSON, rather than the raw ACVP payload, to avoid flooding the \
         conversation with large JSON."
    )]
    async fn run_kat(
        &self,
        Parameters(req): Parameters<RunKatRequest>,
    ) -> Result<String, ErrorData> {
        tokio::task::spawn_blocking(move || kat::run(&req))
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
    }
}

#[tool_handler(
    name = "katwalk-mcp",
    version = "0.1.0",
    instructions = "Tools for generating adversarial KAT vectors for SHA-3/SHAKE, ML-KEM, and \
     HQC-KEM, and running them against a wrapper binary that speaks the ACVP modulewrapper \
     protocol. Typical flow: call generate_vectors for the algorithm under test, then run_kat \
     with the wrapper under test and the paths generate_vectors returned."
)]
impl ServerHandler for KatwalkMcp {}
