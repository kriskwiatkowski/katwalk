// Copyright (c) 2019, Google Inc.
// Copyright (c) 2026, Kris Kwiatkowski
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.

use anyhow::{Context, Result};
use log::{debug, info};
use serde_json::Value;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

mod hash;
mod hqckem;
mod mldsa;
mod mlkem;
mod primitives;
use hash::{process_hash as process_fips202_hash, process_xof as process_fips202_xof};
use hqckem::process_hqckem;
use mldsa::process_mldsa;
use mlkem::process_mlkem;
use primitives::*;

/// Sentinel a wrapper binary returns as its sole result to signal that it
/// cannot perform the requested operation (e.g. an unimplemented parameter
/// set), rather than crashing the read-dispatch-write loop with an error.
const UNSUPPORTED: &[u8] = b"unsupported";

pub struct Subprocess {
    process: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    unsupported_count: usize,
    // Contexts already reported via `check_unsupported`, so a parameter set
    // that's unsupported across e.g. 100 test cases logs once, not 100 times.
    reported_unsupported: std::collections::HashSet<String>,
}

impl Subprocess {
    pub fn new(wrapper_path: &Path, param: Option<&str>) -> Result<Self> {
        info!("Starting subprocess: {:?}", wrapper_path);

        let mut cmd = Command::new(wrapper_path);
        if let Some(p) = param {
            cmd.arg(p);
        }

        let mut process = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("Failed to spawn subprocess: {:?}", wrapper_path))?;

        let stdin = process.stdin.take().context("Failed to open stdin")?;
        let stdout = process.stdout.take().context("Failed to open stdout")?;

        Ok(Self {
            process,
            stdin,
            stdout,
            unsupported_count: 0,
            reported_unsupported: std::collections::HashSet::new(),
        })
    }

    /// Checks whether `results` is a wrapper's "unsupported" response and, if
    /// so, counts it toward `unsupported_count`, logging `context` only the
    /// first time it's seen (a parameter set is typically unsupported across
    /// every test case that uses it, so this avoids one line per test case).
    pub fn check_unsupported(&mut self, results: &[Vec<u8>], context: &str) -> bool {
        let unsupported = results.len() == 1 && results[0] == UNSUPPORTED;
        if unsupported {
            self.unsupported_count += 1;
            if self.reported_unsupported.insert(context.to_string()) {
                eprintln!("UNSUPPORTED: wrapper does not support {context}");
            }
        }
        unsupported
    }

    pub fn unsupported_count(&self) -> usize {
        self.unsupported_count
    }

    pub fn transact(&mut self, cmd: &str, args: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
        debug!("Transact: cmd={}, args={}", cmd, args.len());

        let num_args = 1 + args.len();
        let mut buf = Vec::new();

        buf.extend_from_slice(&(num_args as u32).to_le_bytes());
        buf.extend_from_slice(&(cmd.len() as u32).to_le_bytes());

        for arg in args {
            buf.extend_from_slice(&(arg.len() as u32).to_le_bytes());
        }

        buf.extend_from_slice(cmd.as_bytes());
        for arg in args {
            buf.extend_from_slice(arg);
        }

        self.stdin.write_all(&buf)?;
        self.stdin.flush()?;

        let mut num_results_buf = [0u8; 4];
        self.stdout.read_exact(&mut num_results_buf)?;
        let num_results = u32::from_le_bytes(num_results_buf) as usize;

        let mut lengths = vec![0u32; num_results];
        for length in lengths.iter_mut().take(num_results) {
            let mut len_buf = [0u8; 4];
            self.stdout.read_exact(&mut len_buf)?;
            *length = u32::from_le_bytes(len_buf);
        }

        let mut results = Vec::new();
        for len in lengths {
            let mut data = vec![0u8; len as usize];
            self.stdout.read_exact(&mut data)?;
            results.push(data);
        }

        Ok(results)
    }

    pub fn get_config(&mut self) -> Result<Value> {
        let results = self.transact("getConfig", &[])?;
        if results.is_empty() {
            anyhow::bail!("No config returned from subprocess");
        }
        let config_str = String::from_utf8(results[0].clone())?;
        serde_json::from_str(&config_str).context("Failed to parse config JSON")
    }

    pub fn process_vectors(&mut self, test_vectors: &Value) -> Result<Value> {
        match test_vectors {
            Value::Array(vectors) => {
                let mut responses = Vec::new();
                for vector_set in vectors {
                    let response = self.process_vector_set(vector_set)?;
                    responses.push(response);
                }
                Ok(Value::Array(responses))
            }
            Value::Object(_) => self.process_vector_set(test_vectors),
            _ => anyhow::bail!("Invalid test vector format"),
        }
    }

    fn process_vector_set(&mut self, vector_set: &Value) -> Result<Value> {
        let algorithm = vector_set["algorithm"]
            .as_str()
            .context("Missing algorithm field")?;

        info!("Processing algorithm: {}", algorithm);

        match algorithm {
            "SHA2-224" | "SHA2-256" | "SHA2-384" | "SHA2-512" | "SHA2-512/224" | "SHA2-512/256" => {
                process_hash(self, vector_set)
            }
            "SHA3-224" | "SHA3-256" | "SHA3-384" | "SHA3-512" => {
                process_fips202_hash(self, vector_set)
            }
            "SHAKE-128" | "SHAKE-256" => process_fips202_xof(self, vector_set),
            "HMAC-SHA2-224" | "HMAC-SHA2-256" | "HMAC-SHA2-384" | "HMAC-SHA2-512"
            | "HMAC-SHA2-512/224" | "HMAC-SHA2-512/256" | "HMAC-SHA3-224" | "HMAC-SHA3-256"
            | "HMAC-SHA3-384" | "HMAC-SHA3-512" => process_hmac(self, vector_set),
            "hashDRBG" | "hmacDRBG" | "ctrDRBG" => process_drbg(self, vector_set),
            "ECDSA" => process_ecdsa(self, vector_set),
            "ML-DSA" => process_mldsa(self, vector_set),
            "ML-KEM" => process_mlkem(self, vector_set),
            "HQC" => process_hqckem(self, vector_set),
            "SLH-DSA" => process_slhdsa(self, vector_set),
            "LMS" => process_lms(self, vector_set),
            "XMSS" => process_xmss(self, vector_set),
            "KDF" => process_kdf(self, vector_set),
            "KDA" => process_kda(self, vector_set),
            "kdf-components" => process_tls_kdf(self, vector_set),
            "TLS-v1.3" => process_tls13(self, vector_set),
            "KAS-ECC-SSC" | "KAS-ECC" => process_kas(self, vector_set),
            _ => {
                anyhow::bail!("Unsupported algorithm: {}", algorithm)
            }
        }
    }
}

impl Drop for Subprocess {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_protocol_encoding() {
        // Test that protocol encoding matches expected format
        let cmd = "test";
        let args = vec![b"arg1".as_slice(), b"arg2".as_slice()];

        let num_args = 1 + args.len();
        let mut buf = Vec::new();

        buf.extend_from_slice(&(num_args as u32).to_le_bytes());
        buf.extend_from_slice(&(cmd.len() as u32).to_le_bytes());
        for arg in &args {
            buf.extend_from_slice(&(arg.len() as u32).to_le_bytes());
        }

        // Verify header
        assert_eq!(buf.len(), 4 * (2 + args.len())); // Header size
        assert_eq!(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), 3);
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), 4);
    }

    #[test]
    fn test_algorithm_matching() {
        let test_cases = vec![
            ("SHA2-256", true),
            ("SHA3-512", true),
            ("SHAKE-128", true),
            ("HMAC-SHA2-256", true),
            ("ML-DSA", true),
            ("INVALID-ALGO", false),
        ];

        for (algo, should_match) in test_cases {
            let is_valid = match algo {
                "SHA2-224" | "SHA2-256" | "SHA2-384" | "SHA2-512" | "SHA2-512/224"
                | "SHA2-512/256" | "SHA3-224" | "SHA3-256" | "SHA3-384" | "SHA3-512"
                | "SHAKE-128" | "SHAKE-256" | "HMAC-SHA2-224" | "HMAC-SHA2-256"
                | "HMAC-SHA2-384" | "HMAC-SHA2-512" | "HMAC-SHA2-512/224" | "HMAC-SHA2-512/256"
                | "HMAC-SHA3-224" | "HMAC-SHA3-256" | "HMAC-SHA3-384" | "HMAC-SHA3-512"
                | "hashDRBG" | "hmacDRBG" | "ctrDRBG" | "ECDSA" | "ML-DSA" | "ML-KEM"
                | "SLH-DSA" | "LMS" | "XMSS" | "KDF" | "KDA" | "kdf-components" | "TLS-v1.3"
                | "KAS-ECC-SSC" | "KAS-ECC" => true,
                _ => false,
            };

            if should_match {
                assert!(is_valid, "Algorithm {} should be valid", algo);
            }
        }
    }
}
