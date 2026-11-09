//! Adversarial SHA-3/SHAKE test-vector generation.
//!
//! Boundary lengths are chosen relative to each variant's Keccak sponge
//! rate, since that's where off-by-one buffer and padding bugs in a
//! hand-written implementation tend to live. Expected outputs are computed
//! independently with the RustCrypto `sha3` crate, which already backs
//! `fips202_wrapper`, so these vectors are only useful against some *other*
//! implementation under test.

use super::GenerateVectorsRequest;
use anyhow::{Context, Result};
use serde_json::json;
use sha3::digest::{Digest, ExtendableOutput, Update, XofReader};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};
use std::path::PathBuf;

#[derive(Clone, Copy)]
enum Kind {
    Hash,
    Xof,
}

struct Algo {
    name: &'static str,
    rate_bytes: usize,
    kind: Kind,
}

fn algo(name: &str) -> Result<Algo> {
    Ok(match name {
        "SHA3-224" => Algo {
            name: "SHA3-224",
            rate_bytes: 144,
            kind: Kind::Hash,
        },
        "SHA3-256" => Algo {
            name: "SHA3-256",
            rate_bytes: 136,
            kind: Kind::Hash,
        },
        "SHA3-384" => Algo {
            name: "SHA3-384",
            rate_bytes: 104,
            kind: Kind::Hash,
        },
        "SHA3-512" => Algo {
            name: "SHA3-512",
            rate_bytes: 72,
            kind: Kind::Hash,
        },
        "SHAKE-128" => Algo {
            name: "SHAKE-128",
            rate_bytes: 168,
            kind: Kind::Xof,
        },
        "SHAKE-256" => Algo {
            name: "SHAKE-256",
            rate_bytes: 136,
            kind: Kind::Xof,
        },
        other => anyhow::bail!(
            "Unsupported algorithm {other}; expected one of SHA3-224, SHA3-256, \
             SHA3-384, SHA3-512, SHAKE-128, SHAKE-256"
        ),
    })
}

/// Lengths around 1x/2x the sponge rate (absorb-boundary padding/offset
/// bugs), plus a multi-block length and, optionally, a large one to catch
/// fixed-size buffer assumptions.
fn boundary_lengths(rate: usize, include_large: bool) -> Vec<usize> {
    let mut lengths = vec![
        0,
        1,
        rate.saturating_sub(1),
        rate,
        rate + 1,
        2 * rate - 1,
        2 * rate,
        2 * rate + 1,
        5 * rate + 3,
    ];
    if include_large {
        lengths.push(1 << 20); // 1 MiB
    }
    lengths.sort_unstable();
    lengths.dedup();
    lengths
}

fn compute_hash(name: &str, msg: &[u8]) -> Vec<u8> {
    match name {
        "SHA3-224" => Sha3_224::digest(msg).to_vec(),
        "SHA3-256" => Sha3_256::digest(msg).to_vec(),
        "SHA3-384" => Sha3_384::digest(msg).to_vec(),
        "SHA3-512" => Sha3_512::digest(msg).to_vec(),
        _ => unreachable!("algo() already validated the name"),
    }
}

fn compute_xof(name: &str, msg: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    match name {
        "SHAKE-128" => {
            let mut hasher = Shake128::default();
            hasher.update(msg);
            hasher.finalize_xof().read(&mut out);
        }
        "SHAKE-256" => {
            let mut hasher = Shake256::default();
            hasher.update(msg);
            hasher.finalize_xof().read(&mut out);
        }
        _ => unreachable!("algo() already validated the name"),
    }
    out
}

pub fn generate(req: &GenerateVectorsRequest) -> Result<String> {
    let a = algo(&req.algorithm)?;
    let include_large = req.include_large.unwrap_or(false);
    let out_dir = match &req.out_dir {
        Some(dir) => PathBuf::from(dir),
        None => std::env::temp_dir().join(format!("katwalk-mcp-{}", std::process::id())),
    };
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create output directory {out_dir:?}"))?;

    let lengths = boundary_lengths(a.rate_bytes, include_large);
    let mut tests = Vec::new();
    let mut expected_tests = Vec::new();
    let mut tc_id = 1u64;

    match a.kind {
        Kind::Hash => {
            for (i, &len) in lengths.iter().enumerate() {
                let msg = super::fill(i, len);
                let digest = compute_hash(a.name, &msg);
                tests.push(json!({
                    "tcId": tc_id,
                    "msg": hex::encode(&msg),
                    "len": (len as u64) * 8,
                }));
                expected_tests.push(json!({"tcId": tc_id, "md": hex::encode_upper(&digest)}));
                tc_id += 1;
            }
        }
        Kind::Xof => {
            // Vary the message length against a fixed output length, to
            // stress the absorb path's boundary handling.
            let fixed_out_len = a.rate_bytes;
            for (i, &len) in lengths.iter().enumerate() {
                let msg = super::fill(i, len);
                let out = compute_xof(a.name, &msg, fixed_out_len);
                tests.push(json!({
                    "tcId": tc_id,
                    "msg": hex::encode(&msg),
                    "len": (len as u64) * 8,
                    "outLen": (fixed_out_len as u64) * 8,
                }));
                expected_tests.push(json!({
                    "tcId": tc_id,
                    "md": hex::encode_upper(&out),
                    "outLen": (fixed_out_len as u64) * 8,
                }));
                tc_id += 1;
            }
            // Vary the output length against a fixed, short message, to
            // stress the squeeze path's boundary handling.
            let fixed_msg = super::fill(0, 3);
            for &out_len in &lengths {
                let out = compute_xof(a.name, &fixed_msg, out_len);
                tests.push(json!({
                    "tcId": tc_id,
                    "msg": hex::encode(&fixed_msg),
                    "len": (fixed_msg.len() as u64) * 8,
                    "outLen": (out_len as u64) * 8,
                }));
                expected_tests.push(json!({
                    "tcId": tc_id,
                    "md": hex::encode_upper(&out),
                    "outLen": (out_len as u64) * 8,
                }));
                tc_id += 1;
            }
        }
    }

    let test_count = tests.len();
    let vector_set = json!({
        "vsId": 1,
        "algorithm": a.name,
        "revision": "katwalk-adversarial-1.0",
        "testGroups": [{"tgId": 1, "testType": "AFT", "tests": tests}],
    });
    let expected = json!({
        "testGroups": [{"tgId": 1, "tests": expected_tests}],
    });

    let vectors_path = out_dir.join(format!("{}-adversarial-vectors.json", a.name));
    let expected_path = out_dir.join(format!("{}-adversarial-expected.json", a.name));
    std::fs::write(&vectors_path, serde_json::to_string_pretty(&vector_set)?)
        .with_context(|| format!("failed to write {vectors_path:?}"))?;
    std::fs::write(&expected_path, serde_json::to_string_pretty(&expected)?)
        .with_context(|| format!("failed to write {expected_path:?}"))?;

    Ok(serde_json::to_string_pretty(&json!({
        "algorithm": a.name,
        "vectors": vectors_path.display().to_string(),
        "expected": expected_path.display().to_string(),
        "testCount": test_count,
        "messageLengthsBytes": lengths,
    }))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_algorithm() {
        assert!(algo("AES-256").is_err());
    }

    #[test]
    fn boundary_lengths_straddle_one_and_two_rates() {
        let lengths = boundary_lengths(136, false);
        assert!(lengths.contains(&0));
        assert!(lengths.contains(&136));
        assert!(lengths.contains(&135));
        assert!(lengths.contains(&137));
        assert!(lengths.contains(&272));
        assert!(!lengths.contains(&(1 << 20)));
    }

    #[test]
    fn boundary_lengths_include_large_when_requested() {
        let lengths = boundary_lengths(136, true);
        assert!(lengths.contains(&(1 << 20)));
    }

    #[test]
    fn generate_writes_vectors_matching_rustcrypto_oracle() {
        let dir = std::env::temp_dir().join(format!("katwalk-mcp-test-{}", std::process::id()));
        let req = GenerateVectorsRequest {
            algorithm: "SHA3-256".to_string(),
            out_dir: Some(dir.display().to_string()),
            include_large: Some(false),
        };
        let summary = generate(&req).expect("generation should succeed");
        let summary: serde_json::Value = serde_json::from_str(&summary).unwrap();

        let vectors_path = summary["vectors"].as_str().unwrap();
        let expected_path = summary["expected"].as_str().unwrap();
        let vectors: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(vectors_path).unwrap()).unwrap();
        let expected: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(expected_path).unwrap()).unwrap();

        let tests = vectors["testGroups"][0]["tests"].as_array().unwrap();
        let expected_tests = expected["testGroups"][0]["tests"].as_array().unwrap();
        assert_eq!(tests.len(), expected_tests.len());

        for (test, expected_test) in tests.iter().zip(expected_tests.iter()) {
            let msg = hex::decode(test["msg"].as_str().unwrap()).unwrap();
            let digest = Sha3_256::digest(&msg);
            assert_eq!(
                hex::encode_upper(digest),
                expected_test["md"].as_str().unwrap()
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
