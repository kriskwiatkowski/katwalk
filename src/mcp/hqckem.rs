//! Adversarial HQC-KEM test-vector generation, using `hqckem-ref` as the
//! independent oracle for expected keys, ciphertexts, and shared secrets.
//! Mirrors the exact call pattern `hqckem_wrapper` uses (including its
//! SHAKE256 seed derivation for keyGen), since that's the proven-correct
//! way to drive this library.
//!
//! `hqckem_wrapper` doesn't implement encapsulation/decapsulation key
//! checks, so unlike ML-KEM this generator sticks to keyGen, encaps, and
//! decaps (nominal and bit-flipped-ciphertext).

use super::GenerateVectorsRequest;
use anyhow::Context;
use hqc::{decaps, encaps, keygen, HqcParams};
use serde_json::{json, Value};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::path::PathBuf;

const PARAMETER_SETS: [&str; 3] = ["HQC-128", "HQC-192", "HQC-256"];

struct GroupPair {
    request: Value,
    expected: Value,
    test_count: usize,
}

/// Ciphertext/shared-secret pairs `encaps_group` produced, for the
/// decapsulation groups to consume.
type Ciphertexts = Vec<(Vec<u8>, [u8; 32])>;

fn parameter_sets(name: &str) -> anyhow::Result<Vec<&'static str>> {
    if name.eq_ignore_ascii_case("HQC") {
        return Ok(PARAMETER_SETS.to_vec());
    }
    PARAMETER_SETS
        .iter()
        .copied()
        .find(|&p| p == name)
        .map(|p| vec![p])
        .with_context(|| {
            format!(
                "Unsupported HQC parameter set {name}; expected HQC, HQC-128, HQC-192, or HQC-256"
            )
        })
}

/// Derives a 32-byte seed from arbitrary-length input via SHAKE256, exactly
/// as `hqckem_wrapper` does for the 48-byte ACVP keyGen seed.
fn derive_seed(input: &[u8]) -> [u8; 32] {
    let mut h = Shake256::default();
    Update::update(&mut h, input);
    Update::update(&mut h, &[0u8]);
    let mut out = [0u8; 32];
    XofReader::read(&mut h.finalize_xof(), &mut out);
    out
}

fn do_keygen(p: &HqcParams, seed48: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let derived = derive_seed(seed48);
    let mut ek = vec![0u8; p.public_key_size()];
    let mut dk = vec![0u8; p.secret_key_size()];
    keygen(p, &derived, &mut ek, &mut dk);
    (ek, dk)
}

fn do_encaps(p: &HqcParams, ek: &[u8], m: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
    let mut k = [0u8; 32];
    let mut c = vec![0u8; p.ciphertext_size()];
    encaps(p, m, ek, &mut k, &mut c);
    (c, k)
}

fn do_decaps(p: &HqcParams, dk: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 32];
    decaps(p, dk, ct, &mut k);
    k
}

/// Flips a bit at a handful of distinct, deterministic positions in `data`.
fn bit_flips(data: &[u8]) -> Vec<Vec<u8>> {
    [0usize, data.len() / 2, data.len() - 1]
        .iter()
        .map(|&byte_index| {
            let mut corrupted = data.to_vec();
            corrupted[byte_index] ^= 0x01;
            corrupted
        })
        .collect()
}

/// KeyGen group: a handful of edge-case 48-byte ACVP seeds.
fn keygen_group(tg_id: u64, p: &HqcParams) -> GroupPair {
    let mut tests = Vec::new();
    let mut expected = Vec::new();
    for pattern in 0..3 {
        let seed = super::fill(pattern, 48);
        let (ek, dk) = do_keygen(p, &seed);
        let tc_id = pattern as u64 + 1;
        tests.push(json!({"tcId": tc_id, "seed": hex::encode_upper(&seed)}));
        expected.push(
            json!({"tcId": tc_id, "ek": hex::encode_upper(&ek), "dk": hex::encode_upper(&dk)}),
        );
    }
    let test_count = tests.len();
    GroupPair {
        request: json!({"tgId": tg_id, "testType": "AFT", "parameterSet": p.name, "tests": tests}),
        expected: json!({"tgId": tg_id, "tests": expected}),
        test_count,
    }
}

/// Encapsulation group: a fixed keypair, varied message patterns.
fn encaps_group(tg_id: u64, p: &HqcParams, ek: &[u8]) -> (GroupPair, Ciphertexts) {
    let mut tests = Vec::new();
    let mut expected = Vec::new();
    let mut ciphertexts = Vec::new();
    for pattern in 0..3 {
        let m: [u8; 32] = super::fill(pattern, 32).try_into().unwrap();
        let (c, k) = do_encaps(p, ek, &m);
        let tc_id = pattern as u64 + 1;
        tests.push(json!({"tcId": tc_id, "ek": hex::encode_upper(ek), "m": hex::encode_upper(m)}));
        expected
            .push(json!({"tcId": tc_id, "c": hex::encode_upper(&c), "k": hex::encode_upper(k)}));
        ciphertexts.push((c, k));
    }
    let test_count = tests.len();
    (
        GroupPair {
            request: json!({
                "tgId": tg_id, "testType": "AFT", "parameterSet": p.name,
                "function": "encapsulation", "tests": tests,
            }),
            expected: json!({"tgId": tg_id, "tests": expected}),
            test_count,
        },
        ciphertexts,
    )
}

/// Nominal decapsulation group: decapsulate each ciphertext `encaps_group`
/// produced with the matching key.
fn decaps_group(
    tg_id: u64,
    p: &HqcParams,
    dk: &[u8],
    ciphertexts: &[(Vec<u8>, [u8; 32])],
) -> GroupPair {
    let mut tests = Vec::new();
    let mut expected = Vec::new();
    for (i, (ct, _)) in ciphertexts.iter().enumerate() {
        let tc_id = i as u64 + 1;
        tests
            .push(json!({"tcId": tc_id, "dk": hex::encode_upper(dk), "ct": hex::encode_upper(ct)}));
        let k = do_decaps(p, dk, ct);
        expected.push(json!({"tcId": tc_id, "k": hex::encode_upper(k)}));
    }
    let test_count = tests.len();
    GroupPair {
        request: json!({
            "tgId": tg_id, "testType": "AFT", "parameterSet": p.name,
            "function": "decapsulation", "tests": tests,
        }),
        expected: json!({"tgId": tg_id, "tests": expected}),
        test_count,
    }
}

/// Decapsulation-of-corrupted-ciphertext group: flips a handful of bits in
/// each nominal ciphertext and decapsulates the result. Expected is
/// whatever the oracle's FO-transform implicit rejection computes for that
/// exact corrupted ciphertext, not a fixed "error" sentinel.
fn corrupted_decaps_group(
    tg_id: u64,
    p: &HqcParams,
    dk: &[u8],
    ciphertexts: &[(Vec<u8>, [u8; 32])],
) -> GroupPair {
    let mut tests = Vec::new();
    let mut expected = Vec::new();
    let mut tc_id = 1u64;
    for (ct, _) in ciphertexts {
        for corrupted_ct in bit_flips(ct) {
            tests.push(json!({"tcId": tc_id, "dk": hex::encode_upper(dk), "ct": hex::encode_upper(&corrupted_ct)}));
            let k = do_decaps(p, dk, &corrupted_ct);
            expected.push(json!({"tcId": tc_id, "k": hex::encode_upper(k)}));
            tc_id += 1;
        }
    }
    let test_count = tests.len();
    GroupPair {
        request: json!({
            "tgId": tg_id, "testType": "AFT", "parameterSet": p.name,
            "function": "decapsulation", "tests": tests,
        }),
        expected: json!({"tgId": tg_id, "tests": expected}),
        test_count,
    }
}

pub fn generate(req: &GenerateVectorsRequest) -> anyhow::Result<String> {
    let sets = parameter_sets(&req.algorithm)?;
    let out_dir = match &req.out_dir {
        Some(dir) => PathBuf::from(dir),
        None => std::env::temp_dir().join(format!("katwalk-mcp-{}", std::process::id())),
    };
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create output directory {out_dir:?}"))?;

    let mut keygen_groups = Vec::new();
    let mut keygen_expected = Vec::new();
    let mut encap_decap_groups = Vec::new();
    let mut encap_decap_expected = Vec::new();
    let mut test_count = 0usize;

    for (i, set_name) in sets.iter().enumerate() {
        let p = HqcParams::new(set_name).map_err(anyhow::Error::msg)?;
        let tg_base = (i as u64) * 10;

        let keygen_result = keygen_group(tg_base + 1, &p);
        test_count += keygen_result.test_count;
        keygen_groups.push(keygen_result.request);
        keygen_expected.push(keygen_result.expected);

        let seed = super::fill(2, 48);
        let (ek, dk) = do_keygen(&p, &seed);

        let (encaps_result, ciphertexts) = encaps_group(tg_base + 2, &p, &ek);
        test_count += encaps_result.test_count;
        encap_decap_groups.push(encaps_result.request);
        encap_decap_expected.push(encaps_result.expected);

        let decaps_result = decaps_group(tg_base + 3, &p, &dk, &ciphertexts);
        test_count += decaps_result.test_count;
        encap_decap_groups.push(decaps_result.request);
        encap_decap_expected.push(decaps_result.expected);

        let corrupted = corrupted_decaps_group(tg_base + 4, &p, &dk, &ciphertexts);
        test_count += corrupted.test_count;
        encap_decap_groups.push(corrupted.request);
        encap_decap_expected.push(corrupted.expected);
    }

    let vector_sets = json!([
        {
            "vsId": 1, "algorithm": "HQC", "mode": "keyGen",
            "revision": "katwalk-adversarial-1.0", "testGroups": keygen_groups,
        },
        {
            "vsId": 2, "algorithm": "HQC", "mode": "encapDecap",
            "revision": "katwalk-adversarial-1.0", "testGroups": encap_decap_groups,
        },
    ]);
    let expected = json!([
        {"testGroups": keygen_expected},
        {"testGroups": encap_decap_expected},
    ]);

    let suffix = sets.join("-");
    let vectors_path = out_dir.join(format!("HQC-{suffix}-adversarial-vectors.json"));
    let expected_path = out_dir.join(format!("HQC-{suffix}-adversarial-expected.json"));
    std::fs::write(&vectors_path, serde_json::to_string_pretty(&vector_sets)?)
        .with_context(|| format!("failed to write {vectors_path:?}"))?;
    std::fs::write(&expected_path, serde_json::to_string_pretty(&expected)?)
        .with_context(|| format!("failed to write {expected_path:?}"))?;

    Ok(serde_json::to_string_pretty(&json!({
        "algorithm": "HQC",
        "parameterSets": sets,
        "vectors": vectors_path.display().to_string(),
        "expected": expected_path.display().to_string(),
        "testCount": test_count,
        "notes": "Includes bit-flipped-ciphertext decapsulation (implicit-rejection) cases. \
                  No key-check groups: hqckem_wrapper doesn't implement them.",
    }))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_parameter_set() {
        assert!(parameter_sets("HQC-512").is_err());
    }

    #[test]
    fn hqc_name_expands_to_all_three_sets() {
        assert_eq!(parameter_sets("HQC").unwrap(), PARAMETER_SETS.to_vec());
    }

    #[test]
    fn generate_writes_vectors_matching_hqckem_ref_oracle() {
        let dir = std::env::temp_dir().join(format!("katwalk-mcp-hqc-test-{}", std::process::id()));
        let req = GenerateVectorsRequest {
            algorithm: "HQC-128".to_string(),
            out_dir: Some(dir.display().to_string()),
            include_large: None,
        };
        let summary = generate(&req).expect("generation should succeed");
        let summary: Value = serde_json::from_str(&summary).unwrap();

        let vectors: Value = serde_json::from_str(
            &std::fs::read_to_string(summary["vectors"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let expected: Value = serde_json::from_str(
            &std::fs::read_to_string(summary["expected"].as_str().unwrap()).unwrap(),
        )
        .unwrap();

        let p = HqcParams::new("HQC-128").unwrap();
        let keygen_tests = vectors[0]["testGroups"][0]["tests"].as_array().unwrap();
        let keygen_expected = expected[0]["testGroups"][0]["tests"].as_array().unwrap();
        assert_eq!(keygen_tests.len(), 3);
        for (test, expected_test) in keygen_tests.iter().zip(keygen_expected.iter()) {
            let seed = hex::decode(test["seed"].as_str().unwrap()).unwrap();
            let (ek, dk) = do_keygen(&p, &seed);
            assert_eq!(
                hex::encode_upper(&ek),
                expected_test["ek"].as_str().unwrap()
            );
            assert_eq!(
                hex::encode_upper(&dk),
                expected_test["dk"].as_str().unwrap()
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
