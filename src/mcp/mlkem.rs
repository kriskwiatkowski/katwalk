//! Adversarial ML-KEM (FIPS-203) test-vector generation, using `mlkem-ref`
//! as the independent oracle for expected keys, ciphertexts, and shared
//! secrets. Crucially, this includes decapsulating bit-flipped ciphertexts:
//! a correct implementation must return a deterministic implicit-rejection
//! shared secret for those, computed the same way a valid one is -- never
//! an error, a panic, or a result that diverges from the oracle.

use super::GenerateVectorsRequest;
use anyhow::Context;
use mlkem_ref::{check_dk, check_ek, ml_kem_decaps, ml_kem_encaps, ml_kem_keygen, MLKEMParameters};
use serde_json::{json, Value};
use std::path::PathBuf;

const PARAMETER_SETS: [&str; 3] = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];

/// A request/expected test-group pair, plus how many test cases it holds.
struct GroupPair {
    request: Value,
    expected: Value,
    test_count: usize,
}

/// Ciphertext/shared-secret pairs `encaps_group` produced, for the
/// decapsulation groups to consume.
type Ciphertexts = Vec<(Vec<u8>, [u8; 32])>;

fn parameter_sets(name: &str) -> anyhow::Result<Vec<&'static str>> {
    if name.eq_ignore_ascii_case("ML-KEM") {
        return Ok(PARAMETER_SETS.to_vec());
    }
    PARAMETER_SETS
        .iter()
        .copied()
        .find(|&p| p == name)
        .map(|p| vec![p])
        .with_context(|| {
            format!(
                "Unsupported ML-KEM parameter set {name}; expected ML-KEM, ML-KEM-512, \
                 ML-KEM-768, or ML-KEM-1024"
            )
        })
}

fn keygen(p: &MLKEMParameters, seed: &[u8; 64]) -> (Vec<u8>, Vec<u8>) {
    let z: [u8; 32] = seed[0..32].try_into().unwrap();
    let d: [u8; 32] = seed[32..64].try_into().unwrap();
    let mut ek = vec![0u8; p.public_key_length];
    let mut dk = vec![0u8; p.secret_key_length];
    ml_kem_keygen(&d, &z, p, &mut ek, &mut dk);
    (ek, dk)
}

fn encaps(p: &MLKEMParameters, ek: &[u8], m: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
    let mut k = [0u8; 32];
    let mut c = vec![0u8; p.ciphertext_length];
    ml_kem_encaps(ek, m, p, &mut k, &mut c);
    (c, k)
}

fn decaps(p: &MLKEMParameters, dk: &[u8], c: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 32];
    ml_kem_decaps(dk, c, p, &mut k);
    k
}

/// Flips a bit at a handful of distinct, deterministic positions in `data`,
/// to probe decapsulation's FO-transform implicit-rejection path without
/// relying on any single corruption pattern.
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

/// KeyGen group: a handful of edge-case 64-byte seeds (z || d).
fn keygen_group(tg_id: u64, p: &MLKEMParameters) -> GroupPair {
    let mut tests = Vec::new();
    let mut expected = Vec::new();
    for pattern in 0..3 {
        let seed: [u8; 64] = super::fill(pattern, 64).try_into().unwrap();
        let (ek, dk) = keygen(p, &seed);
        let tc_id = pattern as u64 + 1;
        tests.push(json!({
            "tcId": tc_id,
            "z": hex::encode_upper(&seed[0..32]),
            "d": hex::encode_upper(&seed[32..64]),
        }));
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
fn encaps_group(tg_id: u64, p: &MLKEMParameters, ek: &[u8]) -> (GroupPair, Ciphertexts) {
    let mut tests = Vec::new();
    let mut expected = Vec::new();
    let mut ciphertexts = Vec::new();
    for pattern in 0..3 {
        let m: [u8; 32] = super::fill(pattern, 32).try_into().unwrap();
        let (c, k) = encaps(p, ek, &m);
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
/// produced with the matching key; expected `k` must equal what encaps
/// returned (checked implicitly, since both come from the same oracle).
fn decaps_group(
    tg_id: u64,
    p: &MLKEMParameters,
    dk: &[u8],
    ciphertexts: &[(Vec<u8>, [u8; 32])],
) -> GroupPair {
    let mut tests = Vec::new();
    let mut expected = Vec::new();
    for (i, (c, _)) in ciphertexts.iter().enumerate() {
        let tc_id = i as u64 + 1;
        tests.push(json!({"tcId": tc_id, "dk": hex::encode_upper(dk), "c": hex::encode_upper(c)}));
        let k = decaps(p, dk, c);
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
/// each nominal ciphertext and decapsulates the result. The expected value
/// is still whatever the oracle's FO-transform implicit rejection computes
/// for that exact corrupted ciphertext -- not a fixed "error" sentinel --
/// since a correct KEM never fails loudly here, it degrades silently.
fn corrupted_decaps_group(
    tg_id: u64,
    p: &MLKEMParameters,
    dk: &[u8],
    ciphertexts: &[(Vec<u8>, [u8; 32])],
) -> GroupPair {
    let mut tests = Vec::new();
    let mut expected = Vec::new();
    let mut tc_id = 1u64;
    for (c, _) in ciphertexts {
        for corrupted_c in bit_flips(c) {
            tests.push(json!({"tcId": tc_id, "dk": hex::encode_upper(dk), "c": hex::encode_upper(&corrupted_c)}));
            let k = decaps(p, dk, &corrupted_c);
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

/// Encapsulation/decapsulation key-check group: a valid key plus a few
/// structurally-malformed candidates (all-zero, all-0xFF, one bit flipped).
/// Expected `testPassed` again comes straight from the oracle's own
/// `check_ek`/`check_dk`, not from guessing which malformed inputs should
/// fail.
fn key_check_group(
    tg_id: u64,
    function: &str,
    p: &MLKEMParameters,
    valid_key: &[u8],
    is_ek: bool,
) -> GroupPair {
    let field = if is_ek { "ek" } else { "dk" };
    let candidates: Vec<Vec<u8>> = vec![
        valid_key.to_vec(),
        vec![0x00; valid_key.len()],
        vec![0xFF; valid_key.len()],
        bit_flips(valid_key).into_iter().next().unwrap(),
    ];
    let mut tests = Vec::new();
    let mut expected = Vec::new();
    for (i, candidate) in candidates.into_iter().enumerate() {
        let tc_id = i as u64 + 1;
        tests.push(json!({"tcId": tc_id, field: hex::encode_upper(&candidate)}));
        let passed = if is_ek {
            check_ek(&candidate, p)
        } else {
            check_dk(&candidate, p)
        };
        expected.push(json!({"tcId": tc_id, "testPassed": passed}));
    }
    let test_count = tests.len();
    GroupPair {
        request: json!({
            "tgId": tg_id, "testType": "AFT", "parameterSet": p.name,
            "function": function, "tests": tests,
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
        let p = MLKEMParameters::new(set_name).map_err(anyhow::Error::msg)?;
        let tg_base = (i as u64) * 10;

        let keygen_result = keygen_group(tg_base + 1, &p);
        test_count += keygen_result.test_count;
        keygen_groups.push(keygen_result.request);
        keygen_expected.push(keygen_result.expected);

        // Fixed keypair for every encaps/decaps-family group below, so
        // decapsulation can be exercised against ciphertexts encapsulation
        // actually produced.
        let seed: [u8; 64] = super::fill(2, 64).try_into().unwrap();
        let (ek, dk) = keygen(&p, &seed);

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

        let ek_check = key_check_group(tg_base + 5, "encapsulationKeyCheck", &p, &ek, true);
        test_count += ek_check.test_count;
        encap_decap_groups.push(ek_check.request);
        encap_decap_expected.push(ek_check.expected);

        let dk_check = key_check_group(tg_base + 6, "decapsulationKeyCheck", &p, &dk, false);
        test_count += dk_check.test_count;
        encap_decap_groups.push(dk_check.request);
        encap_decap_expected.push(dk_check.expected);
    }

    let vector_sets = json!([
        {
            "vsId": 1, "algorithm": "ML-KEM", "mode": "keyGen",
            "revision": "katwalk-adversarial-1.0", "testGroups": keygen_groups,
        },
        {
            "vsId": 2, "algorithm": "ML-KEM", "mode": "encapDecap",
            "revision": "katwalk-adversarial-1.0", "testGroups": encap_decap_groups,
        },
    ]);
    let expected = json!([
        {"testGroups": keygen_expected},
        {"testGroups": encap_decap_expected},
    ]);

    let suffix = sets.join("-");
    let vectors_path = out_dir.join(format!("ML-KEM-{suffix}-adversarial-vectors.json"));
    let expected_path = out_dir.join(format!("ML-KEM-{suffix}-adversarial-expected.json"));
    std::fs::write(&vectors_path, serde_json::to_string_pretty(&vector_sets)?)
        .with_context(|| format!("failed to write {vectors_path:?}"))?;
    std::fs::write(&expected_path, serde_json::to_string_pretty(&expected)?)
        .with_context(|| format!("failed to write {expected_path:?}"))?;

    Ok(serde_json::to_string_pretty(&json!({
        "algorithm": "ML-KEM",
        "parameterSets": sets,
        "vectors": vectors_path.display().to_string(),
        "expected": expected_path.display().to_string(),
        "testCount": test_count,
        "notes": "Includes bit-flipped-ciphertext decapsulation (implicit-rejection) cases.",
    }))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_parameter_set() {
        assert!(parameter_sets("ML-KEM-2048").is_err());
    }

    #[test]
    fn ml_kem_name_expands_to_all_three_sets() {
        assert_eq!(parameter_sets("ML-KEM").unwrap(), PARAMETER_SETS.to_vec());
    }

    #[test]
    fn generate_writes_vectors_matching_mlkem_ref_oracle() {
        let dir =
            std::env::temp_dir().join(format!("katwalk-mcp-mlkem-test-{}", std::process::id()));
        let req = GenerateVectorsRequest {
            algorithm: "ML-KEM-512".to_string(),
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

        // Re-derive the keyGen expectations independently and cross-check.
        let p = MLKEMParameters::new("ML-KEM-512").unwrap();
        let keygen_tests = vectors[0]["testGroups"][0]["tests"].as_array().unwrap();
        let keygen_expected = expected[0]["testGroups"][0]["tests"].as_array().unwrap();
        assert_eq!(keygen_tests.len(), 3);
        for (test, expected_test) in keygen_tests.iter().zip(keygen_expected.iter()) {
            let z: [u8; 32] = hex::decode(test["z"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let d: [u8; 32] = hex::decode(test["d"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let mut ek = vec![0u8; p.public_key_length];
            let mut dk = vec![0u8; p.secret_key_length];
            ml_kem_keygen(&d, &z, &p, &mut ek, &mut dk);
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
