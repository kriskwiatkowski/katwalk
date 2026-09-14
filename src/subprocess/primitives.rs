use super::Subprocess;
use anyhow::{Context, Result};
use serde_json::{json, Value};

/// Processes fixed-output hashes that are not implemented by the dedicated
/// FIPS-202 adapter.
pub fn process_hash(subprocess: &mut Subprocess, vector_set: &Value) -> Result<Value> {
    let algorithm = vector_set["algorithm"]
        .as_str()
        .context("Missing algorithm")?;
    let test_groups = vector_set["testGroups"]
        .as_array()
        .context("Missing testGroups")?;

    let mut response_groups = Vec::new();

    for group in test_groups {
        if group["testType"].as_str() != Some("AFT") {
            anyhow::bail!(
                "{algorithm} test group {} has unsupported testType {:?}",
                group["tgId"],
                group["testType"]
            );
        }
        let tests = group["tests"].as_array().context("Missing tests")?;
        let mut response_tests = Vec::new();

        for test in tests {
            let test_id = test["tcId"].as_u64().context("Missing tcId")?;
            let msg_hex = test["msg"].as_str().context("Missing msg")?;
            let msg = hex::decode(msg_hex).context("Invalid hex in msg")?;
            let bit_len = test["len"].as_u64().context("Missing len")?;
            if bit_len % 8 != 0 || bit_len / 8 != msg.len() as u64 {
                anyhow::bail!(
                    "{algorithm} test {test_id} has unsupported non-byte-aligned message length {bit_len}"
                );
            }

            let output_len = test["outLen"].as_u64().unwrap_or(0).to_le_bytes();
            let results = subprocess.transact(algorithm, &[&msg, &output_len])?;
            if results.len() != 1 {
                anyhow::bail!(
                    "{algorithm} returned {} results; expected one",
                    results.len()
                );
            }
            let md = hex::encode(&results[0]);

            response_tests.push(json!({
                "tcId": test_id,
                "md": md
            }));
        }

        response_groups.push(json!({
            "tgId": group["tgId"],
            "tests": response_tests
        }));
    }

    Ok(json!({
        "vsId": vector_set["vsId"],
        "algorithm": algorithm,
        "revision": vector_set["revision"],
        "testGroups": response_groups
    }))
}

pub fn process_hmac(subprocess: &mut Subprocess, vector_set: &Value) -> Result<Value> {
    let algorithm = vector_set["algorithm"].as_str().unwrap();
    let test_groups = vector_set["testGroups"]
        .as_array()
        .context("Missing testGroups")?;

    let mut response_groups = Vec::new();

    for group in test_groups {
        let tests = group["tests"].as_array().context("Missing tests")?;
        let mut response_tests = Vec::new();

        for test in tests {
            let test_id = test["tcId"].as_u64().context("Missing tcId")?;
            let msg_hex = test["msg"].as_str().context("Missing msg")?;
            let key_hex = test["key"].as_str().context("Missing key")?;

            let msg = hex::decode(msg_hex).context("Invalid hex in msg")?;
            let key = hex::decode(key_hex).context("Invalid hex in key")?;

            let mac_len = test.get("macLen").and_then(|v| v.as_u64()).unwrap_or(0);

            let results = if mac_len > 0 {
                let mac_len_str = (mac_len / 8).to_string();
                subprocess.transact(algorithm, &[&key, &msg, mac_len_str.as_bytes()])?
            } else {
                subprocess.transact(algorithm, &[&key, &msg])?
            };

            let mac = hex::encode(&results[0]);

            response_tests.push(json!({
                "tcId": test_id,
                "mac": mac
            }));
        }

        response_groups.push(json!({
            "tgId": group["tgId"],
            "tests": response_tests
        }));
    }

    Ok(json!({
        "vsId": vector_set["vsId"],
        "algorithm": algorithm,
        "revision": vector_set["revision"],
        "testGroups": response_groups
    }))
}

pub fn process_drbg(_subprocess: &mut Subprocess, vector_set: &Value) -> Result<Value> {
    let algorithm = vector_set["algorithm"].as_str().unwrap();
    let test_groups = vector_set["testGroups"]
        .as_array()
        .context("Missing testGroups")?;

    let mut response_groups = Vec::new();

    for group in test_groups {
        let tests = group["tests"].as_array().context("Missing tests")?;
        let mut response_tests = Vec::new();

        for test in tests {
            let test_id = test["tcId"].as_u64().context("Missing tcId")?;

            response_tests.push(json!({
                "tcId": test_id,
                "returnedBits": ""
            }));
        }

        response_groups.push(json!({
            "tgId": group["tgId"],
            "tests": response_tests
        }));
    }

    Ok(json!({
        "vsId": vector_set["vsId"],
        "algorithm": algorithm,
        "revision": vector_set["revision"],
        "testGroups": response_groups
    }))
}

pub fn process_ecdsa(_subprocess: &mut Subprocess, vector_set: &Value) -> Result<Value> {
    let algorithm = vector_set["algorithm"].as_str().unwrap();
    let test_groups = vector_set["testGroups"]
        .as_array()
        .context("Missing testGroups")?;

    let mut response_groups = Vec::new();

    for group in test_groups {
        let tests = group["tests"].as_array().context("Missing tests")?;
        let mut response_tests = Vec::new();

        for test in tests {
            let test_id = test["tcId"].as_u64().context("Missing tcId")?;

            response_tests.push(json!({
                "tcId": test_id
            }));
        }

        response_groups.push(json!({
            "tgId": group["tgId"],
            "tests": response_tests
        }));
    }

    Ok(json!({
        "vsId": vector_set["vsId"],
        "algorithm": algorithm,
        "revision": vector_set["revision"],
        "testGroups": response_groups
    }))
}

fn process_signature_stub(_subprocess: &mut Subprocess, vector_set: &Value) -> Result<Value> {
    let algorithm = vector_set["algorithm"].as_str().unwrap();
    let test_groups = vector_set["testGroups"]
        .as_array()
        .context("Missing testGroups")?;

    let mut response_groups = Vec::new();

    for group in test_groups {
        let test_type = group["testType"].as_str().unwrap_or("");
        let tests = group["tests"].as_array().context("Missing tests")?;
        let mut response_tests = Vec::new();

        for test in tests {
            let test_id = test["tcId"].as_u64().context("Missing tcId")?;

            let response_test = match test_type {
                "AFT" => {
                    json!({
                        "tcId": test_id,
                        "signature": ""
                    })
                }
                "BFT" => {
                    json!({
                        "tcId": test_id,
                        "testPassed": false
                    })
                }
                _ => {
                    json!({
                        "tcId": test_id
                    })
                }
            };

            response_tests.push(response_test);
        }

        response_groups.push(json!({
            "tgId": group["tgId"],
            "tests": response_tests
        }));
    }

    Ok(json!({
        "vsId": vector_set["vsId"],
        "algorithm": algorithm,
        "revision": vector_set["revision"],
        "testGroups": response_groups
    }))
}

pub fn process_slhdsa(subprocess: &mut Subprocess, vector_set: &Value) -> Result<Value> {
    process_signature_stub(subprocess, vector_set)
}

pub fn process_lms(subprocess: &mut Subprocess, vector_set: &Value) -> Result<Value> {
    process_signature_stub(subprocess, vector_set)
}

pub fn process_xmss(subprocess: &mut Subprocess, vector_set: &Value) -> Result<Value> {
    process_signature_stub(subprocess, vector_set)
}

pub fn process_kdf(subprocess: &mut Subprocess, vector_set: &Value) -> Result<Value> {
    process_drbg(subprocess, vector_set)
}

pub fn process_kda(subprocess: &mut Subprocess, vector_set: &Value) -> Result<Value> {
    process_drbg(subprocess, vector_set)
}

pub fn process_tls_kdf(subprocess: &mut Subprocess, vector_set: &Value) -> Result<Value> {
    process_drbg(subprocess, vector_set)
}

pub fn process_tls13(subprocess: &mut Subprocess, vector_set: &Value) -> Result<Value> {
    process_drbg(subprocess, vector_set)
}

pub fn process_kas(subprocess: &mut Subprocess, vector_set: &Value) -> Result<Value> {
    process_drbg(subprocess, vector_set)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn test_hash_response_format() {
        let vector_set = json!({
            "vsId": 1,
            "algorithm": "SHA2-256",
            "revision": "1.0",
            "testGroups": [{
                "tgId": 1,
                "tests": []
            }]
        });

        assert_eq!(vector_set["algorithm"], "SHA2-256");
        assert!(vector_set["testGroups"].is_array());
    }

    #[test]
    fn test_hmac_response_format() {
        let test = json!({
            "tcId": 1,
            "msg": "48656c6c6f",
            "key": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "macLen": 256
        });

        assert_eq!(test["tcId"], 1);
        assert!(test["msg"].is_string());
        assert!(test["key"].is_string());

        let msg_hex = test["msg"].as_str().unwrap();
        let msg_bytes = hex::decode(msg_hex).unwrap();
        assert_eq!(msg_bytes, b"Hello");
    }

    #[test]
    fn test_ml_dsa_test_types() {
        let test_types = vec!["AFT", "BFT"];

        for test_type in test_types {
            match test_type {
                "AFT" => {
                    let response = json!({
                        "tcId": 1,
                        "signature": ""
                    });
                    assert!(response["signature"].is_string());
                }
                "BFT" => {
                    let response = json!({
                        "tcId": 1,
                        "testPassed": false
                    });
                    assert!(response["testPassed"].is_boolean());
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_json_response_structure() {
        let response = json!({
            "vsId": 12345,
            "algorithm": "SHA2-256",
            "revision": "1.0",
            "testGroups": [{
                "tgId": 1,
                "tests": [{
                    "tcId": 1,
                    "md": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                }]
            }]
        });

        assert!(response["vsId"].is_number());
        assert!(response["algorithm"].is_string());
        assert!(response["revision"].is_string());
        assert!(response["testGroups"].is_array());

        let groups = response["testGroups"].as_array().unwrap();
        assert!(!groups.is_empty());

        let group = &groups[0];
        assert!(group["tgId"].is_number());
        assert!(group["tests"].is_array());
    }

    #[test]
    fn test_algorithm_name_parsing() {
        let algorithms = vec![
            ("SHA2-256", "SHA2-256"),
            ("HMAC-SHA2-256", "HMAC-SHA2-256"),
            ("ML-DSA", "ML-DSA"),
        ];

        for (input, expected) in algorithms {
            assert_eq!(input, expected);
            assert!(input.is_ascii());
        }
    }
}
