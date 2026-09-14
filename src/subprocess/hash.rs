//! ACVP adapters for the standalone FIPS-202 SHA-3 and SHAKE wrapper.

use super::Subprocess;
use anyhow::{Context, Result};
use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

#[derive(Debug, Deserialize)]
struct VectorSet {
    #[serde(rename = "vsId")]
    vs_id: u64,
    algorithm: String,
    revision: String,
    // FIPS-202 vector sets do not normally carry a mode, but retain it when
    // supplied so the request shape is explicitly modeled at this boundary.
    mode: Option<String>,
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
struct Capability {
    algorithm: String,
    #[serde(
        default,
        rename = "inBit",
        deserialize_with = "deserialize_capability_boolean"
    )]
    in_bit: bool,
    #[serde(
        default,
        rename = "outBit",
        deserialize_with = "deserialize_capability_boolean"
    )]
    out_bit: bool,
}

fn deserialize_capability_boolean<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct BooleanVisitor;

    impl<'de> Visitor<'de> for BooleanVisitor {
        type Value = bool;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(r#"a boolean or the string "true" or "false""#)
        }

        fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
            Ok(value)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            match value {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(E::custom(format!(
                    r#"expected "true" or "false", got "{value}""#
                ))),
            }
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            self.visit_str(&value)
        }
    }

    deserializer.deserialize_any(BooleanVisitor)
}

#[derive(Debug, Deserialize)]
struct TestGroup {
    #[serde(rename = "tgId")]
    tg_id: u64,
    #[serde(rename = "testType")]
    test_type: TestType,
    tests: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum TestType {
    Aft,
    Mct,
    Ldt,
}

#[derive(Debug, Deserialize)]
struct TestCase {
    #[serde(rename = "tcId")]
    tc_id: u64,
    msg: Option<String>,
    len: Option<u64>,
    #[serde(rename = "outLen")]
    out_len: Option<u64>,
    #[serde(rename = "largeMsg")]
    large_msg: Option<LargeMessage>,
}

#[derive(Debug, Deserialize)]
struct LargeMessage {
    content: String,
    #[serde(rename = "contentLength")]
    content_length: u64,
    #[serde(rename = "fullLength")]
    full_length: u64,
    #[serde(rename = "expansionTechnique")]
    expansion_technique: String,
}

#[derive(Serialize)]
struct Response {
    #[serde(rename = "vsId")]
    vs_id: u64,
    algorithm: String,
    revision: String,
    #[serde(rename = "testGroups")]
    test_groups: Vec<ResponseGroup>,
}

#[derive(Serialize)]
struct ResponseGroup {
    #[serde(rename = "tgId")]
    tg_id: u64,
    tests: Vec<ResponseTest>,
}

#[derive(Serialize)]
struct ResponseTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    md: Option<String>,
    #[serde(rename = "outLen", skip_serializing_if = "Option::is_none")]
    out_len: Option<u64>,
    #[serde(rename = "resultsArray", skip_serializing_if = "Option::is_none")]
    results_array: Option<Vec<MctResult>>,
}

#[derive(Serialize)]
struct MctResult {
    md: String,
}

#[derive(Clone, Copy)]
enum OutputKind {
    FixedHash,
    Xof,
}

fn one_result<'a>(results: &'a [Vec<u8>], algorithm: &str) -> Result<&'a [u8]> {
    if results.len() != 1 {
        anyhow::bail!(
            "{algorithm} returned {} results; expected one",
            results.len()
        );
    }
    Ok(&results[0])
}

fn bit_capabilities(subprocess: &mut Subprocess, algorithm: &str) -> Result<(bool, bool)> {
    let capabilities: Vec<Capability> = serde_json::from_value(subprocess.get_config()?)
        .context("Invalid wrapper configuration")?;
    let capability = capabilities
        .iter()
        .find(|capability| capability.algorithm == algorithm)
        .with_context(|| format!("Wrapper configuration does not advertise {algorithm}"))?;
    Ok((capability.in_bit, capability.out_bit))
}

fn supports_aft(
    output_kind: OutputKind,
    message_bits: u64,
    output_bits: u64,
    supports_bit_input: bool,
    supports_bit_output: bool,
) -> bool {
    (supports_bit_input || message_bits.is_multiple_of(8))
        && (!matches!(output_kind, OutputKind::Xof)
            || supports_bit_output
            || output_bits.is_multiple_of(8))
}

fn process(
    subprocess: &mut Subprocess,
    vector_set: &Value,
    output_kind: OutputKind,
) -> Result<Value> {
    let vector_set: VectorSet =
        serde_json::from_value(vector_set.clone()).context("Invalid FIPS-202 vector set")?;
    let _ = &vector_set.mode;
    let (supports_bit_input, supports_bit_output) =
        bit_capabilities(subprocess, &vector_set.algorithm)?;

    let mut response_groups = Vec::with_capacity(vector_set.test_groups.len());
    for group in &vector_set.test_groups {
        let mut response_tests = Vec::with_capacity(group.tests.len());

        for test in &group.tests {
            match group.test_type {
                TestType::Aft => {
                    let msg = hex::decode(test.msg.as_deref().context("Missing msg")?)
                        .context("Invalid hex in msg")?;
                    let len = test.len.context("Missing len")?;
                    if len > msg.len() as u64 * 8 {
                        anyhow::bail!(
                            "{} test {} has message length {} but msg contains only {} bits",
                            vector_set.algorithm,
                            test.tc_id,
                            len,
                            msg.len() * 8
                        );
                    }
                    let output_len_bits = match output_kind {
                        OutputKind::FixedHash => test.out_len.unwrap_or(0),
                        OutputKind::Xof => test.out_len.context("Missing outLen")?,
                    };
                    if !supports_aft(
                        output_kind,
                        len,
                        output_len_bits,
                        supports_bit_input,
                        supports_bit_output,
                    ) {
                        continue;
                    }
                    // Byte-oriented wrappers use the established ACVP
                    // protocol (message, output-bit-length), as implemented
                    // by the Go and EPCC wrappers. A bit-oriented wrapper
                    // needs the adapter's explicit message-length extension
                    // to distinguish a partial final byte.
                    let results = if supports_bit_input {
                        subprocess.transact(
                            &vector_set.algorithm,
                            &[&msg, &len.to_le_bytes(), &output_len_bits.to_le_bytes()],
                        )?
                    } else {
                        subprocess.transact(
                            &vector_set.algorithm,
                            &[&msg, &output_len_bits.to_le_bytes()],
                        )?
                    };
                    let result = one_result(&results, &vector_set.algorithm)?;
                    response_tests.push(ResponseTest {
                        tc_id: test.tc_id,
                        md: Some(hex::encode_upper(result)),
                        out_len: matches!(output_kind, OutputKind::Xof).then_some(output_len_bits),
                        results_array: None,
                    });
                }
                TestType::Mct => {
                    if matches!(output_kind, OutputKind::Xof) {
                        anyhow::bail!(
                            "{} test group {} has unsupported testType MCT",
                            vector_set.algorithm,
                            group.tg_id
                        );
                    }
                    let mut digest = hex::decode(test.msg.as_deref().context("Missing msg")?)
                        .context("Invalid hex in msg")?;
                    let mut results_array = Vec::with_capacity(100);
                    for _ in 0..100 {
                        let results = subprocess.transact(
                            &format!("{}/MCT", vector_set.algorithm),
                            &[&digest, &0u64.to_le_bytes()],
                        )?;
                        digest = one_result(&results, &format!("{}/MCT", vector_set.algorithm))?
                            .to_vec();
                        results_array.push(MctResult {
                            md: hex::encode_upper(&digest),
                        });
                    }
                    response_tests.push(ResponseTest {
                        tc_id: test.tc_id,
                        md: None,
                        out_len: None,
                        results_array: Some(results_array),
                    });
                }
                TestType::Ldt => {
                    if matches!(output_kind, OutputKind::Xof) {
                        anyhow::bail!(
                            "{} test group {} has unsupported testType LDT",
                            vector_set.algorithm,
                            group.tg_id
                        );
                    }
                    let large_msg = test.large_msg.as_ref().context("Missing largeMsg")?;
                    let content = hex::decode(&large_msg.content)
                        .context("Invalid hex in largeMsg.content")?;
                    if large_msg.content_length != content.len() as u64 * 8 {
                        anyhow::bail!(
                            "largeMsg content is {} bits but contentLength is {}",
                            content.len() * 8,
                            large_msg.content_length
                        );
                    }
                    let results = subprocess.transact(
                        &format!("{}/LDT", vector_set.algorithm),
                        &[
                            &content,
                            &large_msg.full_length.to_le_bytes(),
                            large_msg.expansion_technique.as_bytes(),
                        ],
                    )?;
                    let result = one_result(&results, &format!("{}/LDT", vector_set.algorithm))?;
                    response_tests.push(ResponseTest {
                        tc_id: test.tc_id,
                        md: Some(hex::encode_upper(result)),
                        out_len: None,
                        results_array: None,
                    });
                }
            }
        }
        response_groups.push(ResponseGroup {
            tg_id: group.tg_id,
            tests: response_tests,
        });
    }

    serde_json::to_value(Response {
        vs_id: vector_set.vs_id,
        algorithm: vector_set.algorithm,
        revision: vector_set.revision,
        test_groups: response_groups,
    })
    .context("Failed to serialize FIPS-202 response")
}

/// Processes SHA3-224/256/384/512 vector sets through `fips202_wrapper`.
pub fn process_hash(subprocess: &mut Subprocess, vector_set: &Value) -> Result<Value> {
    process(subprocess, vector_set, OutputKind::FixedHash)
}

/// Processes SHAKE-128 and SHAKE-256 AFT vector sets through `fips202_wrapper`.
pub fn process_xof(subprocess: &mut Subprocess, vector_set: &Value) -> Result<Value> {
    process(subprocess, vector_set, OutputKind::Xof)
}

#[cfg(test)]
mod tests {
    use super::{supports_aft, Capability, OutputKind, VectorSet};
    use serde_json::json;

    #[test]
    fn models_deserialize_sha3_and_shake_aft_shapes() {
        let sha3: VectorSet = serde_json::from_value(json!({
            "vsId": 1,
            "algorithm": "SHA3-256",
            "revision": "2.0",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "tests": [{"tcId": 1, "msg": "", "len": 0}]
            }]
        }))
        .unwrap();
        assert!(sha3.mode.is_none());
        assert_eq!(sha3.test_groups[0].tests[0].out_len, None);

        let shake: VectorSet = serde_json::from_value(json!({
            "vsId": 2,
            "algorithm": "SHAKE-128",
            "revision": "FIPS202",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "tests": [{"tcId": 1, "msg": "616263", "len": 24, "outLen": 256}]
            }]
        }))
        .unwrap();
        assert_eq!(shake.test_groups[0].tests[0].out_len, Some(256));
    }

    #[test]
    fn xof_output_length_is_expressed_in_bits() {
        let test = json!({
            "tcId": 1,
            "msg": "616263",
            "outLen": 512
        });

        let out_len = test["outLen"].as_u64().unwrap();
        assert_eq!(out_len, 512);
        assert_eq!((out_len / 8) as usize, 64);
    }

    #[test]
    fn byte_only_capabilities_skip_partial_bit_cases() {
        assert!(!supports_aft(OutputKind::FixedHash, 82, 0, false, false));
        assert!(!supports_aft(OutputKind::Xof, 24, 517, false, false));
        assert!(supports_aft(OutputKind::Xof, 24, 512, false, false));
        assert!(supports_aft(OutputKind::Xof, 82, 517, true, true));
    }

    #[test]
    fn capabilities_accept_boolean_and_string_boolean_values() {
        let capabilities: Vec<Capability> = serde_json::from_value(json!([
            {"algorithm": "SHA3-256", "inBit": false},
            {"algorithm": "SHAKE-128", "inBit": "true", "outBit": "false"}
        ]))
        .unwrap();
        assert!(!capabilities[0].in_bit);
        assert!(!capabilities[0].out_bit);
        assert!(capabilities[1].in_bit);
        assert!(!capabilities[1].out_bit);
    }

    #[test]
    fn capabilities_reject_invalid_boolean_values() {
        let invalid_string = serde_json::from_value::<Vec<Capability>>(json!([
            {"algorithm": "SHA3-256", "inBit": "False"}
        ]))
        .unwrap_err();
        assert!(invalid_string
            .to_string()
            .contains(r#"expected "true" or "false", got "False""#));

        let invalid_type = serde_json::from_value::<Vec<Capability>>(json!([
            {"algorithm": "SHA3-256", "inBit": 0}
        ]))
        .unwrap_err();
        assert!(invalid_type
            .to_string()
            .contains(r#"a boolean or the string "true" or "false""#));
    }
}
