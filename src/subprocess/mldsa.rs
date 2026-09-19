use super::Subprocess;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const ZERO_RND: [u8; 32] = [0; 32];

#[derive(Debug, Deserialize)]
struct VectorSet {
    #[serde(rename = "vsId")]
    vs_id: u64,
    algorithm: String,
    revision: String,
    mode: Mode,
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Mode {
    KeyGen,
    SigGen,
    SigVer,
}

#[derive(Debug, Deserialize)]
struct TestGroup {
    #[serde(rename = "tgId")]
    tg_id: u64,
    #[serde(rename = "testType")]
    test_type: Option<String>,
    #[serde(rename = "parameterSet")]
    parameter_set: ParameterSet,
    #[serde(default, rename = "signatureInterface")]
    signature_interface: SignatureInterface,
    #[serde(default, rename = "externalMu")]
    external_mu: bool,
    deterministic: Option<bool>,
    #[serde(rename = "keyFormat")]
    key_format: Option<KeyFormat>,
    pk: Option<String>,
    #[serde(rename = "preHash")]
    pre_hash: Option<String>,
    tests: Vec<TestCase>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
enum ParameterSet {
    #[serde(rename = "ML-DSA-44")]
    MlDsa44,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
    #[serde(rename = "ML-DSA-87")]
    MlDsa87,
}

impl ParameterSet {
    fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
enum SignatureInterface {
    #[default]
    #[serde(rename = "internal")]
    Internal,
    #[serde(rename = "external")]
    External,
}

impl SignatureInterface {
    fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::External => "external",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
enum KeyFormat {
    #[serde(rename = "seed")]
    Seed,
    #[serde(rename = "expanded")]
    Expanded,
}

impl KeyFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::Expanded => "expanded",
        }
    }
}

#[derive(Debug, Deserialize)]
struct TestCase {
    #[serde(rename = "tcId")]
    tc_id: u64,
    seed: Option<String>,
    sk: Option<String>,
    message: Option<String>,
    rnd: Option<String>,
    signature: Option<String>,
    pk: Option<String>,
    mu: Option<String>,
    context: Option<String>,
    #[serde(rename = "hashAlg")]
    hash_alg: Option<String>,
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
    pk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(rename = "testPassed", skip_serializing_if = "Option::is_none")]
    test_passed: Option<bool>,
}

fn decode_hex(value: Option<&str>, field: &str) -> Result<Vec<u8>> {
    let value = value.with_context(|| format!("Missing {field}"))?;
    hex::decode(value).with_context(|| format!("Invalid hex in {field}"))
}

fn one_result<'a>(results: &'a [Vec<u8>], command: &str) -> Result<&'a [u8]> {
    if results.len() != 1 {
        anyhow::bail!(
            "{command} returned {} results; expected exactly one",
            results.len()
        );
    }
    Ok(&results[0])
}

fn two_results<'a>(results: &'a [Vec<u8>], command: &str) -> Result<(&'a [u8], &'a [u8])> {
    if results.len() != 2 {
        anyhow::bail!(
            "{command} returned {} results; expected exactly two",
            results.len()
        );
    }
    Ok((&results[0], &results[1]))
}

fn signing_key(group: &TestGroup, test: &TestCase) -> Result<(KeyFormat, Vec<u8>)> {
    match group.key_format.unwrap_or(KeyFormat::Expanded) {
        KeyFormat::Seed => Ok((KeyFormat::Seed, decode_hex(test.seed.as_deref(), "seed")?)),
        KeyFormat::Expanded => Ok((KeyFormat::Expanded, decode_hex(test.sk.as_deref(), "sk")?)),
    }
}

fn randomness(test: &TestCase, deterministic: bool) -> Result<Vec<u8>> {
    if deterministic {
        if test.rnd.is_some() {
            anyhow::bail!("rnd must be absent when deterministic is true in ML-DSA sigGen");
        }
        Ok(ZERO_RND.to_vec())
    } else {
        let rnd = decode_hex(test.rnd.as_deref(), "rnd")?;
        if rnd.len() != ZERO_RND.len() {
            anyhow::bail!("rnd must be 32 bytes, got {}", rnd.len());
        }
        Ok(rnd)
    }
}

fn pre_hash(group: &TestGroup) -> Result<&str> {
    group
        .pre_hash
        .as_deref()
        .context("Missing preHash in external ML-DSA group")
}

fn mu(test: &TestCase) -> Result<Vec<u8>> {
    let mu = decode_hex(test.mu.as_deref(), "mu")?;
    if mu.len() != 64 {
        anyhow::bail!("mu must be 64 bytes, got {}", mu.len());
    }
    Ok(mu)
}

fn external_context(test: &TestCase) -> Result<Vec<u8>> {
    let context = decode_hex(test.context.as_deref(), "context")?;
    if context.len() > 255 {
        anyhow::bail!("context must be at most 255 bytes, got {}", context.len());
    }
    Ok(context)
}

fn hash_alg(test: &TestCase, pre_hash: &str) -> Result<Vec<u8>> {
    if pre_hash == "pure" {
        if test.hash_alg.is_some() {
            anyhow::bail!("hashAlg must be absent for pure ML-DSA");
        }
        return Ok(Vec::new());
    }
    if pre_hash != "preHash" {
        anyhow::bail!("unsupported ML-DSA preHash mode: {pre_hash}");
    }
    Ok(test
        .hash_alg
        .as_deref()
        .context("Missing hashAlg in preHash ML-DSA test")?
        .as_bytes()
        .to_vec())
}

fn require_siggen_aft(group: &TestGroup) -> Result<()> {
    match group.test_type.as_deref() {
        Some("AFT") => Ok(()),
        Some(test_type) => anyhow::bail!("unsupported ML-DSA sigGen testType: {test_type}"),
        None => anyhow::bail!("Missing testType in ML-DSA sigGen group"),
    }
}

fn registration_for_mode<'a>(config: &'a Value, mode: &str) -> Option<&'a Value> {
    config
        .as_array()
        .into_iter()
        .flatten()
        .find(|registration| registration["mode"] == mode)
}

fn supports_siggen_group(config: &Value, group: &TestGroup) -> bool {
    let Some(registration) = registration_for_mode(config, "sigGen") else {
        return false;
    };

    let external_mu_supported = registration["externalMu"]
        .as_array()
        .is_some_and(|values| values.iter().any(|value| value == group.external_mu));
    let interface_supported =
        registration["signatureInterfaces"]
            .as_array()
            .is_some_and(|values| {
                values
                    .iter()
                    .any(|value| value == group.signature_interface.as_str())
            });
    external_mu_supported && interface_supported
}

pub fn process_mldsa(subprocess: &mut Subprocess, vector_set: &Value) -> Result<Value> {
    let vector_set: VectorSet =
        serde_json::from_value(vector_set.clone()).context("Invalid ML-DSA vector set")?;
    let config = match vector_set.mode {
        Mode::SigGen | Mode::SigVer => Some(subprocess.get_config()?),
        _ => None,
    };
    let mut response_groups = Vec::with_capacity(vector_set.test_groups.len());

    if matches!(vector_set.mode, Mode::SigVer)
        && registration_for_mode(config.as_ref().unwrap(), "sigVer").is_none()
    {
        response_groups.resize_with(vector_set.test_groups.len(), || ResponseGroup {
            tg_id: 0,
            tests: Vec::new(),
        });
        for (response_group, group) in response_groups.iter_mut().zip(&vector_set.test_groups) {
            response_group.tg_id = group.tg_id;
        }
        return serde_json::to_value(Response {
            vs_id: vector_set.vs_id,
            algorithm: vector_set.algorithm,
            revision: vector_set.revision,
            test_groups: response_groups,
        })
        .context("Failed to serialize ML-DSA response");
    }

    for group in &vector_set.test_groups {
        let parameter_set = group.parameter_set.as_str();
        let mut response_tests = Vec::with_capacity(group.tests.len());

        match vector_set.mode {
            Mode::KeyGen => {
                for test in &group.tests {
                    let seed = decode_hex(test.seed.as_deref(), "seed")?;
                    let results =
                        subprocess.transact("ML-DSA/keyGen", &[parameter_set.as_bytes(), &seed])?;
                    if subprocess.check_unsupported(
                        &results,
                        &format!("ML-DSA/keyGen for parameterSet={parameter_set}"),
                    ) {
                        continue;
                    }
                    let (pk, sk) = two_results(&results, "ML-DSA/keyGen")?;
                    response_tests.push(ResponseTest {
                        tc_id: test.tc_id,
                        pk: Some(hex::encode(pk)),
                        sk: Some(hex::encode(sk)),
                        signature: None,
                        test_passed: None,
                    });
                }
            }
            Mode::SigGen => {
                require_siggen_aft(group)?;
                if !supports_siggen_group(config.as_ref().unwrap(), group) {
                    response_groups.push(ResponseGroup {
                        tg_id: group.tg_id,
                        tests: Vec::new(),
                    });
                    continue;
                }
                let deterministic = group
                    .deterministic
                    .context("Missing deterministic in ML-DSA sigGen group")?;

                for test in &group.tests {
                    let (key_format, key) = signing_key(group, test)?;
                    let rnd = randomness(test, deterministic)?;
                    let results = match (group.external_mu, group.signature_interface) {
                        (true, _) => {
                            let mu = mu(test)?;
                            subprocess.transact(
                                "ML-DSA/signMu",
                                &[
                                    parameter_set.as_bytes(),
                                    key_format.as_str().as_bytes(),
                                    &key,
                                    &mu,
                                    &rnd,
                                ],
                            )?
                        }
                        (false, SignatureInterface::Internal) => {
                            let message = decode_hex(test.message.as_deref(), "message")?;
                            subprocess.transact(
                                "ML-DSA/signInternal",
                                &[
                                    parameter_set.as_bytes(),
                                    key_format.as_str().as_bytes(),
                                    &key,
                                    &message,
                                    &rnd,
                                ],
                            )?
                        }
                        (false, SignatureInterface::External) => {
                            let message = decode_hex(test.message.as_deref(), "message")?;
                            let context = external_context(test)?;
                            let pre_hash = pre_hash(group)?;
                            let hash_alg = hash_alg(test, pre_hash)?;
                            subprocess.transact(
                                "ML-DSA/signExternal",
                                &[
                                    parameter_set.as_bytes(),
                                    key_format.as_str().as_bytes(),
                                    &key,
                                    &message,
                                    &context,
                                    pre_hash.as_bytes(),
                                    &hash_alg,
                                    &rnd,
                                ],
                            )?
                        }
                    };
                    if subprocess.check_unsupported(
                        &results,
                        &format!("ML-DSA/sigGen for parameterSet={parameter_set}"),
                    ) {
                        continue;
                    }
                    let signature = one_result(&results, "ML-DSA/sigGen")?;
                    response_tests.push(ResponseTest {
                        tc_id: test.tc_id,
                        pk: None,
                        sk: None,
                        signature: Some(hex::encode(signature)),
                        test_passed: None,
                    });
                }
            }
            Mode::SigVer => {
                for test in &group.tests {
                    let pk = decode_hex(test.pk.as_deref().or(group.pk.as_deref()), "pk")?;
                    let signature = decode_hex(test.signature.as_deref(), "signature")?;
                    let results = match (group.external_mu, group.signature_interface) {
                        (true, _) => {
                            let mu = mu(test)?;
                            subprocess.transact(
                                "ML-DSA/verifyMu",
                                &[parameter_set.as_bytes(), &pk, &mu, &signature],
                            )?
                        }
                        (false, SignatureInterface::Internal) => {
                            let message = decode_hex(test.message.as_deref(), "message")?;
                            subprocess.transact(
                                "ML-DSA/verifyInternal",
                                &[parameter_set.as_bytes(), &pk, &message, &signature],
                            )?
                        }
                        (false, SignatureInterface::External) => {
                            let message = decode_hex(test.message.as_deref(), "message")?;
                            let context = external_context(test)?;
                            let pre_hash = pre_hash(group)?;
                            let hash_alg = hash_alg(test, pre_hash)?;
                            subprocess.transact(
                                "ML-DSA/verifyExternal",
                                &[
                                    parameter_set.as_bytes(),
                                    &pk,
                                    &message,
                                    &context,
                                    pre_hash.as_bytes(),
                                    &hash_alg,
                                    &signature,
                                ],
                            )?
                        }
                    };
                    if subprocess.check_unsupported(
                        &results,
                        &format!("ML-DSA/sigVer for parameterSet={parameter_set}"),
                    ) {
                        continue;
                    }
                    let result = one_result(&results, "ML-DSA/sigVer")?;
                    let test_passed = match result {
                        [0] => false,
                        [1] => true,
                        _ => anyhow::bail!("ML-DSA/sigVer returned an invalid result: {result:?}"),
                    };
                    response_tests.push(ResponseTest {
                        tc_id: test.tc_id,
                        pk: None,
                        sk: None,
                        signature: None,
                        test_passed: Some(test_passed),
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
    .context("Failed to serialize ML-DSA response")
}

#[cfg(test)]
mod tests {
    use super::{process_mldsa, registration_for_mode, supports_siggen_group, TestGroup};
    use crate::subprocess::Subprocess;
    use serde_json::json;
    use std::path::Path;

    fn siggen_group(signature_interface: &str, external_mu: bool) -> TestGroup {
        serde_json::from_value(json!({
            "tgId": 1,
            "testType": "AFT",
            "parameterSet": "ML-DSA-44",
            "signatureInterface": signature_interface,
            "externalMu": external_mu,
            "deterministic": true,
            "tests": []
        }))
        .unwrap()
    }

    #[test]
    fn registration_for_mode_finds_matching_entry() {
        let config = json!([
            {"mode": "sigGen", "externalMu": [true, false]},
            {"mode": "sigVer", "externalMu": [true]}
        ]);
        assert_eq!(
            registration_for_mode(&config, "sigVer").unwrap()["externalMu"],
            json!([true])
        );
        assert!(registration_for_mode(&config, "keyGen").is_none());
    }

    #[test]
    fn supports_siggen_group_true_when_registration_advertises_interface_and_mu() {
        let config = json!([{
            "mode": "sigGen",
            "externalMu": [true, false],
            "signatureInterfaces": ["internal", "external"]
        }]);
        assert!(supports_siggen_group(
            &config,
            &siggen_group("internal", false)
        ));
        assert!(supports_siggen_group(
            &config,
            &siggen_group("external", true)
        ));
    }

    #[test]
    fn supports_siggen_group_false_when_sig_gen_registration_missing() {
        let config = json!([{
            "mode": "sigVer",
            "externalMu": [true],
            "signatureInterfaces": ["internal"]
        }]);
        assert!(!supports_siggen_group(
            &config,
            &siggen_group("internal", false)
        ));
    }

    #[test]
    fn supports_siggen_group_false_when_external_mu_not_advertised() {
        let config = json!([{
            "mode": "sigGen",
            "externalMu": [false],
            "signatureInterfaces": ["internal", "external"]
        }]);
        assert!(!supports_siggen_group(
            &config,
            &siggen_group("internal", true)
        ));
    }

    #[test]
    fn supports_siggen_group_false_when_interface_not_advertised() {
        let config = json!([{
            "mode": "sigGen",
            "externalMu": [true, false],
            "signatureInterfaces": ["internal"]
        }]);
        assert!(!supports_siggen_group(
            &config,
            &siggen_group("external", false)
        ));
    }

    fn start_wrapper() -> Subprocess {
        let mut path = std::env::current_exe().expect("cannot resolve test executable");
        path.pop();
        if path.ends_with("deps") {
            path.pop();
        }
        path.push("mldsa_wrapper");
        Subprocess::new(Path::new(&path), None)
            .unwrap_or_else(|e| panic!("failed to start mldsa_wrapper at {path:?}: {e}"))
    }

    fn keygen_vector(parameter_set: &str) -> serde_json::Value {
        json!({
            "vsId": 1,
            "algorithm": "ML-DSA",
            "mode": "keyGen",
            "revision": "FIPS204",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": parameter_set,
                "tests": [{"tcId": 1, "seed": "00".repeat(32)}]
            }]
        })
    }

    #[test]
    fn keygen_produces_fips204_sized_expanded_keys() {
        let expected_sizes = [
            ("ML-DSA-44", 1312, 2560),
            ("ML-DSA-65", 1952, 4032),
            ("ML-DSA-87", 2592, 4896),
        ];

        for (parameter_set, pk_len, sk_len) in expected_sizes {
            let result =
                process_mldsa(&mut start_wrapper(), &keygen_vector(parameter_set)).unwrap();
            let test = &result["testGroups"][0]["tests"][0];
            assert_eq!(test["pk"].as_str().unwrap().len(), pk_len * 2);
            assert_eq!(test["sk"].as_str().unwrap().len(), sk_len * 2);
        }
    }

    #[test]
    fn deterministic_signing_and_verification_round_trip() {
        let mut wrapper = start_wrapper();
        let keygen = process_mldsa(&mut wrapper, &keygen_vector("ML-DSA-44")).unwrap();
        let key = keygen["testGroups"][0]["tests"][0]["sk"]
            .as_str()
            .unwrap()
            .to_string();
        let pk = keygen["testGroups"][0]["tests"][0]["pk"]
            .as_str()
            .unwrap()
            .to_string();

        let signature_vector = json!({
            "vsId": 2,
            "algorithm": "ML-DSA",
            "mode": "sigGen",
            "revision": "FIPS204",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-DSA-44",
                "deterministic": true,
                "tests": [{"tcId": 1,                 "sk": key.clone(), "message": "616263"}]
            }]
        });
        let first = process_mldsa(&mut wrapper, &signature_vector).unwrap();
        let second = process_mldsa(&mut wrapper, &signature_vector).unwrap();
        let signature = first["testGroups"][0]["tests"][0]["signature"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            signature,
            second["testGroups"][0]["tests"][0]["signature"]
                .as_str()
                .unwrap()
        );
        assert_eq!(signature.len(), 2420 * 2);

        let verify_vector = json!({
            "vsId": 3,
            "algorithm": "ML-DSA",
            "mode": "sigVer",
            "revision": "FIPS204",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-DSA-44",
                "pk": pk,
                "tests": [
                    {"tcId": 1, "message": "616263", "signature": signature},
                    {"tcId": 2, "message": "616264", "signature": signature}
                ]
            }]
        });
        let verified = process_mldsa(&mut wrapper, &verify_vector).unwrap();
        let tests = &verified["testGroups"][0]["tests"];
        assert_eq!(tests[0]["testPassed"], true);
        assert_eq!(tests[1]["testPassed"], false);
    }

    #[test]
    fn acvp_randomness_is_used_for_non_deterministic_signing() {
        let keygen = process_mldsa(&mut start_wrapper(), &keygen_vector("ML-DSA-44")).unwrap();
        let key = keygen["testGroups"][0]["tests"][0]["sk"]
            .as_str()
            .unwrap()
            .to_string();
        let vector = json!({
            "vsId": 4,
            "algorithm": "ML-DSA",
            "mode": "sigGen",
            "revision": "FIPS204",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-DSA-44",
                "deterministic": false,
                "tests": [{
                    "tcId": 1,
                    "sk": key.clone(),
                    "message": "616263",
                    "rnd": "A5".repeat(32)
                }]
            }]
        });
        let first = process_mldsa(&mut start_wrapper(), &vector).unwrap();
        let second = process_mldsa(&mut start_wrapper(), &vector).unwrap();
        assert_eq!(
            first["testGroups"][0]["tests"][0]["signature"],
            second["testGroups"][0]["tests"][0]["signature"]
        );
    }

    #[test]
    fn external_prehash_round_trip_uses_test_level_public_key() {
        let mut wrapper = start_wrapper();
        let keygen = process_mldsa(&mut wrapper, &keygen_vector("ML-DSA-44")).unwrap();
        let key = keygen["testGroups"][0]["tests"][0]["sk"]
            .as_str()
            .unwrap()
            .to_string();
        let pk = keygen["testGroups"][0]["tests"][0]["pk"]
            .as_str()
            .unwrap()
            .to_string();
        let signing = json!({
            "vsId": 5,
            "algorithm": "ML-DSA",
            "mode": "sigGen",
            "revision": "FIPS204",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-DSA-44",
                "deterministic": true,
                "signatureInterface": "external",
                "preHash": "preHash",
                "tests": [{
                    "tcId": 1,
                    "sk": key.clone(),
                    "message": "616263",
                    "context": "0102",
                    "hashAlg": "SHA3-256"
                }]
            }]
        });
        let signature = process_mldsa(&mut wrapper, &signing).unwrap()["testGroups"][0]["tests"][0]
            ["signature"]
            .as_str()
            .unwrap()
            .to_string();
        let verification = json!({
            "vsId": 6,
            "algorithm": "ML-DSA",
            "mode": "sigVer",
            "revision": "FIPS204",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-DSA-44",
                "signatureInterface": "external",
                "preHash": "preHash",
                "tests": [{
                    "tcId": 1,
                    "pk": pk.clone(),
                    "message": "616263",
                    "context": "0102",
                    "hashAlg": "SHA3-256",
                    "signature": signature
                }]
            }]
        });
        assert_eq!(
            process_mldsa(&mut wrapper, &verification).unwrap()["testGroups"][0]["tests"][0]
                ["testPassed"],
            true
        );
    }

    #[test]
    fn hash_ml_dsa_sha3_and_shake_variants_cover_all_parameter_sets() {
        let parameter_sets = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];
        let hash_algs = ["SHA3-256", "SHA3-512", "SHAKE-128", "SHAKE-256"];
        let mut wrapper = start_wrapper();

        for parameter_set in parameter_sets {
            let keygen = process_mldsa(&mut wrapper, &keygen_vector(parameter_set)).unwrap();
            let key = keygen["testGroups"][0]["tests"][0]["sk"]
                .as_str()
                .unwrap()
                .to_string();
            let pk = keygen["testGroups"][0]["tests"][0]["pk"]
                .as_str()
                .unwrap()
                .to_string();

            for hash_alg in hash_algs {
                let signing = json!({
                    "vsId": 7,
                    "algorithm": "ML-DSA",
                    "mode": "sigGen",
                    "revision": "FIPS204",
                    "testGroups": [{
                        "tgId": 1,
                        "testType": "AFT",
                        "parameterSet": parameter_set,
                        "deterministic": true,
                        "signatureInterface": "external",
                        "preHash": "preHash",
                        "tests": [{
                            "tcId": 1,
                            "sk": key.clone(),
                            "message": "00112233445566778899AABBCCDDEEFF",
                            "context": "010203",
                            "hashAlg": hash_alg
                        }]
                    }]
                });
                let signature = process_mldsa(&mut wrapper, &signing).unwrap()["testGroups"][0]
                    ["tests"][0]["signature"]
                    .as_str()
                    .unwrap()
                    .to_string();
                let verification = json!({
                    "vsId": 8,
                    "algorithm": "ML-DSA",
                    "mode": "sigVer",
                    "revision": "FIPS204",
                    "testGroups": [{
                        "tgId": 1,
                        "parameterSet": parameter_set,
                        "signatureInterface": "external",
                        "preHash": "preHash",
                        "tests": [{
                            "tcId": 1,
                            "pk": pk.clone(),
                            "message": "00112233445566778899AABBCCDDEEFF",
                            "context": "010203",
                            "hashAlg": hash_alg,
                            "signature": signature
                        }]
                    }]
                });
                assert_eq!(
                    process_mldsa(&mut wrapper, &verification).unwrap()["testGroups"][0]["tests"]
                        [0]["testPassed"],
                    true,
                    "{parameter_set} {hash_alg} HashML-DSA verification failed"
                );
            }
        }
    }

    #[test]
    fn supplied_mu_takes_precedence_for_external_interface() {
        let mut wrapper = start_wrapper();
        let keygen = process_mldsa(&mut wrapper, &keygen_vector("ML-DSA-44")).unwrap();
        let key = keygen["testGroups"][0]["tests"][0]["sk"]
            .as_str()
            .unwrap()
            .to_string();
        let pk = keygen["testGroups"][0]["tests"][0]["pk"]
            .as_str()
            .unwrap()
            .to_string();
        let signing = json!({
            "vsId": 7,
            "algorithm": "ML-DSA",
            "mode": "sigGen",
            "revision": "FIPS204",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-DSA-44",
                "deterministic": true,
                "signatureInterface": "external",
                "externalMu": true,
                "tests": [{"tcId": 1, "sk": key, "mu": "00".repeat(64)}]
            }]
        });
        let signature = process_mldsa(&mut wrapper, &signing).unwrap()["testGroups"][0]["tests"][0]
            ["signature"]
            .as_str()
            .unwrap()
            .to_string();
        let verification = json!({
            "vsId": 8,
            "algorithm": "ML-DSA",
            "mode": "sigVer",
            "revision": "FIPS204",
            "testGroups": [{
                "tgId": 1,
                "parameterSet": "ML-DSA-44",
                "signatureInterface": "external",
                "externalMu": true,
                "tests": [{
                    "tcId": 1,
                    "pk": pk,
                    "mu": "00".repeat(64),
                    "signature": signature
                }]
            }]
        });
        assert_eq!(
            process_mldsa(&mut wrapper, &verification).unwrap()["testGroups"][0]["tests"][0]
                ["testPassed"],
            true
        );
    }

    #[test]
    fn malformed_randomness_mu_and_external_prehash_fail() {
        let malformed_rnd = json!({
            "vsId": 4,
            "algorithm": "ML-DSA",
            "mode": "sigGen",
            "revision": "FIPS204",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-DSA-44",
                "deterministic": false,
                "tests": [{"tcId": 1, "sk": "00".repeat(2560), "message": "00", "rnd": "00"}]
            }]
        });
        assert!(process_mldsa(&mut start_wrapper(), &malformed_rnd).is_err());

        let malformed_mu = json!({
            "vsId": 5,
            "algorithm": "ML-DSA",
            "mode": "sigGen",
            "revision": "FIPS204",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-DSA-44",
                "deterministic": true,
                "signatureInterface": "internal",
                "externalMu": true,
                "tests": [{"tcId": 1, "sk": "00".repeat(2560), "mu": "00"}]
            }]
        });
        assert!(process_mldsa(&mut start_wrapper(), &malformed_mu).is_err());

        let missing_hash = json!({
            "vsId": 6,
            "algorithm": "ML-DSA",
            "mode": "sigGen",
            "revision": "FIPS204",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-DSA-44",
                "deterministic": true,
                "signatureInterface": "external",
                "preHash": "preHash",
                "tests": [{
                    "tcId": 1,
                    "sk": "00".repeat(2560),
                    "message": "00",
                    "context": ""
                }]
            }]
        });
        assert!(process_mldsa(&mut start_wrapper(), &missing_hash).is_err());

        let unsupported_test_type = json!({
            "vsId": 7,
            "algorithm": "ML-DSA",
            "mode": "sigGen",
            "revision": "FIPS204",
            "testGroups": [{
                "tgId": 1,
                "testType": "BFT",
                "parameterSet": "ML-DSA-44",
                "deterministic": true,
                "tests": []
            }]
        });
        assert!(process_mldsa(&mut start_wrapper(), &unsupported_test_type).is_err());
    }
}
