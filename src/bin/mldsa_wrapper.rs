// ACVP binary-protocol wrapper around the RustCrypto ml-dsa crate.
// See katwalk::modulewrapper for the shared stdin/stdout framing.

use katwalk::modulewrapper;
use ml_dsa::signature::rand_core::{TryCryptoRng, TryRng};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, Keypair,
    MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signature, SigningKey, VerifyingKey, B32,
};
use serde::Serialize;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256,
};
use std::convert::TryFrom;
use std::fmt;
use std::panic::AssertUnwindSafe;

const UNSUPPORTED: &[u8] = b"unsupported";
const PARAMETER_SETS: [&str; 3] = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];

#[derive(Serialize)]
struct Registration {
    algorithm: &'static str,
    mode: &'static str,
    revision: &'static str,
    #[serde(rename = "parameterSets", skip_serializing_if = "Option::is_none")]
    parameter_sets: Option<&'static [&'static str]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capabilities: Option<Vec<Capability>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deterministic: Option<[bool; 2]>,
    #[serde(
        rename = "signatureInterfaces",
        skip_serializing_if = "Option::is_none"
    )]
    signature_interfaces: Option<[&'static str; 2]>,
    #[serde(rename = "externalMu", skip_serializing_if = "Option::is_none")]
    external_mu: Option<[bool; 2]>,
    #[serde(rename = "preHash", skip_serializing_if = "Option::is_none")]
    pre_hash: Option<[&'static str; 2]>,
}

#[derive(Serialize)]
struct Capability {
    #[serde(rename = "parameterSets")]
    parameter_sets: &'static [&'static str],
    #[serde(rename = "messageLength")]
    message_length: [LengthDomain; 1],
    #[serde(rename = "hashAlgs")]
    hash_algs: Vec<&'static str>,
    #[serde(rename = "contextLength")]
    context_length: [LengthDomain; 1],
}

#[derive(Serialize)]
struct LengthDomain {
    min: u32,
    max: u32,
    increment: u32,
}

fn config() -> Result<Vec<u8>, String> {
    let internal_capability = || Capability {
        parameter_sets: &PARAMETER_SETS,
        message_length: [LengthDomain {
            min: 8,
            max: 65_536,
            increment: 8,
        }],
        hash_algs: vec![
            "SHA2-224",
            "SHA2-256",
            "SHA2-384",
            "SHA2-512",
            "SHA2-512/224",
            "SHA2-512/256",
            "SHA3-224",
            "SHA3-256",
            "SHA3-384",
            "SHA3-512",
            "SHAKE-128",
            "SHAKE-256",
        ],
        context_length: [LengthDomain {
            min: 0,
            max: 2040,
            increment: 8,
        }],
    };
    serde_json::to_vec(&vec![
        Registration {
            algorithm: "ML-DSA",
            mode: "keyGen",
            revision: "FIPS204",
            parameter_sets: Some(&PARAMETER_SETS),
            capabilities: None,
            deterministic: None,
            signature_interfaces: None,
            external_mu: None,
            pre_hash: None,
        },
        Registration {
            algorithm: "ML-DSA",
            mode: "sigGen",
            revision: "FIPS204",
            parameter_sets: None,
            capabilities: Some(vec![internal_capability()]),
            deterministic: Some([true, false]),
            signature_interfaces: Some(["external", "internal"]),
            external_mu: Some([true, false]),
            pre_hash: Some(["pure", "preHash"]),
        },
        Registration {
            algorithm: "ML-DSA",
            mode: "sigVer",
            revision: "FIPS204",
            parameter_sets: None,
            capabilities: Some(vec![internal_capability()]),
            deterministic: None,
            signature_interfaces: Some(["external", "internal"]),
            external_mu: Some([true, false]),
            pre_hash: Some(["pure", "preHash"]),
        },
    ])
    .map_err(|e| format!("failed to serialize ML-DSA configuration: {e}"))
}

fn expect_args<'a>(
    args: &'a [Vec<u8>],
    expected: usize,
    command: &str,
) -> Result<&'a [Vec<u8>], String> {
    if args.len() != expected {
        return Err(format!(
            "{command} expects {} arguments, got {}",
            expected - 1,
            args.len().saturating_sub(1)
        ));
    }
    Ok(args)
}

fn decode_expanded_key<P: MlDsaParams>(key: &[u8]) -> Result<ExpandedSigningKey<P>, String> {
    let expected_len = ExpandedSigningKeyBytes::<P>::default().len();
    let key = ExpandedSigningKeyBytes::<P>::try_from(key).map_err(|_| {
        format!(
            "expanded secret key must be {expected_len} bytes, got {}",
            key.len()
        )
    })?;

    // The upstream API documents this legacy expanded-key decoder as potentially
    // panicking for malformed input. Treat that as a malformed wrapper request
    // rather than allowing it to terminate the wrapper process.
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        #[allow(deprecated)]
        {
            ExpandedSigningKey::<P>::from_expanded(&key)
        }
    }))
    .map_err(|_| "expanded secret key is malformed".to_string())
}

fn decode_signing_key<P: MlDsaParams>(
    key_format: &[u8],
    key: &[u8],
) -> Result<ExpandedSigningKey<P>, String> {
    match key_format {
        b"seed" => {
            let seed = B32::try_from(key)
                .map_err(|_| format!("seed must be 32 bytes, got {}", key.len()))?;
            Ok(SigningKey::<P>::from_seed(&seed).expanded_key().clone())
        }
        b"expanded" => decode_expanded_key(key),
        _ => Err(format!(
            "unsupported ML-DSA key format: {}",
            String::from_utf8_lossy(key_format)
        )),
    }
}

fn decode_randomness(rnd: &[u8]) -> Result<B32, String> {
    B32::try_from(rnd).map_err(|_| format!("rnd must be 32 bytes, got {}", rnd.len()))
}

struct AcvpRng {
    rnd: B32,
    offset: usize,
}

impl AcvpRng {
    fn new(rnd: B32) -> Self {
        Self { rnd, offset: 0 }
    }
}

impl fmt::Debug for AcvpRng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AcvpRng(..)")
    }
}

#[derive(Debug)]
struct RandomnessExhausted;

impl fmt::Display for RandomnessExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ACVP supplied randomness exhausted")
    }
}

impl std::error::Error for RandomnessExhausted {}

impl TryRng for AcvpRng {
    type Error = RandomnessExhausted;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        let end = self
            .offset
            .checked_add(output.len())
            .filter(|&end| end <= self.rnd.len())
            .ok_or(RandomnessExhausted)?;
        output.copy_from_slice(&self.rnd[self.offset..end]);
        self.offset = end;
        Ok(())
    }
}

impl TryCryptoRng for AcvpRng {}

fn prehashed_message(message: &[u8], context: &[u8], hash_alg: &[u8]) -> Result<Vec<u8>, String> {
    if context.len() > u8::MAX as usize {
        return Err(format!(
            "context must be at most 255 bytes, got {}",
            context.len()
        ));
    }
    let (oid, digest) = match hash_alg {
        // DER OBJECT IDENTIFIER encodings from FIPS 204, Table 2.
        b"SHA2-224" => (
            [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
            ]
            .as_slice(),
            Sha224::digest(message).to_vec(),
        ),
        b"SHA2-256" => (
            [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            ]
            .as_slice(),
            Sha256::digest(message).to_vec(),
        ),
        b"SHA2-384" => (
            [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
            ]
            .as_slice(),
            Sha384::digest(message).to_vec(),
        ),
        b"SHA2-512" => (
            [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
            ]
            .as_slice(),
            Sha512::digest(message).to_vec(),
        ),
        b"SHA2-512/224" => (
            [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05,
            ]
            .as_slice(),
            Sha512_224::digest(message).to_vec(),
        ),
        b"SHA2-512/256" => (
            [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06,
            ]
            .as_slice(),
            Sha512_256::digest(message).to_vec(),
        ),
        b"SHA3-224" => (
            [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07,
            ]
            .as_slice(),
            Sha3_224::digest(message).to_vec(),
        ),
        b"SHA3-256" => (
            [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
            ]
            .as_slice(),
            Sha3_256::digest(message).to_vec(),
        ),
        b"SHA3-384" => (
            [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
            ]
            .as_slice(),
            Sha3_384::digest(message).to_vec(),
        ),
        b"SHA3-512" => (
            [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a,
            ]
            .as_slice(),
            Sha3_512::digest(message).to_vec(),
        ),
        b"SHAKE-128" => {
            let mut digest = [0; 32];
            let mut reader = Shake128::default().chain(message).finalize_xof();
            reader.read(&mut digest);
            (
                [
                    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b,
                ]
                .as_slice(),
                digest.to_vec(),
            )
        }
        b"SHAKE-256" => {
            let mut digest = [0; 64];
            let mut reader = Shake256::default().chain(message).finalize_xof();
            reader.read(&mut digest);
            (
                [
                    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c,
                ]
                .as_slice(),
                digest.to_vec(),
            )
        }
        _ => {
            return Err(format!(
                "unsupported ML-DSA pre-hash algorithm: {}",
                String::from_utf8_lossy(hash_alg)
            ));
        }
    };
    let mut encoded = Vec::with_capacity(2 + context.len() + oid.len() + digest.len());
    encoded.push(1);
    encoded.push(context.len() as u8);
    encoded.extend_from_slice(context);
    encoded.extend_from_slice(oid);
    encoded.extend_from_slice(&digest);
    Ok(encoded)
}

fn keygen<P: MlDsaParams>(seed: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let seed =
        B32::try_from(seed).map_err(|_| format!("seed must be 32 bytes, got {}", seed.len()))?;
    let key = SigningKey::<P>::from_seed(&seed);
    let pk = key.verifying_key().encode().as_slice().to_vec();
    #[allow(deprecated)]
    let sk = key.expanded_key().to_expanded().as_slice().to_vec();
    Ok(vec![pk, sk])
}

fn sign_internal<P: MlDsaParams>(
    key_format: &[u8],
    key: &[u8],
    message: &[u8],
    rnd: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    let key = decode_signing_key::<P>(key_format, key)?;
    let rnd = decode_randomness(rnd)?;
    let signature =
        std::panic::catch_unwind(AssertUnwindSafe(|| key.sign_internal(&[message], &rnd)))
            .map_err(|_| "ML-DSA internal signing failed for the supplied key".to_string())?;
    Ok(vec![signature.encode().as_slice().to_vec()])
}

fn sign_mu<P: MlDsaParams>(
    key_format: &[u8],
    key: &[u8],
    mu: &[u8],
    rnd: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    let key = decode_signing_key::<P>(key_format, key)?;
    let mu = mu
        .try_into()
        .map_err(|_| format!("mu must be 64 bytes, got {}", mu.len()))?;
    let mut rng = AcvpRng::new(decode_randomness(rnd)?);
    let signature = key
        .sign_mu_randomized(&mu, &mut rng)
        .map_err(|_| "ML-DSA external mu signing failed".to_string())?;
    Ok(vec![signature.encode().as_slice().to_vec()])
}

fn sign_external<P: MlDsaParams>(
    key_format: &[u8],
    key: &[u8],
    message: &[u8],
    context: &[u8],
    pre_hash: &[u8],
    hash_alg: &[u8],
    rnd: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    let key = decode_signing_key::<P>(key_format, key)?;
    let rnd = decode_randomness(rnd)?;
    let signature = match pre_hash {
        b"pure" => {
            if !hash_alg.is_empty() {
                return Err("hashAlg must be absent for pure ML-DSA".to_string());
            }
            let mut rng = AcvpRng::new(rnd);
            key.sign_randomized(message, context, &mut rng)
                .map_err(|_| "ML-DSA external signing failed".to_string())?
        }
        b"preHash" => {
            let message = prehashed_message(message, context, hash_alg)?;
            std::panic::catch_unwind(AssertUnwindSafe(|| key.sign_internal(&[&message], &rnd)))
                .map_err(|_| "ML-DSA pre-hash signing failed for the supplied key".to_string())?
        }
        _ => {
            return Err(format!(
                "unsupported ML-DSA preHash mode: {}",
                String::from_utf8_lossy(pre_hash)
            ));
        }
    };
    Ok(vec![signature.encode().as_slice().to_vec()])
}

fn verify_internal<P: MlDsaParams>(
    pk: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    let expected_pk_len = EncodedVerifyingKey::<P>::default().len();
    let pk = EncodedVerifyingKey::<P>::try_from(pk).map_err(|_| {
        format!(
            "public key must be {expected_pk_len} bytes, got {}",
            pk.len()
        )
    })?;
    let expected_signature_len = EncodedSignature::<P>::default().len();
    let signature = EncodedSignature::<P>::try_from(signature).map_err(|_| {
        format!(
            "signature must be {expected_signature_len} bytes, got {}",
            signature.len()
        )
    })?;
    let Some(signature) = Signature::<P>::decode(&signature) else {
        return Ok(false);
    };
    let key = VerifyingKey::<P>::decode(&pk);
    Ok(std::panic::catch_unwind(AssertUnwindSafe(|| {
        key.verify_internal(message, &signature)
    }))
    .unwrap_or(false))
}

fn decode_verification_inputs<P: MlDsaParams>(
    pk: &[u8],
    signature: &[u8],
) -> Result<(VerifyingKey<P>, Option<Signature<P>>), String> {
    let expected_pk_len = EncodedVerifyingKey::<P>::default().len();
    let pk = EncodedVerifyingKey::<P>::try_from(pk).map_err(|_| {
        format!(
            "public key must be {expected_pk_len} bytes, got {}",
            pk.len()
        )
    })?;
    let expected_signature_len = EncodedSignature::<P>::default().len();
    let signature = EncodedSignature::<P>::try_from(signature).map_err(|_| {
        format!(
            "signature must be {expected_signature_len} bytes, got {}",
            signature.len()
        )
    })?;
    Ok((
        VerifyingKey::<P>::decode(&pk),
        Signature::<P>::decode(&signature),
    ))
}

fn verify_mu<P: MlDsaParams>(pk: &[u8], mu: &[u8], signature: &[u8]) -> Result<bool, String> {
    let (key, signature) = decode_verification_inputs::<P>(pk, signature)?;
    let Some(signature) = signature else {
        return Ok(false);
    };
    let mu = mu
        .try_into()
        .map_err(|_| format!("mu must be 64 bytes, got {}", mu.len()))?;
    Ok(key.verify_mu(&mu, &signature))
}

fn verify_external<P: MlDsaParams>(
    pk: &[u8],
    message: &[u8],
    context: &[u8],
    pre_hash: &[u8],
    hash_alg: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    let (key, signature) = decode_verification_inputs::<P>(pk, signature)?;
    let Some(signature) = signature else {
        return Ok(false);
    };
    match pre_hash {
        b"pure" => {
            if !hash_alg.is_empty() {
                return Err("hashAlg must be absent for pure ML-DSA".to_string());
            }
            Ok(key.verify_with_context(message, context, &signature))
        }
        b"preHash" => {
            let message = prehashed_message(message, context, hash_alg)?;
            Ok(std::panic::catch_unwind(AssertUnwindSafe(|| {
                key.verify_internal(&message, &signature)
            }))
            .unwrap_or(false))
        }
        _ => Err(format!(
            "unsupported ML-DSA preHash mode: {}",
            String::from_utf8_lossy(pre_hash)
        )),
    }
}

fn dispatch(args: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
    let command = std::str::from_utf8(args.first().ok_or("empty frame")?)
        .map_err(|e| format!("invalid command: {e}"))?;

    match command {
        "getConfig" => {
            expect_args(args, 1, command)?;
            Ok(vec![config()?])
        }
        "ML-DSA/keyGen" => {
            let args = expect_args(args, 3, command)?;
            match std::str::from_utf8(&args[1])
                .map_err(|e| format!("invalid parameter set: {e}"))?
            {
                "ML-DSA-44" => keygen::<MlDsa44>(&args[2]),
                "ML-DSA-65" => keygen::<MlDsa65>(&args[2]),
                "ML-DSA-87" => keygen::<MlDsa87>(&args[2]),
                _ => Ok(vec![UNSUPPORTED.to_vec()]),
            }
        }
        "ML-DSA/signInternal" => {
            let args = expect_args(args, 6, command)?;
            match std::str::from_utf8(&args[1])
                .map_err(|e| format!("invalid parameter set: {e}"))?
            {
                "ML-DSA-44" => sign_internal::<MlDsa44>(&args[2], &args[3], &args[4], &args[5]),
                "ML-DSA-65" => sign_internal::<MlDsa65>(&args[2], &args[3], &args[4], &args[5]),
                "ML-DSA-87" => sign_internal::<MlDsa87>(&args[2], &args[3], &args[4], &args[5]),
                _ => Ok(vec![UNSUPPORTED.to_vec()]),
            }
        }
        "ML-DSA/signMu" => {
            let args = expect_args(args, 6, command)?;
            match std::str::from_utf8(&args[1])
                .map_err(|e| format!("invalid parameter set: {e}"))?
            {
                "ML-DSA-44" => sign_mu::<MlDsa44>(&args[2], &args[3], &args[4], &args[5]),
                "ML-DSA-65" => sign_mu::<MlDsa65>(&args[2], &args[3], &args[4], &args[5]),
                "ML-DSA-87" => sign_mu::<MlDsa87>(&args[2], &args[3], &args[4], &args[5]),
                _ => Ok(vec![UNSUPPORTED.to_vec()]),
            }
        }
        "ML-DSA/signExternal" => {
            let args = expect_args(args, 9, command)?;
            match std::str::from_utf8(&args[1])
                .map_err(|e| format!("invalid parameter set: {e}"))?
            {
                "ML-DSA-44" => sign_external::<MlDsa44>(
                    &args[2], &args[3], &args[4], &args[5], &args[6], &args[7], &args[8],
                ),
                "ML-DSA-65" => sign_external::<MlDsa65>(
                    &args[2], &args[3], &args[4], &args[5], &args[6], &args[7], &args[8],
                ),
                "ML-DSA-87" => sign_external::<MlDsa87>(
                    &args[2], &args[3], &args[4], &args[5], &args[6], &args[7], &args[8],
                ),
                _ => Ok(vec![UNSUPPORTED.to_vec()]),
            }
        }
        "ML-DSA/verifyInternal" => {
            let args = expect_args(args, 5, command)?;
            let passed = match std::str::from_utf8(&args[1])
                .map_err(|e| format!("invalid parameter set: {e}"))?
            {
                "ML-DSA-44" => verify_internal::<MlDsa44>(&args[2], &args[3], &args[4])?,
                "ML-DSA-65" => verify_internal::<MlDsa65>(&args[2], &args[3], &args[4])?,
                "ML-DSA-87" => verify_internal::<MlDsa87>(&args[2], &args[3], &args[4])?,
                _ => return Ok(vec![UNSUPPORTED.to_vec()]),
            };
            Ok(vec![vec![u8::from(passed)]])
        }
        "ML-DSA/verifyMu" => {
            let args = expect_args(args, 5, command)?;
            let passed = match std::str::from_utf8(&args[1])
                .map_err(|e| format!("invalid parameter set: {e}"))?
            {
                "ML-DSA-44" => verify_mu::<MlDsa44>(&args[2], &args[3], &args[4])?,
                "ML-DSA-65" => verify_mu::<MlDsa65>(&args[2], &args[3], &args[4])?,
                "ML-DSA-87" => verify_mu::<MlDsa87>(&args[2], &args[3], &args[4])?,
                _ => return Ok(vec![UNSUPPORTED.to_vec()]),
            };
            Ok(vec![vec![u8::from(passed)]])
        }
        "ML-DSA/verifyExternal" => {
            let args = expect_args(args, 8, command)?;
            let passed = match std::str::from_utf8(&args[1])
                .map_err(|e| format!("invalid parameter set: {e}"))?
            {
                "ML-DSA-44" => verify_external::<MlDsa44>(
                    &args[2], &args[3], &args[4], &args[5], &args[6], &args[7],
                )?,
                "ML-DSA-65" => verify_external::<MlDsa65>(
                    &args[2], &args[3], &args[4], &args[5], &args[6], &args[7],
                )?,
                "ML-DSA-87" => verify_external::<MlDsa87>(
                    &args[2], &args[3], &args[4], &args[5], &args[6], &args[7],
                )?,
                _ => return Ok(vec![UNSUPPORTED.to_vec()]),
            };
            Ok(vec![vec![u8::from(passed)]])
        }
        _ => Err(format!("unknown command: {command}")),
    }
}

fn main() {
    modulewrapper::run("mldsa_wrapper", dispatch);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::path::Path;

    #[test]
    fn fips202_vectors_validate_hashml_dsa_sha3_and_shake_prehashes() {
        // SHA3-256 tcId=221 and SHA3-512 tcId=384 from the local FIPS-202
        // corpus. SHAKE-128 tcId=230 provides the 256-bit HashML-DSA
        // prehash, while SHAKE-256 tcId=35 provides at least its required
        // 512-bit prehash output.
        let cases = [
            (
                "SHA3-256",
                "",
                "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A",
            ),
            (
                "SHA3-512",
                "",
                "A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26",
            ),
            (
                "SHAKE-128",
                "B3E0ABDFE024B4D76D24F0",
                "6065987CB4865BAA5374CBE2803DC16228EE0FFDE023EA26F0D8CFC632DDD423",
            ),
            (
                "SHAKE-256",
                "A21198252B3928D4273BDC3BE3F3E026BAB4F52008491A1814EBBE9C39FBEA87118CD8993EA307582AA8C2ADBFB9336F29BF7A",
                "78C4EC2BA13DAF27FA4E67B78BC70CFF3FBA1B09157C5639BD2FF751BCCE48CD3200BE88554A988CF7A11767A9155DEA750CB909B11B9A1DFB9F49B875C8EFE3",
            ),
        ];

        for (hash_alg, message, expected_digest) in cases {
            let message = hex::decode(message).unwrap();
            let encoded = prehashed_message(&message, &[], hash_alg.as_bytes()).unwrap();
            // All FIPS 204 HashML-DSA OIDs used here are 11-byte DER values.
            assert_eq!(
                hex::encode(&encoded[13..]),
                expected_digest.to_ascii_lowercase(),
                "{hash_alg} pre-hash did not match its FIPS-202 KAT"
            );
        }
    }

    fn fips202_digest(algorithm: &str, message: &[u8], output_len: usize) -> Vec<u8> {
        match algorithm {
            "SHA3-256" => Sha3_256::digest(message).to_vec(),
            "SHA3-512" => Sha3_512::digest(message).to_vec(),
            "SHAKE-128" => {
                let mut output = vec![0; output_len];
                Shake128::default()
                    .chain(message)
                    .finalize_xof()
                    .read(&mut output);
                output
            }
            "SHAKE-256" => {
                let mut output = vec![0; output_len];
                Shake256::default()
                    .chain(message)
                    .finalize_xof()
                    .read(&mut output);
                output
            }
            _ => unreachable!("test only calls registered FIPS-202 algorithms"),
        }
    }

    #[test]
    fn fips202_byte_aligned_aft_vectors_when_configured() {
        let Ok(root) = std::env::var("ACVP_FIPS202_DIR") else {
            return;
        };
        let root = Path::new(&root);
        let algorithms = ["SHA3-256", "SHA3-512", "SHAKE-128", "SHAKE-256"];
        let mut tested = 0;

        for algorithm in algorithms {
            let prompt: Value = serde_json::from_slice(
                &std::fs::read(root.join(algorithm).join("prompt.json"))
                    .unwrap_or_else(|e| panic!("failed to read {algorithm} FIPS-202 prompt: {e}")),
            )
            .unwrap_or_else(|e| panic!("failed to parse {algorithm} FIPS-202 prompt: {e}"));
            let expected: Value = serde_json::from_slice(
                &std::fs::read(root.join(algorithm).join("expectedResults.json")).unwrap_or_else(
                    |e| panic!("failed to read {algorithm} FIPS-202 expected results: {e}"),
                ),
            )
            .unwrap_or_else(|e| {
                panic!("failed to parse {algorithm} FIPS-202 expected results: {e}")
            });
            let expected_groups = expected["testGroups"]
                .as_array()
                .expect("FIPS-202 expected results must contain testGroups");

            for group in prompt["testGroups"]
                .as_array()
                .expect("FIPS-202 prompt must contain testGroups")
            {
                if group["testType"].as_str() != Some("AFT") {
                    continue;
                }
                let group_id = group["tgId"]
                    .as_u64()
                    .expect("FIPS-202 AFT group must contain tgId");
                let expected_group = expected_groups
                    .iter()
                    .find(|candidate| candidate["tgId"].as_u64() == Some(group_id))
                    .unwrap_or_else(|| panic!("missing expected group {group_id} for {algorithm}"));

                for test in group["tests"]
                    .as_array()
                    .expect("FIPS-202 AFT group must contain tests")
                {
                    let message_len = test["len"]
                        .as_u64()
                        .expect("FIPS-202 AFT test must contain len");
                    let output_len = test["outLen"].as_u64().unwrap_or(0);
                    if message_len % 8 != 0 || (output_len != 0 && output_len % 8 != 0) {
                        continue;
                    }
                    let test_id = test["tcId"]
                        .as_u64()
                        .expect("FIPS-202 AFT test must contain tcId");
                    let expected_test = expected_group["tests"]
                        .as_array()
                        .expect("FIPS-202 expected group must contain tests")
                        .iter()
                        .find(|candidate| candidate["tcId"].as_u64() == Some(test_id))
                        .unwrap_or_else(|| {
                            panic!("missing expected test {group_id}/{test_id} for {algorithm}")
                        });
                    let message = hex::decode(
                        test["msg"]
                            .as_str()
                            .expect("FIPS-202 AFT test must contain msg"),
                    )
                    .expect("FIPS-202 AFT message must be hexadecimal");
                    let expected_output = hex::decode(
                        expected_test["md"]
                            .as_str()
                            .expect("FIPS-202 expected test must contain md"),
                    )
                    .expect("FIPS-202 expected digest must be hexadecimal");
                    assert_eq!(
                        fips202_digest(algorithm, &message, expected_output.len()),
                        expected_output,
                        "{algorithm} FIPS-202 AFT mismatch at {group_id}/{test_id}"
                    );
                    tested += 1;
                }
            }
        }
        assert!(tested > 0, "no byte-aligned FIPS-202 AFT cases were found");
    }
}
