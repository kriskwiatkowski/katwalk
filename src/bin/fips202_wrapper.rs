//! Byte-oriented RustCrypto SHA-3/SHAKE ACVP module wrapper.

use katwalk::modulewrapper;
use sha3::{
    digest::{Digest, ExtendableOutput, Update, XofReader},
    Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256,
};

fn expect_args<'a>(
    args: &'a [Vec<u8>],
    count: usize,
    command: &str,
) -> Result<&'a [Vec<u8>], String> {
    if args.len() != count {
        return Err(format!(
            "{command} expects {} arguments, got {}",
            count - 1,
            args.len().saturating_sub(1)
        ));
    }
    Ok(args)
}

fn bit_len(bits: &[u8], name: &str) -> Result<u64, String> {
    let bits: [u8; 8] = bits
        .try_into()
        .map_err(|_| format!("{name} must be an 8-byte little-endian bit length"))?;
    Ok(u64::from_le_bytes(bits))
}

/// Accepts the original byte-oriented protocol and the newer protocol that
/// explicitly carries the input bit length. The latter is accepted only when
/// it describes exactly the supplied byte string.
fn input_args<'a>(args: &'a [Vec<u8>], command: &str) -> Result<(&'a [u8], &'a [u8]), String> {
    match args.len() {
        3 => Ok((&args[1], &args[2])),
        4 => {
            let input_bits = bit_len(&args[2], "message length")?;
            let byte_len = (args[1].len() as u64) * 8;
            if input_bits != byte_len {
                return Err(format!(
                    "message length {input_bits} bits is unsupported by byte-oriented {command}; expected {byte_len}"
                ));
            }
            Ok((&args[1], &args[3]))
        }
        _ => Err(format!(
            "{command} expects 2 or 3 arguments, got {}",
            args.len().saturating_sub(1)
        )),
    }
}

fn output_len(bits: &[u8]) -> Result<usize, String> {
    let bits = bit_len(bits, "SHAKE output length")?;
    if !bits.is_multiple_of(8) {
        return Err(format!(
            "SHAKE output length is unsupported by byte-oriented SHAKE, got {bits} bits"
        ));
    }
    usize::try_from(bits / 8).map_err(|_| "SHAKE output length does not fit usize".to_string())
}

fn sha3(message: &[u8], output_bits: usize) -> Result<Vec<u8>, String> {
    Ok(match output_bits {
        224 => Sha3_224::digest(message).to_vec(),
        256 => Sha3_256::digest(message).to_vec(),
        384 => Sha3_384::digest(message).to_vec(),
        512 => Sha3_512::digest(message).to_vec(),
        _ => return Err(format!("unsupported SHA3 output length: {output_bits}")),
    })
}

fn sha3_mct(message: &[u8], output_bits: usize) -> Result<Vec<u8>, String> {
    if message.len() != output_bits / 8 {
        return Err(format!(
            "SHA3-{output_bits}/MCT message must be {} bytes, got {}",
            output_bits / 8,
            message.len()
        ));
    }
    let mut digest = message.to_vec();
    for _ in 0..1000 {
        digest = sha3(&digest, output_bits)?;
    }
    Ok(digest)
}

fn sha3_ldt(
    content: &[u8],
    full_length_bits: u64,
    expansion_technique: &[u8],
    output_bits: usize,
) -> Result<Vec<u8>, String> {
    if expansion_technique != b"repeating" {
        return Err(format!(
            "unsupported expansionTechnique: {}",
            String::from_utf8_lossy(expansion_technique)
        ));
    }
    if content.is_empty() {
        return Err("large-message repeating content must not be empty".to_string());
    }
    if !full_length_bits.is_multiple_of(8) {
        return Err(format!(
            "large-message fullLength must be byte-aligned, got {full_length_bits} bits"
        ));
    }

    macro_rules! repeat_hash {
        ($hasher:ty) => {{
            let mut hasher = <$hasher>::default();
            let mut remaining = full_length_bits / 8;
            while remaining >= content.len() as u64 {
                Digest::update(&mut hasher, content);
                remaining -= content.len() as u64;
            }
            if remaining != 0 {
                let end = usize::try_from(remaining)
                    .map_err(|_| "large-message remainder does not fit usize".to_string())?;
                Digest::update(&mut hasher, &content[..end]);
            }
            hasher.finalize().to_vec()
        }};
    }

    Ok(match output_bits {
        224 => repeat_hash!(Sha3_224),
        256 => repeat_hash!(Sha3_256),
        384 => repeat_hash!(Sha3_384),
        512 => repeat_hash!(Sha3_512),
        _ => return Err(format!("unsupported SHA3 output length: {output_bits}")),
    })
}

fn config() -> Result<Vec<u8>, String> {
    serde_json::to_vec(&vec![
        serde_json::json!({"algorithm":"SHA3-224","revision":"2.0","inBit":false,"messageLength":[{"min":0,"max":65528,"increment":8}]}),
        serde_json::json!({"algorithm":"SHA3-256","revision":"2.0","inBit":false,"messageLength":[{"min":0,"max":65528,"increment":8}]}),
        serde_json::json!({"algorithm":"SHA3-384","revision":"2.0","inBit":false,"messageLength":[{"min":0,"max":65528,"increment":8}]}),
        serde_json::json!({"algorithm":"SHA3-512","revision":"2.0","inBit":false,"messageLength":[{"min":0,"max":65528,"increment":8}]}),
        serde_json::json!({"algorithm":"SHAKE-128","revision":"1.0","inBit":false,"inEmpty":true,"outputLength":[{"min":16,"max":65528,"increment":8}],"outBit":false}),
        serde_json::json!({"algorithm":"SHAKE-256","revision":"1.0","inBit":false,"inEmpty":true,"outputLength":[{"min":16,"max":65528,"increment":8}],"outBit":false}),
    ])
    .map_err(|e| format!("failed to serialize FIPS-202 configuration: {e}"))
}

fn dispatch(args: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
    let command = std::str::from_utf8(args.first().ok_or("empty frame")?)
        .map_err(|e| format!("invalid command: {e}"))?;
    match command {
        "getConfig" => {
            expect_args(args, 1, command)?;
            Ok(vec![config()?])
        }
        "SHA3-224" | "SHA3-256" | "SHA3-384" | "SHA3-512" => {
            let (message, _) = input_args(args, command)?;
            let output_bits = match command {
                "SHA3-224" => 224,
                "SHA3-256" => 256,
                "SHA3-384" => 384,
                "SHA3-512" => 512,
                _ => unreachable!(),
            };
            Ok(vec![sha3(message, output_bits)?])
        }
        "SHA3-224/MCT" | "SHA3-256/MCT" | "SHA3-384/MCT" | "SHA3-512/MCT" => {
            let args = expect_args(args, 3, command)?;
            let output_bits = match command {
                "SHA3-224/MCT" => 224,
                "SHA3-256/MCT" => 256,
                "SHA3-384/MCT" => 384,
                "SHA3-512/MCT" => 512,
                _ => unreachable!(),
            };
            Ok(vec![sha3_mct(&args[1], output_bits)?])
        }
        "SHA3-224/LDT" | "SHA3-256/LDT" | "SHA3-384/LDT" | "SHA3-512/LDT" => {
            let args = expect_args(args, 4, command)?;
            let output_bits = match command {
                "SHA3-224/LDT" => 224,
                "SHA3-256/LDT" => 256,
                "SHA3-384/LDT" => 384,
                "SHA3-512/LDT" => 512,
                _ => unreachable!(),
            };
            Ok(vec![sha3_ldt(
                &args[1],
                bit_len(&args[2], "fullLength")?,
                &args[3],
                output_bits,
            )?])
        }
        "SHAKE-128" => {
            let (message, output_bits) = input_args(args, command)?;
            let mut output = vec![0; output_len(output_bits)?];
            Shake128::default()
                .chain(message)
                .finalize_xof()
                .read(&mut output);
            Ok(vec![output])
        }
        "SHAKE-256" => {
            let (message, output_bits) = input_args(args, command)?;
            let mut output = vec![0; output_len(output_bits)?];
            Shake256::default()
                .chain(message)
                .finalize_xof()
                .read(&mut output);
            Ok(vec![output])
        }
        _ => Err(format!("unknown command: {command}")),
    }
}

fn main() {
    modulewrapper::run("fips202_wrapper", dispatch);
}

#[cfg(test)]
mod tests {
    use super::{config, dispatch, sha3, sha3_ldt};

    #[test]
    fn fips202_sha3_and_shake_known_answers() {
        let sha3_256 = dispatch(&[
            b"SHA3-256".to_vec(),
            Vec::new(),
            0u64.to_le_bytes().to_vec(),
        ])
        .unwrap();
        assert_eq!(
            hex::encode(&sha3_256[0]),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        let sha3_512 = dispatch(&[
            b"SHA3-512".to_vec(),
            Vec::new(),
            0u64.to_le_bytes().to_vec(),
        ])
        .unwrap();
        assert_eq!(
            hex::encode(&sha3_512[0]),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
        let shake_128 = dispatch(&[
            b"SHAKE-128".to_vec(),
            hex::decode("B3E0ABDFE024B4D76D24F0").unwrap(),
            256u64.to_le_bytes().to_vec(),
        ])
        .unwrap();
        assert_eq!(
            hex::encode(&shake_128[0]),
            "6065987cb4865baa5374cbe2803dc16228ee0ffde023ea26f0d8cfc632ddd423"
        );
    }

    #[test]
    fn bit_oriented_requests_are_rejected() {
        assert!(dispatch(&[
            b"SHA3-224".to_vec(),
            hex::decode("08FF1739BC139096A044C0").unwrap(),
            82u64.to_le_bytes().to_vec(),
            0u64.to_le_bytes().to_vec(),
        ])
        .is_err());
        assert!(dispatch(&[
            b"SHAKE-256".to_vec(),
            Vec::new(),
            0u64.to_le_bytes().to_vec(),
            517u64.to_le_bytes().to_vec(),
        ])
        .is_err());
    }

    #[test]
    fn configuration_advertises_byte_oriented_interfaces() {
        let config: serde_json::Value = serde_json::from_slice(&config().unwrap()).unwrap();
        for capability in config.as_array().unwrap() {
            assert_eq!(capability["inBit"], false);
            if capability["algorithm"]
                .as_str()
                .unwrap()
                .starts_with("SHAKE")
            {
                assert_eq!(capability["outBit"], false);
            }
        }
    }

    #[test]
    fn sha3_ldt_repeating_input_matches_direct_hashing() {
        let repeated = [0x1d, 0x89, 0xd1, 0x1d, 0xa2, 0xf6, 0x2c, 0xf9];
        let mut message = Vec::new();
        for _ in 0..18 {
            message.extend_from_slice(&repeated);
        }
        assert_eq!(
            sha3_ldt(&repeated, 1152, b"repeating", 224).unwrap(),
            sha3(&message, 224).unwrap()
        );
    }
}
