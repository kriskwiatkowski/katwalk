use hex::FromHex;

// Converts txt to usize
fn to_usize(s: &str) -> usize {
    if s.is_empty() {
        return 0;
    }
    match s.parse() {
        Ok(v) => v,
        Err(e) => panic!("{}", e),
    }
}

// Converts hex in txt, to an array of bytes
fn to_u8arr(s: &str) -> Vec<u8> {
    let mut t = String::from(s);
    // from_hex requres that hex is properly formated
    // Numbers in FIPS186-4 have 131 digits, so prepend
    // with 0.
    if t.len() % 2 != 0 {
        t.insert_str(0, "0");
    }
    match Vec::from_hex(t) {
        Ok(v) => v,
        // Panic here is good, because when execution is
        // here it means all checks should be already done.
        Err(e) => panic!("{}", e),
    }
}

pub mod reader {
    use std::cmp::Ordering;
    use std::collections::{HashSet, LinkedList};
    use std::io::{BufRead, BufReader};

    #[derive(Copy, Clone)]
    pub enum AlgType {
        AlgSignature,
        AlgEcdsaSignature, // TODO: needs merging with AlgSignature
        AlgEcKey,
        AlgKem,
        AlgHash,
        AlgXof,
        AlgDh,
        AlgHmac,
        AlgKdf,
        AlgDrbg,
    }

    #[derive(Debug, Default)]
    pub struct Signature {
        pub count: usize,
        pub seed: Vec<u8>,
        pub mlen: usize,
        pub msg: Vec<u8>,
        pub pk: Vec<u8>,
        pub sk: Vec<u8>,
        pub smlen: usize,
        pub sm: Vec<u8>,
        /// Set to true if verification must fail
        pub result: char,
    }

    #[derive(Debug, Default)]
    pub struct EcdsaSignature {
        pub sign: Signature,
    }

    #[derive(Debug, Default)]
    pub struct EcdsaPublicKeyValidation {
        pub pk: Vec<u8>,
        pub result: char,
    }

    #[derive(Debug, Default)]
    pub struct Kem {
        pub count: usize,
        pub seed: Vec<u8>,
        pub pk: Vec<u8>,
        pub sk: Vec<u8>,
        pub ct: Vec<u8>,
        pub ss: Vec<u8>,
        // Ciphertext that is NOT a result of encapsulation
        pub ct_n: Vec<u8>,
        // Shared secret that is a result of decapsulation of ct_n
        pub ss_n: Vec<u8>,
    }

    #[derive(Debug, Default)]
    pub struct Hash {
        pub len: usize,
        pub msg: Vec<u8>,
        pub md: Vec<u8>,
    }

    #[derive(Debug, Default)]
    pub struct Xof {
        pub count: usize,
        pub len: usize,
        pub outputlen: usize,
        pub msg: Vec<u8>,
        pub output: Vec<u8>,
    }

    #[derive(Debug, Default)]
    pub struct Dh {
        pub count: usize,
        pub public_key_x: Vec<u8>,
        pub public_key_y: Vec<u8>,
        pub other_key_x: Vec<u8>,
        pub other_key_y: Vec<u8>,
        pub shared_secret: Vec<u8>,
        pub secret_key: Vec<u8>,
    }

    #[derive(Debug, Default)]
    pub struct Hmac {
        pub count: usize,
        pub msg: Vec<u8>,
        pub mac: Vec<u8>,
        pub secret_key: Vec<u8>,
        tlen: usize,
        klen: usize,
    }

    #[derive(Debug, Default)]
    pub struct Kdf {
        pub count: usize,
        pub k0: Vec<u8>,
        pub salt: Vec<u8>,
        pub prk: Vec<u8>,
        pub info: Vec<u8>,
        pub iv: Vec<u8>,
        pub derived_key: Vec<u8>,
    }

    #[derive(Debug, Default)]
    pub struct Drbg {
        pub count: usize,
        pub entropy_input: Vec<u8>,
        pub entropy_input_reseed: Vec<u8>,
        pub nonce: Vec<u8>,
        pub personalization: Vec<u8>,
        pub additional_input_reseed: Vec<u8>,
        pub additional_input: LinkedList<Vec<u8>>,
        pub returned_bits: Vec<u8>,
    }

    pub struct Kat {
        pub scheme_type: AlgType,
        pub scheme_id: u32,
        pub kat_file: &'static str,
    }

    pub struct KatReader<R: std::io::Read> {
        reader: BufReader<R>,
        alg_type: AlgType,
        scheme_id: u32,
        current_sections: HashSet<String>,
        is_section_parsing_finished: bool,
        elements_processed: usize,
    }

    // Possible results of reading a single KAT from file
    enum ReadResult {
        ReadMore,
        ReadDone,
        ReadError,
    }

    // TODO: ensure 'sm' must always be the last one
    // Implement KatParser for signature
    impl Signature {
        fn parse_element(self: &mut Self, k: &str, v: &str) -> ReadResult {
            match k {
                "count" => self.count = super::to_usize(v),
                "result" => {
                    let s = v.to_string();
                    self.result = match s.trim_start().chars().nth(0) {
                        Some(val) => val,
                        None => 'E',
                    }
                }
                "seed" => self.seed = super::to_u8arr(v),
                "mlen" => self.mlen = super::to_usize(v),
                "msg" => self.msg = super::to_u8arr(v),
                "pk" => self.pk = super::to_u8arr(v),
                "sk" => self.sk = super::to_u8arr(v),
                "smlen" => self.smlen = super::to_usize(v),
                "sm" => {
                    self.sm = super::to_u8arr(v);
                    // Last item for the record
                    return ReadResult::ReadDone;
                }
                _ => return ReadResult::ReadMore,
            };
            ReadResult::ReadMore
        }
    }

    impl EcdsaSignature {
        fn parse_element(self: &mut Self, k: &str, v: &str) -> ReadResult {
            match k {
                "Msg" => self.sign.msg = super::to_u8arr(v),
                "d" => self.sign.sk = super::to_u8arr(v),
                "k" => self.sign.seed = super::to_u8arr(v),
                "Qx" => self.sign.pk = super::to_u8arr(v),
                "Qy" => self.sign.pk.append(&mut super::to_u8arr(v).to_vec()),
                "R" => self.sign.sm = super::to_u8arr(v),
                "S" => {
                    self.sign.sm.append(&mut super::to_u8arr(v).to_vec());
                    // Last item for the record
                    return ReadResult::ReadDone;
                }
                _ => return ReadResult::ReadMore,
            };
            ReadResult::ReadMore
        }
    }

    impl EcdsaPublicKeyValidation {
        fn parse_element(self: &mut Self, k: &str, v: &str) -> ReadResult {
            match k {
                "Qx" => self.pk = super::to_u8arr(v),
                "Qy" => self.pk.append(&mut super::to_u8arr(v).to_vec()),
                "Result" => {
                    let s = v.to_string();
                    self.result = match s.trim_start().chars().nth(0) {
                        Some(val) => val,
                        None => 'E',
                    };
                    return ReadResult::ReadDone;
                }
                _ => return ReadResult::ReadMore,
            };
            ReadResult::ReadMore
        }
    }

    // Implement KatParser for signature
    impl Kem {
        fn parse_element(self: &mut Self, k: &str, v: &str) -> ReadResult {
            match k {
                "count" => self.count = super::to_usize(v),
                "seed" => self.seed = super::to_u8arr(v),
                "pk" => self.pk = super::to_u8arr(v),
                "sk" => self.sk = super::to_u8arr(v),
                "ct_n" => self.ct_n = super::to_u8arr(v),
                "ss_n" => self.ss_n = super::to_u8arr(v),
                "ct" => self.ct = super::to_u8arr(v),
                "ss" => {
                    self.ss = super::to_u8arr(v);
                    // Last item for the record
                    return ReadResult::ReadDone;
                }
                _ => return ReadResult::ReadMore,
            };
            ReadResult::ReadMore
        }
    }

    // Implement parser for the hash functions
    impl Hash {
        fn parse_element(self: &mut Self, k: &str, v: &str) -> ReadResult {
            match k {
                "Len" => self.len = super::to_usize(v),
                "Msg" => self.msg = super::to_u8arr(v),
                "MD" => {
                    self.md = super::to_u8arr(v);
                    return ReadResult::ReadDone;
                }
                _ => return ReadResult::ReadMore,
            }
            ReadResult::ReadMore
        }
    }

    // Implement parser for the XOF functions
    impl Xof {
        fn parse_element(self: &mut Self, k: &str, v: &str) -> ReadResult {
            match k {
                "COUNT" => self.count = super::to_usize(v),
                "Outputlen" => self.outputlen = super::to_usize(v),
                "Msg" => self.msg = super::to_u8arr(v),
                "Len" => self.len = super::to_usize(v),
                "Output" => {
                    self.output = super::to_u8arr(v);
                    return ReadResult::ReadDone;
                }
                _ => return ReadResult::ReadMore,
            }
            ReadResult::ReadMore
        }
    }

    // Implement parser for the XOF functions
    impl Dh {
        fn parse_element(self: &mut Self, k: &str, v: &str) -> ReadResult {
            match k {
                "COUNT" => self.count = super::to_usize(v),
                "QCAVSx" => self.other_key_x = super::to_u8arr(v),
                "QCAVSy" => self.other_key_y = super::to_u8arr(v),
                "QIUTx" => self.public_key_x = super::to_u8arr(v),
                "QIUTy" => self.public_key_y = super::to_u8arr(v),
                "dIUT" => self.secret_key = super::to_u8arr(v),
                "ZIUT" => {
                    self.shared_secret = super::to_u8arr(v);
                    return ReadResult::ReadDone;
                }
                _ => return ReadResult::ReadMore,
            }
            ReadResult::ReadMore
        }
    }

    // Implement parser for the XOF functions
    impl Hmac {
        fn parse_element(self: &mut Self, k: &str, v: &str) -> ReadResult {
            match k {
                "Klen" => self.klen = super::to_usize(v),
                "Tlen" => self.tlen = super::to_usize(v),
                "Count" => self.count = super::to_usize(v),
                "Key" => self.secret_key = super::to_u8arr(v),
                "Msg" => self.msg = super::to_u8arr(v),
                "Mac" => {
                    self.mac = super::to_u8arr(v);
                    if self.klen != self.secret_key.len() || self.tlen != self.mac.len() {
                        // At this point key,tlen,klen and mac must be parsed
                        // and delcared sizes must correspond to sizes of arrays
                        return ReadResult::ReadError;
                    }
                    return ReadResult::ReadDone;
                }
                _ => return ReadResult::ReadMore,
            }
            ReadResult::ReadMore
        }
    }

    // Implement parser for the XOF functions
    impl Kdf {
        fn parse_element(self: &mut Self, k: &str, v: &str) -> ReadResult {
            match k {
                "COUNT" => self.count = super::to_usize(v),
                "Salt" => self.salt = super::to_u8arr(v),
                "K_0" => self.k0 = super::to_u8arr(v),
                "IV" => self.iv = super::to_u8arr(v),
                "FixedInputData" => self.info = super::to_u8arr(v),
                "KI" => self.prk = super::to_u8arr(v),
                "KO" => {
                    self.derived_key = super::to_u8arr(v);
                    return ReadResult::ReadDone;
                }
                _ => return ReadResult::ReadMore,
            }
            ReadResult::ReadMore
        }
    }

    // Implement parser for the XOF functions
    impl Drbg {
        fn parse_element(self: &mut Self, k: &str, v: &str) -> ReadResult {
            match k {
                "COUNT" => self.count = super::to_usize(v),
                "EntropyInput" => self.entropy_input = super::to_u8arr(v),
                "Nonce" => self.nonce = super::to_u8arr(v),
                "PersonalizationString" => self.personalization = super::to_u8arr(v),
                "EntropyInputReseed" => self.entropy_input_reseed = super::to_u8arr(v),
                "AdditionalInput" => self.additional_input.push_back(super::to_u8arr(v)),
                "AdditionalInputReseed" => self.additional_input_reseed = super::to_u8arr(v),
                "ReturnedBits" => {
                    self.returned_bits = super::to_u8arr(v);
                    return ReadResult::ReadDone;
                }
                "EntropyInputPR" => {
                    // "Prediction Resistance" is not supported
                    return ReadResult::ReadError;
                }
                _ => return ReadResult::ReadMore,
            }
            ReadResult::ReadMore
        }
    }

    // Type used by iterator.
    #[derive(Debug, Default)]
    pub struct TestVector {
        pub scheme_id: u32,
        pub sections: HashSet<String>,
        pub sig: Signature,
        pub ecdsa_sig: EcdsaSignature,
        pub ecpkv: EcdsaPublicKeyValidation,
        pub kem: Kem,
        pub hash: Hash,
        pub xof: Xof,
        pub dh: Dh,
        pub hmac: Hmac,
        pub kdf: Kdf,
        pub drbg: Drbg,
    }

    impl TestVector {
        fn new(id: u32) -> Self {
            let mut el: TestVector = Default::default();
            el.scheme_id = id;
            el
        }
        fn parse_element(self: &mut Self, t: AlgType, k: &str, v: &str) -> ReadResult {
            return match t {
                AlgType::AlgKem => self.kem.parse_element(k, v),
                AlgType::AlgSignature => self.sig.parse_element(k, v),
                AlgType::AlgEcdsaSignature => self.ecdsa_sig.parse_element(k, v),
                AlgType::AlgEcKey => self.ecpkv.parse_element(k, v),
                AlgType::AlgHash => self.hash.parse_element(k, v),
                AlgType::AlgXof => self.xof.parse_element(k, v),
                AlgType::AlgDh => self.dh.parse_element(k, v),
                AlgType::AlgHmac => self.hmac.parse_element(k, v),
                AlgType::AlgKdf => self.kdf.parse_element(k, v),
                AlgType::AlgDrbg => self.drbg.parse_element(k, v),
            };
        }

        pub fn set_sections(&mut self, s: &HashSet<String>) {
            self.sections = s.clone();
        }

        fn check_sections(&self, s: &Vec<&str>, res: Ordering, exp: Ordering) -> bool {
            if res == exp {
                for i in s.iter() {
                    if !self.sections.contains(&i.to_string()) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }

        pub fn has_same_sections(&self, s: &Vec<&str>) -> bool {
            let res = s.len().cmp(&self.sections.len());
            return self.check_sections(s, res, Ordering::Equal);
        }

        pub fn contains_sections(&self, s: &Vec<&str>) -> bool {
            let res = s.len().cmp(&self.sections.len());
            return self.check_sections(s, res, Ordering::Less)
                || self.check_sections(s, res, Ordering::Equal);
        }
    }

    impl<R: std::io::Read> KatReader<R> {
        pub fn new(reader: BufReader<R>, alg_type: AlgType, scheme_id: u32) -> KatReader<R> {
            KatReader {
                reader,
                alg_type,
                scheme_id,
                current_sections: HashSet::new(),
                is_section_parsing_finished: false,
                elements_processed: 0,
            }
        }

        fn read_kat(&mut self) -> Result<TestVector, ReadResult> {
            let mut vectors: TestVector = TestVector::new(self.scheme_id);

            // Read one record
            loop {
                let mut line = String::new();
                match self.reader.read_line(&mut line) {
                    Ok(0) => return Err(ReadResult::ReadDone),
                    Err(_) => return Err(ReadResult::ReadError),
                    _ => {}
                }

                if line.trim().len() == 0 {
                    continue;
                }
                if line.starts_with("#") {
                    continue;
                }

                // Parse section
                line = line.trim().to_string();
                if line.starts_with("[") && line.ends_with("]") {
                    if self.is_section_parsing_finished {
                        // Remove old parsed sections
                        self.current_sections.clear();
                        self.is_section_parsing_finished = false;
                    }
                    let mut l = line.to_string();
                    l = l.strip_suffix("]").unwrap().to_string();
                    l = l.strip_prefix("[").unwrap().to_string();
                    self.current_sections.insert(l);
                    continue;
                }
                self.is_section_parsing_finished = true;

                // If section parsing has finished, make them available to runner
                // and clear from current_sections
                if self.is_section_parsing_finished {
                    vectors.set_sections(&self.current_sections);
                }

                let v: Vec<&str> = line.split("=").collect();
                if v.len() != 2 {
                    println!("{}", line);
                    return Err(ReadResult::ReadError);
                }

                self.increment_element_processed();
                match vectors.parse_element(self.alg_type, v[0].trim(), v[1].trim()) {
                    ReadResult::ReadError => return Err(ReadResult::ReadError),
                    ReadResult::ReadDone => break,
                    _ => {
                        continue;
                    }
                }
            }
            return Ok(vectors);
        }

        pub fn increment_element_processed(&mut self) {
            self.elements_processed += 1;
        }

        pub fn elements_processed(&self) -> usize {
            self.elements_processed
        }
    }

    // Iterator iterates over KAT tests in a file
    impl<R: std::io::Read> Iterator for KatReader<R> {
        type Item = TestVector;
        fn next(&mut self) -> Option<Self::Item> {
            match self.read_kat() {
                Ok(v) => return Some(v),
                Err(e) => match e {
                    ReadResult::ReadDone => return None,
                    ReadResult::ReadError | ReadResult::ReadMore => {
                        panic!("Error occured while reading {}", e as u64)
                    }
                },
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::reader::*;
    use std::io::Cursor;

    #[test]
    fn test_hash_parsing() {
        let ex = "
#  CAVS 19.0
[XXX]
Len = 0
Msg = 00
MD = 6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";

        let r = KatReader::new(
            std::io::BufReader::new(Cursor::new(ex)),
            AlgType::AlgHash,
            1,
        );

        let mut count = 0;
        for el in r {
            assert_eq!(el.hash.md.len(), 28);
            assert_eq!(el.hash.len, 0);
            assert_eq!(el.hash.msg, [0x00]);
            assert_eq!(el.hash.md[0..5], [0x6B, 0x4E, 0x03, 0x42, 0x36]);
            count += 1;
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn test_xof_variable_len_parsing() {
        let ex = "
#  CAVS 19.0
#  SHAKE256 VariableOut information for SHAKE3AllBitsGT
#  Length values represented in bits
#  Generated on Thu Jan 28 14:45:13 2016

[Tested for Output of bit-oriented messages]
[Input Length = 256]
[Minimum Output Length (bits) = 20]
[Maximum Output Length (bits) = 1297]
COUNT = 72
Outputlen = 3
Msg = 37433497799ffbf297f8156d0c2ff67c08fe7a5b68237952e6c19c388d036f36
Output = ea930a

COUNT = 1
";

        let r = KatReader::new(std::io::BufReader::new(Cursor::new(ex)), AlgType::AlgXof, 1);

        let mut count = 0;
        for el in r {
            assert_eq!(el.xof.count, 72);
            assert_eq!(el.xof.outputlen, 3);
            assert_eq!(el.xof.msg[0..5], [0x37, 0x43, 0x34, 0x97, 0x79]);
            assert_eq!(el.xof.output.len(), el.xof.outputlen);
            assert_eq!(el.xof.output, [0xEA, 0x93, 0x0A]);
            count += 1;
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn test_xof_fixed_len_parsing() {
        let ex = "
#  CAVS 19.0
#  SHAKE128 LongMsg information for SHAKE3AllBytesGT
#  SHAKE128 tests are configured for BYTE oriented implementations
#  Length values represented in bits
#  Generated on Thu Jan 28 14:46:45 2016

[Outputlen = 128]

Len = 2696
Msg = a6fe00064257aa318b621c5eb311d32bb8004c2fa1a969d205d71762cc5d2e633907992629d1b69d9557ff6d5e8deb454ab00f6e497c89a4fea09e257a6fa2074bd818ceb5981b3e3faefd6e720f2d1edd9c5e4a5c51e5009abf636ed5bca53fe159c8287014a1bd904f5c8a7501625f79ac81eb618f478ce21cae6664acffb30572f059e1ad0fc2912264e8f1ca52af26c8bf78e09d75f3dd9fc734afa8770abe0bd78c90cc2ff448105fb16dd2c5b7edd8611a62e537db9331f5023e16d6ec150cc6e706d7c7fcbfff930c7281831fd5c4aff86ece57ed0db882f59a5fe403105d0592ca38a081fed84922873f538ee774f13b8cc09bd0521db4374aec69f4bae6dcb66455822c0b84c91a3474ffac2ad06f0a4423cd2c6a49d4f0d6242d6a1890937b5d9835a5f0ea5b1d01884d22a6c1718e1f60b3ab5e232947c76ef70b344171083c688093b5f1475377e3069863
Output = 3109d9472ca436e805c6b3db2251a9bc

";

        let r = KatReader::new(std::io::BufReader::new(Cursor::new(ex)), AlgType::AlgXof, 1);

        let mut count = 0;
        for el in r {
            count += 1;
            assert_eq!(el.xof.msg[0..5], [0xA6, 0xFE, 0x00, 0x06, 0x42]);
            assert_eq!(el.xof.output.len(), 128 / 8);
            assert_eq!(el.xof.output[0..3], [0x31, 0x09, 0xD9]);
            assert_eq!(el.xof.len, 2696);
            assert_eq!(count, 1);
        }
    }

    #[test]
    fn test_select_block() {
        let ex = "
#  CAVS 19.0
[Outputlen = 64]

Len = 2696
Msg = deadbeef
Output = 3109d9472ca436e8

# This block must be selected
[Outputlen = 128]

COUNT = 1
Len = 2696
Msg = a6fe00064257aa318b621c5eb311d32bb8004c2fa1a969d205d71762cc5d2e633907992629d1b69d9557ff6d5e8deb454ab00f6e497c89a4fea09e257a6fa2074bd818ceb5981b3e3faefd6e720f2d1edd9c5e4a5c51e5009abf636ed5bca53fe159c8287014a1bd904f5c8a7501625f79ac81eb618f478ce21cae6664acffb30572f059e1ad0fc2912264e8f1ca52af26c8bf78e09d75f3dd9fc734afa8770abe0bd78c90cc2ff448105fb16dd2c5b7edd8611a62e537db9331f5023e16d6ec150cc6e706d7c7fcbfff930c7281831fd5c4aff86ece57ed0db882f59a5fe403105d0592ca38a081fed84922873f538ee774f13b8cc09bd0521db4374aec69f4bae6dcb66455822c0b84c91a3474ffac2ad06f0a4423cd2c6a49d4f0d6242d6a1890937b5d9835a5f0ea5b1d01884d22a6c1718e1f60b3ab5e232947c76ef70b344171083c688093b5f1475377e3069863
Output = 3109d9472ca436e805c6b3db2251a9bc

COUNT = 2
Len = 2696
Msg = a6fe00064257aa318b621c5eb311d32bb8004c2fa1a969d205d71762cc5d2e633907992629d1b69d9557ff6d5e8deb454ab00f6e497c89a4fea09e257a6fa2074bd818ceb5981b3e3faefd6e720f2d1edd9c5e4a5c51e5009abf636ed5bca53fe159c8287014a1bd904f5c8a7501625f79ac81eb618f478ce21cae6664acffb30572f059e1ad0fc2912264e8f1ca52af26c8bf78e09d75f3dd9fc734afa8770abe0bd78c90cc2ff448105fb16dd2c5b7edd8611a62e537db9331f5023e16d6ec150cc6e706d7c7fcbfff930c7281831fd5c4aff86ece57ed0db882f59a5fe403105d0592ca38a081fed84922873f538ee774f13b8cc09bd0521db4374aec69f4bae6dcb66455822c0b84c91a3474ffac2ad06f0a4423cd2c6a49d4f0d6242d6a1890937b5d9835a5f0ea5b1d01884d22a6c1718e1f60b3ab5e232947c76ef70b344171083c688093b5f1475377e3069863
Output = aabbccdd2ca436e805c6b3db2251a9bc

";

        let r = KatReader::new(std::io::BufReader::new(Cursor::new(ex)), AlgType::AlgXof, 1);

        let mut found2 = false;
        let mut found3 = false;
        let mut count = 0;
        for el in r {
            count += 1;
            if el.has_same_sections(&vec![&"Outputlen = 128"]) {
                match count {
                    2 => {
                        assert_eq!(el.xof.output[0..3], [0x31, 0x09, 0xD9]);
                        found2 = true;
                    }
                    3 => {
                        assert_eq!(el.xof.output[0..3], [0xaa, 0xbb, 0xcc]);
                        found3 = true;
                    }
                    _ => assert!(false),
                }
            }
        }
        assert!(found2);
        assert!(found3);
    }

    #[test]
    fn test_select_from_multisections_check_equal_sections() {
        let ex = "
#  CAVS 19.0
# This block must be selected
[Outputlen = 128]

Len = 2696
Msg = a6fe00064257aa318b621c5eb311d32bb8004c2fa1a969d205d71762cc5d2e633907992629d1b69d9557ff6d5e8deb454ab00f6e497c89a4fea09e257a6fa2074bd818ceb5981b3e3faefd6e720f2d1edd9c5e4a5c51e5009abf636ed5bca53fe159c8287014a1bd904f5c8a7501625f79ac81eb618f478ce21cae6664acffb30572f059e1ad0fc2912264e8f1ca52af26c8bf78e09d75f3dd9fc734afa8770abe0bd78c90cc2ff448105fb16dd2c5b7edd8611a62e537db9331f5023e16d6ec150cc6e706d7c7fcbfff930c7281831fd5c4aff86ece57ed0db882f59a5fe403105d0592ca38a081fed84922873f538ee774f13b8cc09bd0521db4374aec69f4bae6dcb66455822c0b84c91a3474ffac2ad06f0a4423cd2c6a49d4f0d6242d6a1890937b5d9835a5f0ea5b1d01884d22a6c1718e1f60b3ab5e232947c76ef70b344171083c688093b5f1475377e3069863
Output = 3109d9472ca436e805c6b3db2251a9bc
[Outputlen = 64]
[TEST = 1]

Len = 2696
Msg = deadbeef
Output = 3109d9472ca436e8
";
        let mut found = false;
        let r = KatReader::new(std::io::BufReader::new(Cursor::new(ex)), AlgType::AlgXof, 1);

        let mut count = 0;
        for el in r {
            count += 1;
            if el.has_same_sections(&vec![&"Outputlen = 64", &"TEST = 1"]) {
                assert_eq!(el.xof.output[0..3], [0x31, 0x09, 0xD9]);
                assert_eq!(count, 2);
                found = true;
            }
        }
        assert!(found);
    }

    #[test]
    fn test_select_from_multisections_check_contains_sections() {
        let ex = "
#  CAVS 19.0
# This block must be selected
[Outputlen = 128]

Len = 2696
Msg = a6fe00064257aa318b621c5eb311d32bb8004c2fa1a969d205d71762cc5d2e633907992629d1b69d9557ff6d5e8deb454ab00f6e497c89a4fea09e257a6fa2074bd818ceb5981b3e3faefd6e720f2d1edd9c5e4a5c51e5009abf636ed5bca53fe159c8287014a1bd904f5c8a7501625f79ac81eb618f478ce21cae6664acffb30572f059e1ad0fc2912264e8f1ca52af26c8bf78e09d75f3dd9fc734afa8770abe0bd78c90cc2ff448105fb16dd2c5b7edd8611a62e537db9331f5023e16d6ec150cc6e706d7c7fcbfff930c7281831fd5c4aff86ece57ed0db882f59a5fe403105d0592ca38a081fed84922873f538ee774f13b8cc09bd0521db4374aec69f4bae6dcb66455822c0b84c91a3474ffac2ad06f0a4423cd2c6a49d4f0d6242d6a1890937b5d9835a5f0ea5b1d01884d22a6c1718e1f60b3ab5e232947c76ef70b344171083c688093b5f1475377e3069863
Output = 3109d9472ca436e805c6b3db2251a9bc
[Outputlen = 64]
[TEST = 1]

Len = 2696
Msg = deadbeef
Output = 3109d9472ca436e8
";
        let mut found = false;
        let r = KatReader::new(std::io::BufReader::new(Cursor::new(ex)), AlgType::AlgXof, 1);

        let mut count = 0;
        for el in r {
            count += 1;
            if el.contains_sections(&vec![&"Outputlen = 64"]) {
                assert_eq!(el.xof.output[0..3], [0x31, 0x09, 0xD9]);
                assert_eq!(count, 2);
                found = true;
            }
        }
        assert!(found);
    }

    #[test]
    fn test_dh_parsing() {
        let ex = "
COUNT = 21
QCAVSx = 700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287
QCAVSy = db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac
dIUT = 7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534
QIUTx = ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230
QIUTy = 28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141
ZIUT = 46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b
";

        let r = KatReader::new(std::io::BufReader::new(Cursor::new(ex)), AlgType::AlgDh, 1);

        for el in r {
            assert_eq!(el.dh.public_key_x[0..3], [0xEA, 0xD2, 0x18]);
            assert_eq!(el.dh.public_key_y[0..3], [0x28, 0xAF, 0x61]);
            assert_eq!(el.dh.other_key_x[0..3], [0x70, 0x0C, 0x48]);
            assert_eq!(el.dh.other_key_y[0..3], [0xDB, 0x71, 0xE5]);
            assert_eq!(el.dh.secret_key[0..3], [0x7D, 0x7D, 0xC5]);
            assert_eq!(el.dh.shared_secret[0..3], [0x46, 0xFC, 0x62]);
            assert_eq!(el.dh.count, 21);
        }
    }
    #[test]
    fn test_drbg() {
        let ex = "
COUNT = 10
EntropyInput = bfb68be4ce1756d25bdfad5e0c2f8bec29360901cc4da51d423d1591cc57e1ba
Nonce = 98afe4bd194c143e099680c504cceaab
PersonalizationString =
EntropyInputReseed = b97caf210e82498c3408790d41c320dd4a72007778389b44b7bc3c1c4b8c53f8
AdditionalInputReseed =
AdditionalInput = aabb
AdditionalInput = ccdd
ReturnedBits = 409e0aa949fb3b38231bf8732e7959e943a338ea399026b744df15cbfeff8d71b3da023dcce059a88cf0d4b7475f628e4764c8bef13c70cfbbbb6da2a18aabcad919db09d04fc59765edb165147c88dd473a0f3c5ee19237ca955697e001ba654c5ee0bd26761b49333154426bc63286298a8be634fe0d72cfdeef0f3fc48eca
";

        let r = KatReader::new(
            std::io::BufReader::new(Cursor::new(ex)),
            AlgType::AlgDrbg,
            1,
        );

        for mut el in r {
            assert_eq!(el.drbg.count, 10);
            assert_eq!(el.drbg.entropy_input[0..3], [0xbf, 0xb6, 0x8b]);
            assert_eq!(el.drbg.nonce[0..3], [0x98, 0xaf, 0xe4]);
            assert_eq!(el.drbg.personalization.len(), 0);
            assert_eq!(el.drbg.entropy_input_reseed[0..3], [0xb9, 0x7c, 0xaf]);
            assert_eq!(
                el.drbg.additional_input.pop_front().unwrap()[0..2],
                [0xaa, 0xbb]
            );
            assert_eq!(
                el.drbg.additional_input.pop_front().unwrap()[0..2],
                [0xcc, 0xdd]
            );
            assert_eq!(el.drbg.returned_bits[0..3], [0x40, 0x9e, 0x0a]);
        }
    }

    #[test]
    fn test_pkv() {
        let ex = "
Qx = d17c446237d9df87266ba3a91ff27f45abfdcb77bfd83536e92903efb861a9a9
Qy = 1eabb6a349ce2cd447d777b6739c5fc066add2002d2029052c408d0701066231c
Result = F (1 - Q_x or Q_y out of range)
";
        let r = KatReader::new(
            std::io::BufReader::new(Cursor::new(ex)),
            AlgType::AlgEcKey,
            1,
        );

        for el in r {
            assert_eq!(el.ecpkv.pk[0..3], [0xd1, 0x7c, 0x44]);
            assert_eq!(el.ecpkv.result, 'F');
        }
    }
    #[test]
    fn test_kem() {
        let ex = "
count = 998
z = fd2d178aabc94b7d7c906945cf6a3a9a29ed62c4cde56131ba9c13e746ee7abf
d = 87f0e1345fcdcd3e1502b764be76c7b08adf1bb99af73ae61fd8e042588ba57e
msg = 4d6183ec5474199b457cae56db947bec864268059013fe0268bdb45b043b57d3
seed = 7b27830862c4e2fb113c3482af656c612ff798b62269846938eeb7f8b86a8f7bd0e1f123c996f105be6ad3b7f32346e3
pk = 00b6a3b3e374781b31a199c0fcb85f33f2b91e871d35308f02979d8c89a9e6f593ea38caccb3a8ea9437781b86ae828bc18a5bcc987736338120f5b1a3d865885b18bbb8bced66b18395afa6581d950a5060ecb92d2284ae4bac2cc54028b7c2a4e1aa2b2aa74ddbcb44188ec8433de7c58e11c90fbf3962437a637af9a3a3931837484614467e98ca5943a3321af53273b25bbed016c45b3d838c191f3b2b2e473205a93067100e1bfcbb545b4766c60a431aa9b0c842b0f974d2dbb2ae780967b06ecd2c887bac41d4273bcb4736bcc9011e734713f5350c58b31036ae75db1f4afa1385a28281e6be6b141c55b25e849662e325c235aa01a3741be1ea0c1fc9486a63bfbee8118f47a1af9b5df4561fcaacbd5ca27815168787813a01c41e32484051ba95e639c98b88c75cc46f7be33dbf94655c508114fb4c3af926bc692caa723fd4b1cd3a6b3c55054d725144007113c0d00b11e6b72f4c1775ec7f9919a1b5ecad23bb21aee9b920f0447168583fc61674b509f0097162341c81b8c7c24b850c747c465851c7b15a78db3bc1f72ef4d75d5c0c703d19372a0570b714c6ec69b15eb78708b93fe97c0f4c869e4ecc97d64b08ada2886a169d54b23473194a6f1184bfaa1af3c25c9f63b49215c6db386853cc2b90a24d2271306318848c760dcc8817c0182c67f674375038d484b31b111a02262da644cf7f3baccb937a69f2c647938358122197114a60f457eda2ba9030527143658091a55538211a846b40e07440e3c26ebb5386ac77d6d4454b14174b4848b23437751b9f934712642a641df54332fa41e1612988d68ec2a67b9a65c25501ae6d6566a5052eb107378cb27575fb3d5af9acb39aa30c0940b4b117d4b26025e2341250420d5b9f87fb4196e7426ceba912065ec4656b9f9b6aa2566a5dea1bf22257e27a6eb9db1ad61abda152a9eee2565ed9836704a7f2223b40fc6b8fe0456b6b51ac66557aea8fd562a9fe0a4416911d482681b19847570836562a3e4f88a9db1c10badbbe39e366be60197cf6531cf3901e58c8244cafb0527614c96a95b852e7624ca56755389982b222172e5e82a2dece3f0b3ee9e0d81c7697655dee2dc5187d95e0dcfe
sk = f11baf3d27562aa46a36735ca250cdbffc93db0ab95ed73bbf3b2fcc98aa28e9bf71b72159b16b01107ed5f84e9717cb8feb85a6e15e65d9816df71cb5a8c1db3345ba994312e6be3fb47e34860ea50178cd6469403b7bc636422c69a676aa9033e0639817628ea10ec721be8c8061b5cace787564745766136663e26b82c38104a0b2a5f77c75b2562852eb3504f5c11f91403e7938a97b23566073d820cb02d19a4d8b6418aa718789a9be228bd522ce32fa6b6a9c08a6f420c1d7cda4fa9b25db64e52a0a610319e463c7f52c2f82a131ce200e4789aee4378331d567fbe46289638f59f8c437e63477762f63063e79b0979c8c201cab49c86242fa8cada42c2e4037a2a6925b14c412622190c6bc6c8438209d5280b37b8afd1754b8b19f8c0613bd24bb9e0771d782b031a436186036e22638d25a2506f44ad7d76d2b54611e89219910695e150a31bc1900ddbc19843f840b0b3b817a8944b6fb7c2455da4ad354a33e911e7d8c8fc247b84c7395ac0759886205269a03e149048feb2dc592a9277cc6840628530878c768c343f5c2d6f96f76c203b33557f748b9169b5f20d2692979238450a2b287775ac69335e02c123223fea6c8e761413967356cd8a62492a97e383ab6b215e5f91ff5da21fe4c5d7b030e27e69f45842275a4b12c4452f7d53900569b19118eb3cc031cf23f3214544147bf2007bdcc8a5f0bb3a2ade7c18b2054478071b90590f1b425967588202a0131f64afe8aa78a082f98b51c3761c6fdfc5bbdf11ebe7abe155b36c4ea477cd281fac4b0df356b8e6a0c6c47b717f7c6feb4250c9039d1290e83eace5b7a92296c1cff43344a91098aa5ce85d2c6c7330fb082ce38a4c6503424ab461279c3414c3b2d6ba2b6ad4b89d471556bbb54c312a9300876e53c655c15ca51d2963e353d10b7508fa7c9c3364f465420bda18b4c8c2464f3c07c4c6b8e612c423b6577bc1c95917462f655e11b6802ba99fa44c125f4b642e04061099df3eab8aa4a1a56d4b69e9c178d7c4899eb3baa891b630378cf4bbdbc89c8f3805a434314d326aeb4066515409d46c87600b6a3b3e374781b31a199c0fcb85f33f2b91e871d35308f02979d8c89a9e6f593ea38caccb3a8ea9437781b86ae828bc18a5bcc987736338120f5b1a3d865885b18bbb8bced66b18395afa6581d950a5060ecb92d2284ae4bac2cc54028b7c2a4e1aa2b2aa74ddbcb44188ec8433de7c58e11c90fbf3962437a637af9a3a3931837484614467e98ca5943a3321af53273b25bbed016c45b3d838c191f3b2b2e473205a93067100e1bfcbb545b4766c60a431aa9b0c842b0f974d2dbb2ae780967b06ecd2c887bac41d4273bcb4736bcc9011e734713f5350c58b31036ae75db1f4afa1385a28281e6be6b141c55b25e849662e325c235aa01a3741be1ea0c1fc9486a63bfbee8118f47a1af9b5df4561fcaacbd5ca27815168787813a01c41e32484051ba95e639c98b88c75cc46f7be33dbf94655c508114fb4c3af926bc692caa723fd4b1cd3a6b3c55054d725144007113c0d00b11e6b72f4c1775ec7f9919a1b5ecad23bb21aee9b920f0447168583fc61674b509f0097162341c81b8c7c24b850c747c465851c7b15a78db3bc1f72ef4d75d5c0c703d19372a0570b714c6ec69b15eb78708b93fe97c0f4c869e4ecc97d64b08ada2886a169d54b23473194a6f1184bfaa1af3c25c9f63b49215c6db386853cc2b90a24d2271306318848c760dcc8817c0182c67f674375038d484b31b111a02262da644cf7f3baccb937a69f2c647938358122197114a60f457eda2ba9030527143658091a55538211a846b40e07440e3c26ebb5386ac77d6d4454b14174b4848b23437751b9f934712642a641df54332fa41e1612988d68ec2a67b9a65c25501ae6d6566a5052eb107378cb27575fb3d5af9acb39aa30c0940b4b117d4b26025e2341250420d5b9f87fb4196e7426ceba912065ec4656b9f9b6aa2566a5dea1bf22257e27a6eb9db1ad61abda152a9eee2565ed9836704a7f2223b40fc6b8fe0456b6b51ac66557aea8fd562a9fe0a4416911d482681b19847570836562a3e4f88a9db1c10badbbe39e366be60197cf6531cf3901e58c8244cafb0527614c96a95b852e7624ca56755389982b222172e5e82a2dece3f0b3ee9e0d81c7697655dee2dc5187d95e0dcfea0e8b4569a940d374b025ed461d8bd635adbb0e767a628dbf80b4b0159c0fa52fd2d178aabc94b7d7c906945cf6a3a9a29ed62c4cde56131ba9c13e746ee7abf
ct_n = da471af84f42ce2f6f6d5d916dfb00598d30026d839e7770cdaa45dea069254360709ef85083a7a7ecaf03d54daa728ba039f1ac76e109540981a228767e89a5649d491a32f04915710d132ee1f92b2674b7ddb75df8f295b57475b8340ca6df32ed70cf3f3b4f4ef9d984adfd581d7f45e06db444dd9e55c03a24fb591dd7cdc658cd6e812e8b8217e18cc916ecfee9dae50552a304b7800a2f5730cf80581fe36705db39c4953f0624c075edabf27c20fdca29fc49608288bb8647945fa0164005acd61890200ef413637a2eb3579e6895ea49031260fc8d89ba4d04f63c2304b3d08f85a6d7aa9bd6c9cb8e073a97a0ca947c9edfba141d5d487f3149d3fa1d690f0fa98d225f136ae4e780a3757a1d3b7161b0fa0a14fe08ec1484d033c2808fa959ffe582473684b225f94124f2348a52abb2996b0a500a78d5e8e630be0779c827245a29c9785e4f88440225e78a02545dd1da417d1a74dae347e670265d0b87947d70491502634db9fac4d658ac0a51fef1ca3eba3e2682cd201958d5830a19ffce37caf135d3390ea82fdffffbaa4b7ce99a496aad22649c972e929f2b8502af082e491b22367c5e92bd992add5a130e7138754e6ff4947097dbc8b80c372165faf4e3fa26e7a56ef9e4e3b78cc7f392ef62169445ac8008c781bd69df75eb300e1c26a1e3a084676e33017d6b00de2d10ebd5814f3cda4060b8b598cf9e39d92c0c7db021885274ab2512730552412d7bdb542d7ef47ef43d72ddfa6dca5703be0f93fcd9f6855e3db0be2bfb8ce8049422952b0fa5ecabb2bddd93bdae1e347fbf32084c7a3244ba5eb7f264328e8be69fa3c49a86031d9616f18627c179d1f5d3b1ed60897ae578aad6308a2fcd6cf56ac6f22d744ef9ee63056f5b88a10292b69e3c84f911aaf426f788d616432abaec92c8ace7cb66931f4bd96424583a399ea083f4735b0c1b1edf125c2fc563d47d7869018a8d037a8a9f7e07c02713f9cfa14976c4c1b43571a574eee84563b8c3c8004aad8f94964b29dfe4d2970ce4fb2207d3a70077e7ea0be4103c7ae57e7bd04005fa5d79da563fd5
ss_n = e711761e734750c8117f2449cfd10120323e827772d4ee0b8c05a19e9ca3e062
ct = 2fb4cb1412186f3115feab6efbaea4dd75180b40bd970c28934d625059b721f831ee3923ea06a8fede23171bd2fd03bb0b574301a87f9eb9a6b710d84181e8fba75b98ebb0b37eb6b51a6abc6380a16337bdcb43034290396b37b087bc365735293f3198ecc2029357fd1dad35104dc1bdd6d686c6c4547b4310c8e1f256935a50ca8f82921482e2b0adf8b6bced7bb69033f498579bf7a6f8f3ca0bfc46119dcecc4753d0312c9613d2dcb9f9d22dc8e65b86c36ae3e5788f5c9d95064627a4ddd83790b1f57c29405c86027b96c0ca9c8b99609797525c2938d1e392b8eb306c686280c86944e5d4fe64ac1d1fed9e30e723c0382cff55a5e9923484da2e1d28598afd94bd345fe607b99b04b4367f7734c16977236b9480b73ac18954e29b0c8083968cdc0748b755efedd905167a8661fccd186ef4b32f01eaf7ecccc111f9232b756306d94f86ff521d3b0b551fc34058b7cb60a9b50d645e8c5c1a5c7cc42ae5e54727d9fb79f0c23b656bf24730242f035b3ebea6bacbd42082b8da3ba79cd84d54e9bfb160abf89e08a898c05ade3ab0cb1e9ebcf074010e148734a2504db7ecc90e1c89d7e983b8977027c608aa5db43fa2683553484a58a368471b180ce37c6e17a1b237f0b3da7116ebb56b6c425c15d11b799bb5fcda82bfc66a59b860e4da2da614683d3a6c393621170ca21102909498129cd063d25094980d9f6c5f863c87e0a03a22e9516730422a0ce250a28cffbc96e9c9f7781e805969b7c49ae76475a5774594a807581b4a28c8ca70280f91791731b1fddf96d5c055059999e0583e1e8c76b8cc8ecc1c9bb3e9ee099efee6800f2ec328779400d315f05b8a7c54416c550b3aa7e59ae7a4e1052c533f056427d44078790a167e7c74a6d15eb8fdcbf8befeea41124c3d1cb8470c614a9362481316e5249968796d49f7107328f8485d5d40bc06b170a9bedd112fafd1a3934bebffccbf313fbb7051bc77ffa7ca22408fb1f93f47b6d6b6c8eb289416c74f8aa2ea3ee61dc9558b4ece255974cbbd4256a03a18a21696c06f823d72bf540e6db192badaae9a9aab74
ss = a7ced0c75f20de0103f90a8da884bf4dd9719e185c54ffb6215b4a28a5fc76f6
";
        let r = KatReader::new(std::io::BufReader::new(Cursor::new(ex)), AlgType::AlgKem, 1);

        for el in r {
            assert_eq!(el.kem.count, 998);
            assert_eq!(el.kem.pk[0..3], [0x00, 0xb6, 0xa3]);
            assert_eq!(el.kem.sk[0..3], [0xf1, 0x1b, 0xaf]);
            assert_eq!(el.kem.ct[0..3], [0x2f, 0xb4, 0xcb]);
            assert_eq!(el.kem.ss[0..3], [0xa7, 0xce, 0xd0]);
            assert_eq!(el.kem.ct_n[0..3], [0xda, 0x47, 0x1a]);
            assert_eq!(el.kem.ss_n[0..3], [0xe7, 0x11, 0x76]);
        }
    }
    #[test]
    fn test_signature() {
        let ex = "
count = 99
result = F
seed = CB2E6226615393FC3BD4AB3A412AAA030AAD40E8648EE6B56D2C1591D8B97915D88F2D22F7221377B4B04CF2AE9ECC4E
mlen = 3300
msg = D21A6BB3A2356805E678673C45FB055FC5266E3F692AF9935AEA307F14A5C41B979966A5DFE42EBFED1487E4822B74AB5AF28995E085EC8007ECA4977C63EE5299FEC63DCCBC42EEACAB488E574249E9D856146750AD97C8A443485EC1C5820BEB0964640010F6407140791E74684DBB91052E2D8BEF7BDCD78B2EC03C97A53295D683BDBE32A70DC19A2F75B8613AEA9616AE0E280179492820F73FB7FA4121E673FB5C328F41B67FF8FFA7AEE6564ADABA046D6E1D6AA13FB24965390F829246DFA8763851405075F76CF94C66FFC3308214DF0960C649AAEDC22926CE9357D3875F8B71D68D75999AA3663C30A9EDF07228BF7DFF49EC1E6C7A33D2053597003B82392E826EBD701B4C981AAAC9951C79E08F592C2C0637C8E5A7F9DCDA599E859C317D4888B4098992E0E2D979E41C703686D577E5BA6001EC4F587140711293D664963632F87EA0461E0E0C5E9D8D292FB409F9F9AB172EE17FC8AFABAD06E42B437CE22924EB5DBD3A80A06962F3B37946259F9C75A233CB2B4ABDC5CD1B648FAEB1BE8630DB40D151B8FBA693DF2C5BDCAA14DC4783F450B6BC407515CEEBC5C9A47BD1A141384F0B596CAB1135C075651CBA989C190F3171DC1D72330EDAA01656813C4B7811715060B023FC426745C301B2A91E0D08ED3BDED438C4CE6799C35F3981C882A0BDE4A2FEEB1A52CAFA47B0C48558FC43F98FE08F03A71128362BB6FB9DA6A22249F4D4352AE7D3DAE85DE497E2411EADCFE5BF1A3C075C45811E0097ECEA255FE15BD8321FE8B546A8CACFB899EECF5419DB363C7567C2FE7360B36DE14674F500A31D3EEC71451A7C0D5576A8939C0F6D4D9F2F03F3C516CE25CE73ABB35C73AA94F6AEFAE6AD87052D6B195FA43586817F5BB974AAE7F1B8608922411AA5B0D7D574016CBD3DED13395623470A108FA0E1D3F9FAA7E1E5031843F2A23DBCE8B196315290DEA5795E4115D53DC570A444064CFA3C9457DBF3EE323B1966ECD2270C32910F8F430522471258A1F1955A6E1DD8C84ED9A566499BF85628615351ABE84B401421DA2CFAF575E2644C9304C075ECFC374066CEC713FA4C0D89043689FBC59FF54B8F97EE0A3B0989BC5E4EF83CC9833E75BC8B67BB5EE3C06EA156611CDA95A6702416807530EA206ED89835D20805EA988B1958569CDF7F809996214DADAB4E20BD44917E3410EC6BEAC98FEA07F764E85B66AED5E17CF675D2ED8E63DB728FE75158CB31779E31379648B43D68CCFF3780854CF03535C57122019456E73CF06769BF1FBF558542241CE665BD10F921828553585E0CF664CDC6160F9C47FA5330591B74194F4716056CA83993EFEC4A52DB9A1FBD3B2F504AC19667325167407375B6D7DE739F07947B511C8D475744E5C29D6E286A37F1FF8317BD0178F0E306A38FA6E75F4A80427FEB2C91235D3E7F20D8101CFC03BB73F44EF59AF3526E9AFC580027A1DADE37654238B8EC7AF0105248FE30784A88B72E11FC1BD807E47A349BD29075BEFBB29730EF8E85E3ABD5105559BACEE74AA27D90D360A8D629DBEC95EB34C7F7CA20096FF7B521E40D3944A975436896F372EEAB6B8615EB91697965BBF955779DD3047F7E3BF029E3509A5780247445D6223D085AFB4291D976EFADC41E42DC2C0728D18F6155654A332FEC72EB6AEF8B92C1D177E3DC28C31971BCAFF76DDEBFD9588BC244B116D409E58DC5ADA1648663D603C47FAEB814AAA7EB9B6264356F926C18B9357BF426B89DDC8EB9177ECEB5C6CDC64DD8FEB7B326BC1BA89BD9035235DA0E644EF959C58DD97B88D5C749B36931AC2694C67151DB0894652E99254222D37CEFE9E27B3DD663A152DBE29A3639AFE42F4578937076180563AAD6AD739255EA012A17D2A56627D84C44FBAB261D392A966CFE19278799CF1634D42384323C496190D4B9FB662694E3887EA66AB9E8B195488C8DCA47C8BC0424247759137CFBF86DEDC3641904CB6FACBB30A9FA84ACF69A67B4AFDF4C2AA420FC0D90CEFA0DFBBCD3072D9F772FD6058E2BF0E251BE93B00DC43765B53DB51B22F12D3ED0CC5655E4AEBD9D923F99A43E4461DCF5992030E66A1CDC3A65558D9BB3A39788D92328387D144850DD3706FD7A079E3D2398F542F91A8AAABF0C5068DBAF1FCC5160398ABECF74884BEB04F3A3EA38BBB80D798F5981B3F2DB6C7B33F867B7DC06A4417E30F94CDB4F523AEEA0BE12BD75AAED57520DB0D4B4F013BE3A1DC7AE5C58FD1DE9637F7D82F697B7E92DA427A78FEEC6A5C0255EB57A43DEA6CEBC8805BC04E04FE789E222B1E2642D26EDC14FB36ECC6092B3060E45EED6C5B35DE8741F72933930ECBD7338CF39474122357365700CB50C5EB176FB92814FA7F4032570CCEE6B859236AD5DA5F1730129EDC7BE218BA9874620F6F0EBC45E0BD622F8FD1AE6974994AF95C6519EC1C46650C073D194FA6EBC62F405F63A3416782A47872C7D77D648D0A1C802FFDFDE5FDC112C94CFC68F401889EFC522FE488FDB5384C0D93147AB6587659D936F98ECFBCDCFBF8B352D605F18C855E2559743ED97991C5D50DF44A7B929303835654A3955ABC5BEE6327400A7CCCE460B318D8B5ECE5B12F606ADB3D7B5ED59563B8E675E78029AABC234442C2463256FE02B04F556DA35C4615D14A9F4EFF17DB0DB81DE4BDD894F6628A120BE2D4CF3E1F46D53817899657035A76137E23C0B0E8DDD29465D7F15628FD435E6CAACA4194FDBF85FDCC31D5DAFCB52568B7C0CFBE713BC85FA424BA3ABE149E4035FC86807A8B876D2163B447CAD5EC0E6EF38A1D591AFB46267F9DBF142CAB1CAC1F73BEBA212992FC6D4647EC17848D1ADBB1901277A5078DD72D9C9184E893C0806E9B4AFF0A824670D438620F2A7E8D2965B619D291E5824C014FC888A36FBBE17356431F0039038F9B497902AED969F9C488390B7087763638E976801127BAF1F53803C4DC9649F0EE85D67B239E2BDAFB2BD75F1D1DA22A56FB3AF10A9DDE7AD306C4AF8681029316C0E1949228E6BF5ADF942F1C0EF92B2BCBC0C70D49E5808851444240A78B14D21B54F66271482F49B85F5180B268050327368496CFA8B54ECB97EE6D28EB74A3742F68583DA046809002C22F7B31FBC0566969F9A15CDCA892C4BEB101A2AC3526C76E9D30982C9B4893450FDEC4001D2431828D24D8B1A67DF80E2E10ED2EA8D723227055C48006665F7DA8E032EFDC70BC7EEB2B369B551FAC542AD6DF1A23107E2B3C0E3CCACC25F26404C085CBF56E52D35D7948DB9FDA6DFC24709994719D8CED41A2CC9B3C4B2BEF0967CB71861CF0E6AEA9BEC9395726AA0E2F1A7247ED0F6038E3DF4BF566786073590DCF97F8F0A99658D8F630A2D130C46CF4D26C669360D0F70B75F904C9F923AB285D5DB129F6C25AD21F9E26AC844D07A8EED86C4E224EBFC5B3F720D6F94B0A01B1433C46B40CF84E80F7A6AFA7BB8F9ACF818AD3CAB2DDD6904C067BEA4F1FE79B83CB0AA8FC75B6B096BAD6FE94ABFD48F8EFC0F2B9A02EBDA8FDBDBE1C77F1854EDBA18AAE7F31CED9CD34C1B355108DF18A8953932F7554AF05B203A96A9BB93E0EFF51D7F93B56E351562CF85A2D35EAE2C2427B89A8662A1C723D4F14E6EAFDBD636C2BB7ADE29C1A6BC8A463734C808BEC68B1E9A31AF6E29B412F1CB8C90A9911AC5C3EA71E46113D2D7B1AE2D8802B06A770FD0E9E4652895E42181AD09BB541E9493F258711BB7BEDD3E7CA8B8CE875669CF80A6880ECA3F13800DE7011EA67F443E505C4FB455608AE586F922B3C83FD33B306BDEDB86223C33E3AA65EDC93CBCF3A03ADAF9F328997951D59A9200C0BA2618E3596AF176B43122CEDC52B1E006EA6D12DC236A6FCD7CC46825F2EF7ED71683A731D746FFF2FE54E0B392A8CBFA38873196BB2B835DCA7CB7C3ED9A004C7A329B9734A111744BDACDB669E69E9DF1E52F07C513E3752A0CCD81D7DDC4A64868B7BB2BBBD2095373480522BE10615248A179DCB61DAC90F7FA5FA9B84F190A9C62B5FF9CD473A940F03E7107157D7EB60AF1E3E384FFE8A67DCB2389B3B0FAB7C789CF100CA95CD6A85442CB9A2C243FB9D454B20BAE5762D72B8FE79B4DF81163D61DE4578CF976992D8B9989FC68089F811F53DB1E1092B60220552876B818BEA981571898CD6AB7B5F13C46B0A076526E3241D65014F855EFD7BDE08AD91F259DCB64E94EC3DAD97811EB024EE1D341521DC92AE5E93C73422088976F2D27D64E1D193B955E6736AD2BCCF3C1A53D590576434ACBC0B687F27F255FEF354E68ACA47160EFA7126F908E08E4548C11546D9C412D685FA84D2EB4DCB2BDFC48E2FA8023548198EBB072A48044F4391143E3BEF4FF9066A4B0D03ADC826819D67588BA84F99DA27424103652ACC039DDD3B567851CD78E4117A8B93AFE01FC8EEBDAA1ACB8BA9D095789E76B9D5AB9EE177A15D666EF171FE1D4BDCCFE2E58CE669B561F63028C6CE26DB5C8182FE048680B175C7AB407215FF3A7801C950D509867AB1B0BEF89B3E38A387915225EDE76F91AAD15A85D8C46EFD588BB3BAACBC52C036211512473420F3F061F5F53E9353DE0780425745A76439B3811511C86CA503251F24113384E1A24A9367536E796CE08B896F572489A2339E82A856C
pk = 0BE5FF5F64E309B8BD4D60D6302B5A9669979515352E32EB57BB8868FB19FEE357BE8B706C870D4386EFFA9C9FBE09FF900B1A0F4E303D094950716A7BF711E673B46CAC3D40E1D7705806C8ACB74EE79143EF535299D91540FBD430C99CAD59A1EC0C02E1788BB7D2B177B222872EEB9E232B6F83DE223EC61430022466BBE6C0537B4486C5BA80CFE974DD9991581ECA07FCB586FC9CC3489E0DB9013E8B5EB8E1CA8477F98180C804FB0D87E1084B71E052E65BD19A05B279F9324CAA8DBDCFA9ECB253D2A49CB3DB80BD5434C6E33DA90C552B9AA48B6B9875B155D207FD6B7C68D362F597FCF67D29EC0171A92827D626640F4863C4A283E87CB7D5BEDB0863B82F2DD41FD0E3BA3E09501CD385592437F23A8D00029AC97C76286AB265670034EB6B95EAFF362EA77DC39DED87164F08BC92E3F91DD671027B47FA81A06A80C3080977EF0FF9FFC5002C765B4C9863426978C99BA7C55172336913D7EF5ED7F414443CA115F1171E716D71439F64D9EBE3CC438DB0FFC47A616ED4996803B0EB464EAB4DD79C6149907BD85435109E9D67F6CB2457BFD190BBEC40AA70C669B3A0DD8E753B62E811B05D78E1993A6E73F3E474E1C2A65F609A2E01CD4CE91E16BAA78A61859672D10F7E76FF5D4EB08272177218B9C90DF6A521ED5493E68067F9BB884705AF792DE13C77198CCFA3F8B2BEDEFA2EE9341D69A68D2D8E921683484687A96AFB641DE8ACE3DEE04B5A7E65930885909B54BECE9FEE80B9295DC68F113F4DB4A5737E1E14F18D9A108C0F0417B99099FA36A00E5DA33B66C806406AB6106789B7A1546501A2E90983238B7312AE709543C05F53EC8F7C3160B9B585A2090DF1B47EC8FAA64645C3463E99B5664DCC98C739BDB1D53913FF99D64A805E76DF5B06BFE07CD8B8E9B7D77A7743A4FFAB30C70953FDE13527A5114D9BEC4460BEDEDA6B2FAAC460E83E157C68B9F8B9CBA031E6DAB481765438B43A45CACFC42C657E1D48C82CED462DEA3B39263452AEACBEB9D5FCB8FF6B5390E3696E54A1927D48A30C249E058EB8AFC53AE6646E5AD47BCAC94B7E488B5A4A5FB11E225059E7C4E8F3DFE3D3661ABB0585AA90780D0A599B6F73FC3D2919C8BA6DD1CBC1E6917228403676F358E35D73BC2121DF13716A43974AE30CB0990E1960E5C0CB660A330A5A15584A3034C752CABAC263EE6AB4DDF61C2C8ED52E5AC5869F3EE630FB53B866F8612A9F8859DCE1E675ED3296C40ABDA7BDEA1045959C1855B37C85A6A42139C29BBF63B716AF09A0AB69252C2294AD43F4BA09F7E6734605BDB8F4CEF1BDA942F97460589E032A7A3DE5AB54F07BE58276F21E09DA00D97D9EBE2A1F2C7BA5348DEE3DC32BA332CF8551A2A8B769FF115326FFF47FCC6985D0CFA58231025352737F3541D5775D9EAE36D53C74E17A90AF59937E198BCE938C9F455B2E25691913175A863BA66638F476DB7FD426BF68B752F9F420EC9323776C27E4C85138A4928B6C29901FB1DEDD9C7E79F9977B1F8A78EF4E0314560EC88A818CB4DE52B98B75F53188FE6CC3482934D4B69138738582274C2A47D77CB1B221524DCEC0ED7CD8D3168567C588D1E6ECAC44B9620AC95E28DA8293136E39C4C938D6644185A2CCF53209CE0A4C99738CCEFC25DD22085E6AEB5F9F26EBFA60502E8D41B344E9CBBDEAE3C83AEE990389FD287F646A72CA08060DCBC2A3C37078933E0B9E5D2AD6BAA11E65D3DD6E50FC09C4228A8D23C0E7C73D9B5785B6E141F1CA8A4A060F8162D94E571AF7E8DB1B1BF17B5DB7D935688598B1B22131B8981FA65E5F0A6786D1222A69643A0BB18944CD9FB900BE6DA17A
sk = 0BE5FF5F64E309B8BD4D60D6302B5A9669979515352E32EB57BB8868FB19FEE35F130B34EC33E8A395F7FA574912DD2221CC4225114D6E1AB37A320339593469ED24906472AF7A949CDF91107633D4DF97030DE33CFD995E30472E62A01DAF39B80BAA282357A6F7E706D1E63430A0DACB01FA13A6721EA166F429EDC30E98FC6438285222494A36310A0465080350124086108870D2324581922D52060294209212018858845109C80549020A4CC6240A394123A404119509D032820A822551140022A5901C276D62A890A328304320690932650A37045282254A42650BA64021B4000BB74D09454C139564A0402858224910350C0880104A086294189090346CCCC021098509D2C808DA44491CB16824B66923482654147110340801C081CC488E0A849000906060B23022C82482B28CC8C66014138058C808203268D9A4000B288A11482E1816211AB42940068021022113420913429281424918867111C93023A905114988D2126E9A464C91A244141749094760D3328122278824018260A669DCB62524490CCC368D631072811292521848DB4006DC282652008D89A229D0B80DA1180AA3B2201AB12803208A4044515C48292403300A364142186E02918D612672E1C8481C972409072022C665143391E0A04D61348602B22910918D11A34D84246E1A4572C9863052B40D08B9201A336D14094E0322850C29046110651B26866316241C128D0A29480348050010669A9060199029D1C611E1165114830C11926DC3248500178C5C963114085190048519090E8C962D9C16209B10251AA408231591112240212984C4029003B96D848661C926128BC88044000A529410591862848648530622CB1882122492490400140924C4845188140D42940414911108356A2210521A446D20B38D49B6905B422594366D11A96C08072490942DC0B28D1432811A242E04014E04164D04424DDB320C24144520B6240440711823008394810C812D489228D8960C0B0546CB487111140909291293468E63C630021500D0806D1A93699B18260A464A23930093B068DC36441C97249A14410BB6650A4744C046258146860BA0505C1442D8180DDC1881A386495A402244308492406D00406A2037041AC661A0446E2204494A268DC9C40C001860C2284DC8026AA214609A262A8CC24C63342E181150822605C186218BA81122B13104A38DE1061218410A24426E538849120705DAB0410C192C88000522A50C02940950064DD846708F2405A3A6E19E9A1B239FC8A6A582A72634AE5313F944DAD0C6170E71A23E9B2DC6BDB51D398B559354CD33E79C15D18E210DB2604D0DC55BEBEB48B86FE90A54FBAC339FA479CABFEC4791357D5B5F991EB79EB3E61848458A19E99CE817E91C0FFA79083F790A2BE65864FEECA45FF7F09E1F8B1B302CC02AD3213DD035344EEA285F28FAD9F85B64A75E2FE62C96DA7741A6DFC5FAD1CD4CE44D134399FD7E93582ACF3DC893B3287267EFA697341439FF3613000CC972725BE9D12939D1897C610752A8806BF3ADAC273F214FDF016A2A90D2D1D1FDDEF0B921DDAA31040A9F44885F73B3AA7BB25557AA2F329B2CD78343797F4FE3553E083A801F4D600632D932E08D40077E7D098C1DECEFAF764A392C623FE9576094F5FD0953145382D29CAAB5241DFCCCF30D02FDCC75BAC21935FAD7A0DB8514386C2F1F8062F94B32732D90C5189C572877BB4E38AC19ADE3D5BB95EE4920BA3B12AB322EA79964D997E2B4561DD658C10DE73FB944780E4FA1114C20F0D061E3F207A1B6F7F61A098D8FFF23C2A0F5F220EB7268717728733795B205F3211D4CA25B693BCF8D5EBA0066498A68B6F1FA385E68F64F073BBA6EB119E66153861BBD09B48638DD158D1CB9BD99EBC7C8E652E7AC42F5A7D14C6CF70B6C153DE5E64BA256C81C9A82DE130C30456FF250AB862474486207845960AB78DFF935F23403796B4550B0D731F0E946C37B099840E76E3751CBB847248E2EDBFBAD3BB947216106E4ED92AA00C4197425E296AFFAFE11DDA986F591D9A44E34C0556CE0D8F735D838F4E1319B6BAF16FB6269EE95EBDC8F28BC61EC681645215A773CC24529AD5A11CB01E8EB43DBBAB327AA227343EC466E284530C7FE9AA642DA1EDA8921332C036A168028A70B94B05F050227A38E118C47444AB827EFE6CCC7A646F510CFE35555AB3BEB7C308A977E7863511274479A9201A00AB8BCD68C4548418687502B6C1FCE07E98CD82698A8343BD3052003DCA0F9D0792BDBD78025F0D440C9E0D22546360FB644630CEAF8656DEAA47988340E93298AE7808700F12831FF0FB9522D3AB3E084428B3282E73E5D15741B8B525BFA98D7D2F9EC09E369F31A76813E29964725CBA39A6749B71780B4421756BECFD564952513E283D91076F89928D5C58DCF9899E74151CAEC6760A6A7616D52F6E83D7D79C1D09B5ECB6CF6A0BF61CF1F013F4D85D73BEC59DFF5F64DEE0DB424BB63AE9CA0B660F6E72CB7F3AF37E0FFECDD78DF2656A46E738D2B35B1146B86D21FFC38DD98D9FBAFBCC560DBC141F236F0B12BE16BCFEBFE716B8ED80B46ACCB05A5F42695AFF2F1804407E9D78D33A2D5B4A03A4DFC2F476B66302E6F806B5CDD1C91B24A0FDC856BC079D5C1EE243D9B72033C76FDBA1FD8E9E719FE101A450266828BCE2EA4522790CED01FD13F9CB7999CACED40925FBEB867DBC8A3C971A8F0DC3AAB006BBB4A51C4A57BFDEF9630883321B5CD0F13FFFAB219EA0B9E511A22EC78EE10226041BBC8A687196C981D0D118916AB414B04DBB20EF48865D5614B7F7E3E26BCA520CCCACB5728635132214F7890E9B3B74C772B4BC79A0231EABD7F6870F19AC48FA5565F8A80047C49CDB308AED9A2B3F77E775BCFB0A569DFF4197900D06349EED1B8E3C534B3C2B787099794C39DE86422C7F6E0C6C2CFAB729959FC8CE886FA42670C85DA7D107172EBDCBA7CAE46F24C87482324179602EA1E7219F7BB35DF577BAEAB64861CDB0735FD8DA3958FDC07BEFC068C770980C8CA8E39C0E3F2594501E0E0962933767EF12D5FF8B9DCC62730F509AC951455D4A6C26B5D8553DA69EC9707370319A919B31C33EA7D50603C3600B1E2CF65FEB21EC9AF5F2BE2D21615C079301CB8EBC48A78D99CB55A54CFB1B33743D4364F0A09F3AFAA096C879C870E1365B0AF79F46DDD5AACFA520C7B7E5B07E725E522DB4A3987EED433344C51853CCB17A3EEF3D826E394DAF359E5ABDF6B39E614CD029BFFF4B047E4F57D4164956C6693BCE0C853FA2EAF5496AB63701220AA41851D784741C96FA2956CF0D12300F71C23EC43D5AB260D4717DF3FEFE9C1C17F586E7C6DC438F457F2C815A1FCDEEE88FA3640CDEF4496B3E468F27C8EBF7B82D1285D7C8FC0CF9BB93B688B2B8A61F803693E86C7D01A8FEA1292C505B2C9F0EC1469E7EBB20E00D16F99FC9DE7BAD752A33598D6D29B9ABDE826FD630455012D24DA48584DC0449F175CA338BA94F60A235157D29CFBCD04518812EA51F129C2C3A97A8C78F004A49911EB1538BFD4609DEE8AEE7C5FA10D1037385D57706FE54E7377D40FAF3BCA966C7A61723E9D
smlen = 5720
sm = EDA3EAB30E40C77234A211C774051C308C3B38E5FCC6E8DB3C199F9149691A8FB766DA04BFA79B1CF4E7EA10A09574BF7C5C2BF30B77461FF40CA12562125CDE00E7755F3B1D89CBA9F0A098769E7CCA8E0928043D093C70B6FFF4008BEC273509E83E0DC0ECA9E22272C1F68148DCA09AD4F60553BCECCA4408C6AE85A319D6F97070A34D2E241418EC8E8579948074A94E662EB865D2C0EBBDE87B1A92D0522DE1644B5ACA53D2B68B86C538EAD8C03EF43F4BCF4900F88E144DB6BE0156190BD97E4A11DAFFF6B1881D118F61276391934756D5F17289D87AC235CB2B7079AE7DFDEAF5074482D821CDD06C808884E9080596FDF42A2056C57610EE7CCC8966EC3F964792741EBF77831BE56C73CAC581F3ADA8BA1BD3556EC0626C228153CBB106D4A7D7EF9E7764D3B200A291632E3971F1A6DB03986DFC6139D058717C075ECE10181BD5627EB8F5E2680B8B827D2E68E2983F8310ED039D7A6BF9E3F46236C8EA2E5A70EFB175125CC2EAB6B7EC94A79E3D2A2EA7A94AA9407D5C83116C0F0A361A554341474D85D1AB901C142551D11B170B2AAA47C29FD01C98BD4692EFB7A5CB61CB0343A5585B5F4D4805C1082208074ADA4BD9956A3C9F04A8F068E01A0BC003A1D9034771800C6F580C8C1BB5FCA6B7D88D238DBB48B214835546D330E569C4F8574C70E9BD4BC00EC24B63DC252A496B0221AA11C37B7CE5C0EAD9521F0ABB72EBD9568B91AE4B85851157AB23916EBD2668D4F76C4E297F113549D3A36CDD53462D136A2DCB315EE1F2601FCE40C137A9E5D57DFBA2E331742C1FC86DC26CB03F92B0EC940E85FE0FB39AC50FAC005B5857C5C46313F9086944AA0558ADDB8EBAB8B2F33EA77A7C3DBA5A3DD76148BBDF23E12E0F737E0FBD5874F6948B2EC96F6B2C8E404A6ECA9684C59DDACF5B29D27EB1ADE7758134F09FF46BAFDD9AD4BC645CB370A5FA4527187A3E76438D27F08364AE44031222168852F6140EE233AA3BC75C7DC1482825E1821AC9E8209CDBFB47573A8177A87776C048164D8728CE3C79B6A0E859FC3FCA70370E29DEA9B879131DCD75DD1493A72F1560641218FF1072229C4CD8BB3405E0D9BA1E3539B6AE61FF44361D56DAEDF57C9A7AFE708DDEF8101C82554F70D90C3EFA4B5BADB6633015D941DE9A518A6B16A62405924E9325D03B354806DEEE99653ABEF84B2873A3A52A7C9E817BFA1F77AE359DD7F279EA961130A540CEBEAC117272605EE208C64D65EA9EB34A0EC1E5613F005CDD8EAE11C9113D83DA2C557BF47868BEBD8A32CBC4ABFAB52782F87C7BC3FCD330EE3E4E12DE38FE15C0B4C4B730708A78291F5907881605F8FA601F512B4378EEB098A72BAF9FAAED646BD8E8F421FADCC54F684849151A6175763310BC67C5777D997347C1EE949DC714D631CD3164703C817B41316C315C8ACE20BE4D2D32952E113A039A32523F2438D588B3C7E7406EC88E0CA2D60D1189AD389D996F570F3CDFA8F096DA86C830841E7DAE7298CE382C1EDAAA155A14A5552414F86DDEB17EB8E09F1B2CA99F0E97EBC1BF90ECD0867F3C83517EEB79B761AB4085E2BFE7787C61C639F7C62B1DCEE9A63BAF61AE5BF890142F592BA3A8BB91C62AE6B997CC08A4D57D3A3BAA88406E163E0E848A08C93BA3CE3BD3B761BA7C5104F8A67ECFE3DFC458E68295B29874D7FDA685D1BBD982CA79099AF84C4466F217E016508F5BCFC7DC4F8DDAD961CAE8F772AE2D5B0472604D0E079F1A271C3B42D3475DF518464FFA395A026BC234BF71766CCDB28B4CEB9753E63BEBF4424735AE16AF684F67E8E80EAE5D98F3382D62CA936A93CD7B132DD1C6DACF9C2F3E400FA4D2BA2D87E2C9100F57489674E37E51CA971BE86CC466A384D8BFB97B7ABAEE8C8BF117F4AF148F09CFD9A0CD3586D1187A1E049E9A1866FF777FE27C177793045B7AC0E06386C7D6A4BF19EA45C5D220DE4AB12DDE49BC163E99198E765F454D53B6D05293B5C71100DCEA30AFC0666B5959705F38D06503603A5755B446345FA8EB79D757493DF52E8A2FB5580C24B4847D4CF4FDE53A5D0A1B7AD2A70F6E6EF2832E0C911162244CCDC98F06E0A856027AD48F556F10C270B657891E0B04B838815DC45FFB9A008F70E4934F2246E99977704B82A0B8A8E1823A5428FB4429A10E081C4F292973C4B089D7967D24DC257485D5356D08F139FA479899158DFEDCD90B36C769E36BCFAB800A9EF17CF79A62C5C14D5BF42BEA20CC440EE0A47E6068FC2B0AACEDF9CF8B5F6BACCB89900592EC3CF6A34799DD01F3C0B0F7F5536528DE40DA8D5A46DB538425A311B2A895FECECFAC17CC71D5614C9A6F6E7ACE37BFE8E19E6F51E7818B1EF2432D6E4068BED261BDE6F467C0D7D1884D8ED10184612C3F41BFCA2A8DBD9F2B9B69D304B6884FC58AEADC17DF898B29939706A99D24BD1089835B0DDDB331C00B35CE8A4B75CA9AA507FB9865648319929A1D009668FC78565A99A2F3C012D8120DC93830873FC0C1647A3DE7F4641AE8CF1EFA6C33C019E68876D53B3EE56A6BC0AB5AD43D0283EE198B103AAE1A67E067C301E7DCBE10E88585C71B397799BBC61EC405F38C1A7B675945D65B77FEFCE253B36D66332C205D184143EC30F5A0A5FE0C5B419ED0AC139BAA36B5B61884343DE8F30A4A1F8117B84C4F82BEB3717E1E90C2EBD41C1385A461059733F44BE120DDC6F32817EA7CB8016491F9315545980B0E5B6A2E7E8221A79E4701EDC3245AA667F2BAEE55228D5CBC280934554C08D9B40880D69BF62610CF54E308E7403F8EFE68F2D1370AAEF03C7BEDFEC646A51D2919FD2D29E81263622F029456BF570F56CB19D7274F33C5C88B3ED1FF4D1D7127DBDB3B983A000726C7C0D08FF8E16014AE05BC902291C8B2E41ECD6CE14B88BFC5F1C763B4F9269CFB847970E266A416CF87B8E435370F8DB3FA476F15BC2B0F76888C31A2419250405507595EC694568765A9E6BB308A78B18F579DE8E536F991E062EE506EAE2358C2DEF392ABD834D8D6CE9B8702179F5A96D1669BAB0D0687F65D3E55EB88CDBCAD9B988B1237D6291E04DCE13B9623410540F128970DBCBE5A4599078FF465696673B55B230A2349854EF4DEB578D21E12FC125103CB1CD523C601C75E19E93BFBB1E8D69D38300DCF5256D6AE94850C892DBCA435E5F169AD38896668F0AD38C6FB5327C533E47945CE6DA229657DFBBD85DB46ADD9CA61350B0F390FF07D07574EAF7689B9D8AAF5368E24885F3A8B069B3519FE8B0589E54B531E9831BA010210151936545E7176798B8EA90111161829426871808291A0ADC2E0E2E8EFF8FF09283638526067777C8FA1ADBABDCDEDF8011528393C50606F72838C969CD3DEE0F40000000000000000000000000E223344D21A6BB3A2356805E678673C45FB055FC5266E3F692AF9935AEA307F14A5C41B979966A5DFE42EBFED1487E4822B74AB5AF28995E085EC8007ECA4977C63EE5299FEC63DCCBC42EEACAB488E574249E9D856146750AD97C8A443485EC1C5820BEB0964640010F6407140791E74684DBB91052E2D8BEF7BDCD78B2EC03C97A53295D683BDBE32A70DC19A2F75B8613AEA9616AE0E280179492820F73FB7FA4121E673FB5C328F41B67FF8FFA7AEE6564ADABA046D6E1D6AA13FB24965390F829246DFA8763851405075F76CF94C66FFC3308214DF0960C649AAEDC22926CE9357D3875F8B71D68D75999AA3663C30A9EDF07228BF7DFF49EC1E6C7A33D2053597003B82392E826EBD701B4C981AAAC9951C79E08F592C2C0637C8E5A7F9DCDA599E859C317D4888B4098992E0E2D979E41C703686D577E5BA6001EC4F587140711293D664963632F87EA0461E0E0C5E9D8D292FB409F9F9AB172EE17FC8AFABAD06E42B437CE22924EB5DBD3A80A06962F3B37946259F9C75A233CB2B4ABDC5CD1B648FAEB1BE8630DB40D151B8FBA693DF2C5BDCAA14DC4783F450B6BC407515CEEBC5C9A47BD1A141384F0B596CAB1135C075651CBA989C190F3171DC1D72330EDAA01656813C4B7811715060B023FC426745C301B2A91E0D08ED3BDED438C4CE6799C35F3981C882A0BDE4A2FEEB1A52CAFA47B0C48558FC43F98FE08F03A71128362BB6FB9DA6A22249F4D4352AE7D3DAE85DE497E2411EADCFE5BF1A3C075C45811E0097ECEA255FE15BD8321FE8B546A8CACFB899EECF5419DB363C7567C2FE7360B36DE14674F500A31D3EEC71451A7C0D5576A8939C0F6D4D9F2F03F3C516CE25CE73ABB35C73AA94F6AEFAE6AD87052D6B195FA43586817F5BB974AAE7F1B8608922411AA5B0D7D574016CBD3DED13395623470A108FA0E1D3F9FAA7E1E5031843F2A23DBCE8B196315290DEA5795E4115D53DC570A444064CFA3C9457DBF3EE323B1966ECD2270C32910F8F430522471258A1F1955A6E1DD8C84ED9A566499BF85628615351ABE84B401421DA2CFAF575E2644C9304C075ECFC374066CEC713FA4C0D89043689FBC59FF54B8F97EE0A3B0989BC5E4EF83CC9833E75BC8B67BB5EE3C06EA156611CDA95A6702416807530EA206ED89835D20805EA988B1958569CDF7F809996214DADAB4E20BD44917E3410EC6BEAC98FEA07F764E85B66AED5E17CF675D2ED8E63DB728FE75158CB31779E31379648B43D68CCFF3780854CF03535C57122019456E73CF06769BF1FBF558542241CE665BD10F921828553585E0CF664CDC6160F9C47FA5330591B74194F4716056CA83993EFEC4A52DB9A1FBD3B2F504AC19667325167407375B6D7DE739F07947B511C8D475744E5C29D6E286A37F1FF8317BD0178F0E306A38FA6E75F4A80427FEB2C91235D3E7F20D8101CFC03BB73F44EF59AF3526E9AFC580027A1DADE37654238B8EC7AF0105248FE30784A88B72E11FC1BD807E47A349BD29075BEFBB29730EF8E85E3ABD5105559BACEE74AA27D90D360A8D629DBEC95EB34C7F7CA20096FF7B521E40D3944A975436896F372EEAB6B8615EB91697965BBF955779DD3047F7E3BF029E3509A5780247445D6223D085AFB4291D976EFADC41E42DC2C0728D18F6155654A332FEC72EB6AEF8B92C1D177E3DC28C31971BCAFF76DDEBFD9588BC244B116D409E58DC5ADA1648663D603C47FAEB814AAA7EB9B6264356F926C18B9357BF426B89DDC8EB9177ECEB5C6CDC64DD8FEB7B326BC1BA89BD9035235DA0E644EF959C58DD97B88D5C749B36931AC2694C67151DB0894652E99254222D37CEFE9E27B3DD663A152DBE29A3639AFE42F4578937076180563AAD6AD739255EA012A17D2A56627D84C44FBAB261D392A966CFE19278799CF1634D42384323C496190D4B9FB662694E3887EA66AB9E8B195488C8DCA47C8BC0424247759137CFBF86DEDC3641904CB6FACBB30A9FA84ACF69A67B4AFDF4C2AA420FC0D90CEFA0DFBBCD3072D9F772FD6058E2BF0E251BE93B00DC43765B53DB51B22F12D3ED0CC5655E4AEBD9D923F99A43E4461DCF5992030E66A1CDC3A65558D9BB3A39788D92328387D144850DD3706FD7A079E3D2398F542F91A8AAABF0C5068DBAF1FCC5160398ABECF74884BEB04F3A3EA38BBB80D798F5981B3F2DB6C7B33F867B7DC06A4417E30F94CDB4F523AEEA0BE12BD75AAED57520DB0D4B4F013BE3A1DC7AE5C58FD1DE9637F7D82F697B7E92DA427A78FEEC6A5C0255EB57A43DEA6CEBC8805BC04E04FE789E222B1E2642D26EDC14FB36ECC6092B3060E45EED6C5B35DE8741F72933930ECBD7338CF39474122357365700CB50C5EB176FB92814FA7F4032570CCEE6B859236AD5DA5F1730129EDC7BE218BA9874620F6F0EBC45E0BD622F8FD1AE6974994AF95C6519EC1C46650C073D194FA6EBC62F405F63A3416782A47872C7D77D648D0A1C802FFDFDE5FDC112C94CFC68F401889EFC522FE488FDB5384C0D93147AB6587659D936F98ECFBCDCFBF8B352D605F18C855E2559743ED97991C5D50DF44A7B929303835654A3955ABC5BEE6327400A7CCCE460B318D8B5ECE5B12F606ADB3D7B5ED59563B8E675E78029AABC234442C2463256FE02B04F556DA35C4615D14A9F4EFF17DB0DB81DE4BDD894F6628A120BE2D4CF3E1F46D53817899657035A76137E23C0B0E8DDD29465D7F15628FD435E6CAACA4194FDBF85FDCC31D5DAFCB52568B7C0CFBE713BC85FA424BA3ABE149E4035FC86807A8B876D2163B447CAD5EC0E6EF38A1D591AFB46267F9DBF142CAB1CAC1F73BEBA212992FC6D4647EC17848D1ADBB1901277A5078DD72D9C9184E893C0806E9B4AFF0A824670D438620F2A7E8D2965B619D291E5824C014FC888A36FBBE17356431F0039038F9B497902AED969F9C488390B7087763638E976801127BAF1F53803C4DC9649F0EE85D67B239E2BDAFB2BD75F1D1DA22A56FB3AF10A9DDE7AD306C4AF8681029316C0E1949228E6BF5ADF942F1C0EF92B2BCBC0C70D49E5808851444240A78B14D21B54F66271482F49B85F5180B268050327368496CFA8B54ECB97EE6D28EB74A3742F68583DA046809002C22F7B31FBC0566969F9A15CDCA892C4BEB101A2AC3526C76E9D30982C9B4893450FDEC4001D2431828D24D8B1A67DF80E2E10ED2EA8D723227055C48006665F7DA8E032EFDC70BC7EEB2B369B551FAC542AD6DF1A23107E2B3C0E3CCACC25F26404C085CBF56E52D35D7948DB9FDA6DFC24709994719D8CED41A2CC9B3C4B2BEF0967CB71861CF0E6AEA9BEC9395726AA0E2F1A7247ED0F6038E3DF4BF566786073590DCF97F8F0A99658D8F630A2D130C46CF4D26C669360D0F70B75F904C9F923AB285D5DB129F6C25AD21F9E26AC844D07A8EED86C4E224EBFC5B3F720D6F94B0A01B1433C46B40CF84E80F7A6AFA7BB8F9ACF818AD3CAB2DDD6904C067BEA4F1FE79B83CB0AA8FC75B6B096BAD6FE94ABFD48F8EFC0F2B9A02EBDA8FDBDBE1C77F1854EDBA18AAE7F31CED9CD34C1B355108DF18A8953932F7554AF05B203A96A9BB93E0EFF51D7F93B56E351562CF85A2D35EAE2C2427B89A8662A1C723D4F14E6EAFDBD636C2BB7ADE29C1A6BC8A463734C808BEC68B1E9A31AF6E29B412F1CB8C90A9911AC5C3EA71E46113D2D7B1AE2D8802B06A770FD0E9E4652895E42181AD09BB541E9493F258711BB7BEDD3E7CA8B8CE875669CF80A6880ECA3F13800DE7011EA67F443E505C4FB455608AE586F922B3C83FD33B306BDEDB86223C33E3AA65EDC93CBCF3A03ADAF9F328997951D59A9200C0BA2618E3596AF176B43122CEDC52B1E006EA6D12DC236A6FCD7CC46825F2EF7ED71683A731D746FFF2FE54E0B392A8CBFA38873196BB2B835DCA7CB7C3ED9A004C7A329B9734A111744BDACDB669E69E9DF1E52F07C513E3752A0CCD81D7DDC4A64868B7BB2BBBD2095373480522BE10615248A179DCB61DAC90F7FA5FA9B84F190A9C62B5FF9CD473A940F03E7107157D7EB60AF1E3E384FFE8A67DCB2389B3B0FAB7C789CF100CA95CD6A85442CB9A2C243FB9D454B20BAE5762D72B8FE79B4DF81163D61DE4578CF976992D8B9989FC68089F811F53DB1E1092B60220552876B818BEA981571898CD6AB7B5F13C46B0A076526E3241D65014F855EFD7BDE08AD91F259DCB64E94EC3DAD97811EB024EE1D341521DC92AE5E93C73422088976F2D27D64E1D193B955E6736AD2BCCF3C1A53D590576434ACBC0B687F27F255FEF354E68ACA47160EFA7126F908E08E4548C11546D9C412D685FA84D2EB4DCB2BDFC48E2FA8023548198EBB072A48044F4391143E3BEF4FF9066A4B0D03ADC826819D67588BA84F99DA27424103652ACC039DDD3B567851CD78E4117A8B93AFE01FC8EEBDAA1ACB8BA9D095789E76B9D5AB9EE177A15D666EF171FE1D4BDCCFE2E58CE669B561F63028C6CE26DB5C8182FE048680B175C7AB407215FF3A7801C950D509867AB1B0BEF89B3E38A387915225EDE76F91AAD15A85D8C46EFD588BB3BAACBC52C036211512473420F3F061F5F53E9353DE0780425745A76439B3811511C86CA503251F24113384E1A24A9367536E796CE08B896F572489A2339E82A856C
    ";
        let r = KatReader::new(
            std::io::BufReader::new(Cursor::new(ex)),
            AlgType::AlgSignature,
            1,
        );

        for el in r {
            assert_eq!(el.sig.pk[0..3], [0x0b, 0xe5, 0xff]);
            assert_eq!(el.sig.result, 'F');
        }
    }
}
