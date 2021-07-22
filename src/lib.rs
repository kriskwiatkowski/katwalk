use hex::FromHex;

// Converts txt to usize
fn to_usize(s: &str) -> usize {
	if s.is_empty() {
		return 0;
	}
	match s.parse() {
		Ok(v) => v,
		Err(e) => panic!("{}", e)
	}
}

// Converts hex in txt, to an array of bytes
fn to_u8arr(s: &str) -> Vec<u8> {
	match Vec::from_hex(s) {
		Ok(v) => v,
		// Panic here is good, because when execution is
		// here it means all checks should be already done.
		Err(e) => panic!("{}", e)
	}
}

pub mod reader {
	use std::io::{BufRead, BufReader};
	use std::str;

	#[derive(Copy, Clone)]
	pub enum AlgType {
		AlgSignature,
		AlgKem,
		AlgHash,
		AlgXof,
		AlgDh,
		AlgHmac,
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
		pub sm: Vec<u8>
	}

	#[derive(Debug, Default)]
	pub struct Kem {
		pub count: usize,
		pub seed: Vec<u8>,
		pub pk: Vec<u8>,
		pub sk: Vec<u8>,
		pub ct: Vec<u8>,
		pub ss: Vec<u8>
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
	}

	pub struct Kat {
		pub scheme_type : AlgType,
		pub scheme_id: u32,
		pub kat_file: &'static str,
	}

	pub struct KatReader<R: std::io::Read> {
		reader: BufReader<R>,
		alg_type: AlgType,
		scheme_id: u32,
		current_section: String,
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
				_ => return ReadResult::ReadError,
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
				"ct" => self.ct = super::to_u8arr(v),
				"ss" => {
					self.ss = super::to_u8arr(v);
					// Last item for the record
					return ReadResult::ReadDone;
				}
				_ => return ReadResult::ReadError,
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
				_ => return ReadResult::ReadError,
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
				_ => return ReadResult::ReadError,
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
				_ => return ReadResult::ReadError,
			}
			ReadResult::ReadMore
		}
	}

	// Implement parser for the XOF functions
	impl Hmac {
		fn parse_element(self: &mut Self, k: &str, v: &str) -> ReadResult {
			let mut klen = 0usize;
			let mut tlen = 0usize;
			match k {
				// Rust warns here, but it is wrong
				#[allow(unused_assignments)]
				"Klen" => klen = super::to_usize(v),
				#[allow(unused_assignments)]
				"Tlen" => tlen = super::to_usize(v),
				"Count" => self.count = super::to_usize(v),
				"Key" => self.secret_key = super::to_u8arr(v),
				"Msg" => self.msg = super::to_u8arr(v),
				"Mac" => {
					self.mac = super::to_u8arr(v);
					if klen != self.secret_key.len() || tlen != self.mac.len() {
						// At this point key,tlen,klen and mac must be parsed
						// and delcared sizes must correspond to sizes of arrays
						return ReadResult::ReadError;
					}
					return ReadResult::ReadDone;
				}
				_ => return ReadResult::ReadError,
			}
			ReadResult::ReadMore
		}
	}

	// Type used by iterator.
	#[derive(Debug, Default)]
	pub struct TestVector {
		pub scheme_id: u32,
		pub section: String,
		pub sig: Signature,
		pub kem: Kem,
		pub hash: Hash,
		pub xof: Xof,
		pub dh: Dh,
		pub hmac: Hmac,
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
			    AlgType::AlgHash => self.hash.parse_element(k, v),
			    AlgType::AlgXof => self.xof.parse_element(k, v),
			    AlgType::AlgDh => self.dh.parse_element(k, v),
			    AlgType::AlgHmac => self.hmac.parse_element(k, v),
			}
		}

		pub fn set_section(&mut self, s: &String) {
			self.section = s.clone();
		}

		pub fn get_section(&self) -> &String {
			&self.section
		}
	}

	impl<R: std::io::Read> KatReader<R> {
		pub fn new(reader: BufReader<R>, alg_type: AlgType, scheme_id: u32) -> KatReader<R> {
		        KatReader{
					reader,
				    alg_type,
				    scheme_id,
				    current_section: String::new(),
		        }
		}

		fn read_kat(&mut self) -> Result<TestVector, ReadResult>{
			let mut el: TestVector = TestVector::new(self.scheme_id);

			// Read one record
			loop {
				let mut line = String::new();
				match self.reader.read_line(&mut line) {
					Ok(0) => return Err(ReadResult::ReadDone),
					Err(_) => return Err(ReadResult::ReadError),
					_ => {},
				}

				if line.trim().len() == 0 {
					continue;
				}
				if line.starts_with("#") {
					continue;
				}

				// Parse section
				if line.trim().starts_with("[") && line.trim().ends_with("]") {
					self.current_section = line[1..line.len()].to_string();
					continue;
				}
				el.set_section(&self.current_section);

				let v: Vec<&str> = line.split("=").collect();
				if v.len() != 2 {
					return Err(ReadResult::ReadError);
				}

				match el.parse_element(self.alg_type, v[0].trim(), v[1].trim()) {
					ReadResult::ReadError => return Err(ReadResult::ReadError),
					ReadResult::ReadDone => break,
					_ => {continue;},
				}
			}

			return Ok(el);
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
					ReadResult::ReadError | ReadResult::ReadMore
						=> panic!("Error occured while reading"),
				}
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
			AlgType::AlgHash, 1);

		let mut count = 0;
		for el in r {
			assert_eq!(el.hash.md.len(), 28);
			assert_eq!(el.hash.len, 0);
			assert_eq!(el.hash.msg, [0x00]);
			assert_eq!(el.hash.md[0..5], [0x6B, 0x4E, 0x03, 0x42, 0x36]);
			count+=1;
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

		let r = KatReader::new(
			std::io::BufReader::new(Cursor::new(ex)),
			AlgType::AlgXof, 1);

		let mut count = 0;
		for el in r {
			assert_eq!(el.xof.count, 72);
			assert_eq!(el.xof.outputlen, 3);
			assert_eq!(el.xof.msg[0..5], [0x37, 0x43, 0x34, 0x97, 0x79]);
			assert_eq!(el.xof.output.len(), el.xof.outputlen);
			assert_eq!(el.xof.output, [0xEA, 0x93, 0x0A]);
			count+=1;
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

		let r = KatReader::new(
			std::io::BufReader::new(Cursor::new(ex)),
			AlgType::AlgXof, 1);

		let mut count = 0;
		for el in r {
			count+=1;
			assert_eq!(el.xof.msg[0..5], [0xA6, 0xFE, 0x00, 0x06, 0x42]);
			assert_eq!(el.xof.output.len(), 128/8);
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
Output =
3109d9472ca436e8

# This block must be selected
[Outputlen = 128]

Len = 2696
Msg = a6fe00064257aa318b621c5eb311d32bb8004c2fa1a969d205d71762cc5d2e633907992629d1b69d9557ff6d5e8deb454ab00f6e497c89a4fea09e257a6fa2074bd818ceb5981b3e3faefd6e720f2d1edd9c5e4a5c51e5009abf636ed5bca53fe159c8287014a1bd904f5c8a7501625f79ac81eb618f478ce21cae6664acffb30572f059e1ad0fc2912264e8f1ca52af26c8bf78e09d75f3dd9fc734afa8770abe0bd78c90cc2ff448105fb16dd2c5b7edd8611a62e537db9331f5023e16d6ec150cc6e706d7c7fcbfff930c7281831fd5c4aff86ece57ed0db882f59a5fe403105d0592ca38a081fed84922873f538ee774f13b8cc09bd0521db4374aec69f4bae6dcb66455822c0b84c91a3474ffac2ad06f0a4423cd2c6a49d4f0d6242d6a1890937b5d9835a5f0ea5b1d01884d22a6c1718e1f60b3ab5e232947c76ef70b344171083c688093b5f1475377e3069863
Output = 3109d9472ca436e805c6b3db2251a9bc

";

		let r = KatReader::new(
			std::io::BufReader::new(Cursor::new(ex)),
			AlgType::AlgXof, 1);

		let mut count = 0;
		for el in r {
			count += 1;
			if el.get_section().starts_with("Outputlen = 128") {
				assert_eq!(el.xof.output[0..3], [0x31, 0x09, 0xD9]);
				assert_eq!(count, 2);
			}
		}
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

		let r = KatReader::new(
			std::io::BufReader::new(Cursor::new(ex)),
			AlgType::AlgDh, 1);

		for el in r {
			assert_eq!(el.dh.public_key_x[0..3], [0xEA,0xD2,0x18]);
			assert_eq!(el.dh.public_key_y[0..3], [0x28,0xAF,0x61]);
			assert_eq!(el.dh.other_key_x[0..3], [0x70,0x0C,0x48]);
			assert_eq!(el.dh.other_key_y[0..3], [0xDB,0x71,0xE5]);
			assert_eq!(el.dh.secret_key[0..3], [0x7D,0x7D,0xC5]);
			assert_eq!(el.dh.shared_secret[0..3], [0x46,0xFC,0x62]);
			assert_eq!(el.dh.count, 21);
		}
	}
}
