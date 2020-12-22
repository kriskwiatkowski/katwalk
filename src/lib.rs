use hex::FromHex;

// Converts txt to usize
fn to_uint(s: &str) -> usize {
	if s.is_empty() {
		return 0;
	}
	match s.parse() {
		Ok(v) => v,
		Err(e) => panic!(e)
	}
}

// Converts hex in txt, to an array of bytes
fn to_u8arr(s: &str) -> Vec<u8> {
	match Vec::from_hex(s) {
		Ok(v) => v,
		// Panic here is good, because when execution is
		// here it means all checks should be already done.
		Err(e) => panic!(e)
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
		pub outputlen: usize,
		pub msg: Vec<u8>,
		pub output: Vec<u8>,
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
				"count" => self.count = super::to_uint(v),
				"seed" => self.seed = super::to_u8arr(v),
				"mlen" => self.mlen = super::to_uint(v),
				"msg" => self.msg = super::to_u8arr(v),
				"pk" => self.pk = super::to_u8arr(v),
				"sk" => self.sk = super::to_u8arr(v),
				"smlen" => self.smlen = super::to_uint(v),
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
				"count" => self.count = super::to_uint(v),
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
				"Len" => self.len = super::to_uint(v),
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
				"COUNT" => self.count = super::to_uint(v),
				"Outputlen" => self.outputlen = super::to_uint(v),
				"Msg" => self.msg = super::to_u8arr(v),
				"Output" => {
					self.output = super::to_u8arr(v);
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
		pub sig: Signature,
		pub kem: Kem,
		pub hash: Hash,
		pub xof: Xof,
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
			}
		}
	}

	impl<R: std::io::Read> KatReader<R> {
		pub fn new(r: BufReader<R>, t: AlgType, scheme_id: u32) -> KatReader<R> {
		        KatReader{
		        	alg_type: t,
					reader: r,
					scheme_id: scheme_id,
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

				if !line.contains("=") {
					continue;
				}

				if line.starts_with("[") || line.starts_with("#") {
					continue;
				}

				let v: Vec<&str> = line.split("=").collect();
				if v.len() != 2 {
					return Err(ReadResult::ReadError);
				}

				// OZAPTF: wrong
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
	fn test_xof_parsing() {
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
}