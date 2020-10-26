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
	use std::fs::File;
	use std::io::prelude::*;
	use std::io::BufReader;
	use std::str;

	#[derive(Copy, Clone)]
	pub enum AlgType {
		AlgSignature,
		AlgKem,
		AlgHash
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

	pub struct Kat {
		pub scheme_type : AlgType,
		pub scheme_id: u32,
		pub kat_file: &'static str,
	}

	pub struct KatReader {
		reader: BufReader<File>,
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

	// Type used by iterator.
	#[derive(Debug, Default)]
	pub struct TestVector {
		pub scheme_id: u32,
		pub sig: Signature,
		pub kem: Kem,
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
			    AlgType::AlgHash => ReadResult::ReadDone,
			}
		}
	}

	impl KatReader {
		pub fn new(f: File, t: AlgType, scheme_id: u32) -> KatReader {
		        KatReader{
		        	alg_type: t,
					reader: BufReader::new(f),
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
	impl Iterator for KatReader {
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
