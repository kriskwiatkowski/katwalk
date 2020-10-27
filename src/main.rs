//use serde::Deserialize;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::str;
use std::marker;
use hex::FromHex;

#[derive(Debug, Default)]
struct Signature {
	count: usize,
	seed: Vec<u8>,
	mlen: usize,
	msg: Vec<u8>,
	pk: Vec<u8>,
	sk: Vec<u8>,
	smlen: usize,
	sm: Vec<u8>
}

#[derive(Debug, Default)]
struct KeyEncapsMech {
	count: usize,
	seed: Vec<u8>,
	pk: Vec<u8>,
	sk: Vec<u8>,
	ct: Vec<u8>,
	ss: Vec<u8>
}

// Possible results of reading a single KAT from file
enum ReadResult {
	ReadMore,
	ReadDone,
	ReadError,
}

// Each algoritym type needs to implement algorithm-specific KAT parsing
trait AlgType {
	fn parse_element(el: &mut Self, k: &str, v: &str) -> ReadResult;
}

struct KatIterator<T: AlgType> {
	reader: BufReader<File>,
    phantom: marker::PhantomData<T>,
}

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

// KatIterator iterates over KAT tests in a file
impl<T: AlgType + Default> Iterator for KatIterator<T> {
	type Item = T;
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

impl<T: AlgType + Default> KatIterator<T> {
	fn new(f: File) -> KatIterator<T> {
		KatIterator{
			reader: BufReader::new(f),
			phantom: marker::PhantomData
		}
	}

	fn read_kat(&mut self) -> Result<T, ReadResult>{
		let mut el: T = Default::default();

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

			match T::parse_element(&mut el, v[0].trim(), v[1].trim()) {
				ReadResult::ReadError => return Err(ReadResult::ReadError),
				ReadResult::ReadDone => break,
				_ => {continue;},
			}
		}

		return Ok(el);
	}
}

// Implement AlgType for signature
impl AlgType for Signature {
	fn parse_element(el: &mut Signature, k: &str, v: &str) -> ReadResult {
		match k {
			"count" => el.count = to_uint(v),
			"seed" => el.seed = to_u8arr(v),
			"mlen" => el.mlen = to_uint(v),
			"msg" => el.msg = to_u8arr(v),
			"pk" => el.pk = to_u8arr(v),
			"sk" => el.sk = to_u8arr(v),
			"smlen" => el.smlen = to_uint(v),
			"sm" => {
				el.sm = to_u8arr(v);
				// Last item for the record
				return ReadResult::ReadDone;
			}
			_ => return ReadResult::ReadError,
		};
		ReadResult::ReadMore
	}
}

// Implement AlgType for signature
impl AlgType for KeyEncapsMech {
	fn parse_element(el: &mut KeyEncapsMech, k: &str, v: &str) -> ReadResult {
		match k {
			"count" => el.count = to_uint(v),
			"seed" => el.seed = to_u8arr(v),
			"pk" => el.pk = to_u8arr(v),
			"sk" => el.sk = to_u8arr(v),
			"ct" => el.ct = to_u8arr(v),
			"ss" => {
				el.ss = to_u8arr(v);
				// Last item for the record
				return ReadResult::ReadDone;
			}
			_ => return ReadResult::ReadError,
		};
		ReadResult::ReadMore
	}
}

fn main() {
	//let file = File::open(&"/home/kris/data/02_Work/pqshield/submissions_round3/Rainbow/KAT/Vc_Classic/PQCsignKAT_1408736.req".to_string());
	let file = File::open(&"/home/kris/data/02_Work/pqshield/submissions_round3/SABER/KAT/FireSaber/PQCkemKAT_3040.rsp".to_string());
	let iter = match file {
		Err(_) => panic!("Can't open a file"),
		//Ok(f) => KatIterator::<Signature>::new(f),
		Ok(f) => KatIterator::<KeyEncapsMech>::new(f),
	};

    for el in iter {
    	println!("> {:?}", el);
    }
}
