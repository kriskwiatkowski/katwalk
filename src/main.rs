//use serde::Deserialize;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::str;
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

enum ReadResult {
	ReadMore,
	ReadDone,
	ReadError,
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

impl Signature {
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
		return ReadResult::ReadMore;
	}
}

struct KatIterator {
	reader: BufReader<File>,
}

impl Iterator for KatIterator {
	type Item = Signature;
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

impl KatIterator {
	fn new(f: File) -> KatIterator {
		return KatIterator{reader: BufReader::new(f)};
	}
}


impl KatIterator {
	fn read_kat(&mut self) -> Result<Signature, ReadResult>{
		// TODO: do I really need to use ::default()?
		let mut el: Signature = Default::default();

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

			match Signature::parse_element(&mut el, v[0].trim(), v[1].trim()) {
				ReadResult::ReadError => return Err(ReadResult::ReadError),
				ReadResult::ReadDone => break,
				_ => {continue;},
			}
		}

		return Ok(el);
	}
}

fn main() {
	let file = File::open(&"/home/kris/data/02_Work/pqshield/submissions_round3/Rainbow/KAT/Vc_Classic/PQCsignKAT_1408736.req".to_string());
	let iter = match file {
		Err(_) => panic!("Can't open a file"),
		Ok(f) => KatIterator::new(f),
	};

    for el in iter {
    	println!("> {:?}", el.count);
    }
}
