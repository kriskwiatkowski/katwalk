//use serde::Deserialize;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::str;
use hex::FromHex;

#[derive(Debug)]
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

struct SigKatIter {
	reader: BufReader<File>,
}

enum ReadResult {
	ReadDone,
	ReadError,
}

//TODO: generic?
fn atou(s: &str) -> usize {
	if s.is_empty() {
		return 0;
	}
	match s.parse() {
		Ok(v) => v,
		Err(_) => 0
	}
}

fn stohex(s: &str) -> Vec<u8> {
	match Vec::from_hex(s) {
		Ok(v) => v,
		// Panic here is good, because when execution is
		// here it means all checks should be already done.
		Err(e) => panic!(e)
	}
}

// TODO: how to do default initalization better
impl Default for Signature {
	fn default() -> Self {
	    Signature {
	    	count: 0,
			seed: Vec::<u8>::new(),
			mlen: 0,
			msg: Vec::<u8>::new(),
			pk: Vec::<u8>::new(),
			sk: Vec::<u8>::new(),
			smlen: 0,
			sm: Vec::<u8>::new(),
	    }
	}
}

impl Iterator for SigKatIter {
	type Item = Signature;
	fn next(&mut self) -> Option<Self::Item> {
		match self.read_kat() {
			Ok(v) => return Some(v),
			Err(e) => match e {
				ReadResult::ReadDone => return None,
				ReadResult::ReadError=> panic!("Error occured while reading"),
			}
		};
	}
}

impl SigKatIter {
	pub fn new(f: File) -> SigKatIter {
		return SigKatIter{reader: BufReader::new(f)};
	}

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

			let valtxt = v[1].trim();
			match v[0].trim() {
				"count" => el.count = atou(valtxt),
				"seed" => el.seed = stohex(valtxt),
				"mlen" => el.mlen = atou(valtxt),
				"msg" => el.msg = stohex(valtxt),
				"pk" => el.pk = stohex(valtxt),
				"sk" => el.sk = stohex(valtxt),
				"smlen" => el.smlen = atou(valtxt),
				// Last item for the record
				"sm" => { el.sm = stohex(valtxt); break},
				_ => return Err(ReadResult::ReadError)
			};
		}

		return Ok(el);
	}
}

fn main() {
	let file = File::open(&"/home/kris/data/02_Work/pqshield/submissions_round3/Rainbow/KAT/Vc_Classic/PQCsignKAT_1408736.req".to_string());
	let iter = match file {
		Err(_) => panic!("Can't open a file"),
		Ok(f) => SigKatIter::new(f),
	};

    for el in iter {
    	println!("{:?}", el.count);
    }
}
