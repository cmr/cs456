#![feature(plugin)]

extern crate gmp;
#[plugin] #[no_link] extern crate docopt_macros;
extern crate "rustc-serialize" as rustc_serialize;
extern crate docopt;
extern crate serialize;

use gmp::Mpz;
use std::collections::HashMap;
use std::str::FromStr;
use std::num::{FromPrimitive};


docopt!(Args, "Usage: de-rsa <e> <n>");

fn main() {
    let args: Args = Args::docopt().decode().unwrap();
    let e: Mpz = FromStr::from_str(args.arg_e.as_slice().trim()).expect("e is invalid!");
    let n: Mpz = FromStr::from_str(args.arg_n.as_slice().trim()).expect("n is invalid!");

    let mut stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    let mut map = HashMap::new();

    for i in range(0, 255) {
        let val: Mpz = FromPrimitive::from_int(i).expect("Couldn't make an Mpz for a byte!");
        map.insert(val.powm(&e, &n).to_str_radix(10), i);
    }

    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let val = map.get(line.as_slice().trim()).expect("Found non-byte!");
        stdout.write_u8(*val as u8);
    }
}
