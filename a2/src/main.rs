#![feature(phase)]

extern crate gmp;
#[phase(plugin)] extern crate docopt_macros;
extern crate docopt;
extern crate serialize;

use gmp::Mpz;
use docopt::FlagParser;
use std::collections::HashMap;

docopt!(Args, "Usage: de-rsa <e> <n>")

fn main() {
    let args: Args = FlagParser::parse().unwrap();
    let e: Mpz = from_str(args.arg_e.as_slice().trim()).expect("e is invalid!");
    let n: Mpz = from_str(args.arg_n.as_slice().trim()).expect("n is invalid!");

    let mut stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    let mut map = HashMap::new();

    for i in range(0, 255i) {
        let val: Mpz = FromPrimitive::from_int(i).expect("Couldn't make an Mpz for a byte!");
        map.insert(val.powm(&e, &n).to_string(), i);
    }

    for line in stdin.lines() {
        let line = line.unwrap();
        let val = map.find_equiv(&line.as_slice().trim()).expect("Found non-byte!");
        stdout.write_u8(*val as u8);
    }
}
