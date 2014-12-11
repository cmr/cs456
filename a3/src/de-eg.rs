extern crate crap_elgamal;
extern crate gmp;
extern crate docopt;
extern crate serialize;

use gmp::Mpz;
use crap_elgamal::{Privkey, Pubkey, decrypt};

#[deriving(Decodable, Show)]
struct Args {
    arg_p: String,
    arg_q: String,
    arg_g: String,
    arg_a: String,
    arg_b: String,
}

const USAGE: &'static str = "Usage: de-eg <p> <q> <g> <a> <b>";

fn fs<S: std::str::Str>(s: S, m: &str) -> Mpz {
    from_str(s.as_slice().trim()).expect(m)
}

fn main() {
    let args: Args = docopt::Docopt::new(USAGE)
        .and_then(|d| d.decode())
        .unwrap_or_else(|e| e.exit());

    let pubkey = Pubkey {
        p: fs(args.arg_p, "p invalid"),
        g: fs(args.arg_g, "g invalid"),
        b: fs(args.arg_b, "b invalid"),
    };

    let privkey = Privkey {
        a: fs(args.arg_a, "a invalid"),
    };

    for line in std::io::stdin().lock().lines() {
        let line = match line {
            Ok(l) => if l.trim() == "" { continue } else { l },
            Err(e) => { println!("Error: {}", e); break; }
        };

        let mut nums = line.split(',');

        let half = fs(nums.next().unwrap(), "half-mask invalid");
        let cipher = fs(nums.next().unwrap(), "cipher invalid");

        let dec = decrypt(&pubkey, &privkey, (half, cipher));
        print!("{}", std::char::from_u32(dec.to_u32().expect("over-large decrypted x!")).expect("non-char point!"));
    }
    println!("");
}
