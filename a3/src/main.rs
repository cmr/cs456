#![allow(dead_code, non_snake_case)]

extern crate gmp;
extern crate docopt;
extern crate serialize;

use gmp::Mpz;

#[deriving(Decodable, Show)]
struct Args {
    arg_p: String,
    arg_q: String,
    arg_g: String,
    arg_a: String,
    arg_b: String,
}

const USAGE: &'static str = "Usage: de-eg <p> <q> <g> <a> <b>";

struct Pubkey {
    p: Mpz,
    g: Mpz,
    b: Mpz,
}

struct Privkey {
    a: Mpz,
}

fn encrypt(key: &Pubkey, message: Mpz) -> (Mpz, Mpz) {
    let k = gmp::RandState::new().urandom(&key.p);
    let half = key.g.powm(&k, &key.p);
    let full = key.b.powm(&k, &key.p);
    let cipher = (message * full).modulus(&key.p);
    (half, cipher)
}

fn decrypt(key: &Pubkey, privkey: &Privkey, (half, cipher): (Mpz, Mpz)) -> Mpz {
    let full = half.powm(&privkey.a, &key.p);
    (cipher * full.invert(&key.p).unwrap()).modulus(&key.p)
}

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
