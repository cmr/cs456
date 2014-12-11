#![allow(dead_code, non_snake_case)]

extern crate gmp;
extern crate docopt;
extern crate serialize;

use gmp::Mpz;
use self::Point::{Infinity, Real};

#[deriving(Decodable, Show)]
struct Args {
    arg_p: String,
    arg_A: String,
    arg_B: String,
    arg_G1: String,
    arg_G2: String,
    arg_P1: String,
    arg_P2: String,
    arg_N: String,
}

const USAGE: &'static str = "Usage: de-eceg <p> <A> <B> <G1> <G2> <P1> <P2> <N>";

#[deriving(Show, Eq, PartialEq, Clone)]
struct RealPoint {
    x: Mpz,
    y: Mpz
}

#[deriving(Show, Eq, PartialEq, Clone)]
enum Point {
    Infinity,
    Real(RealPoint),
}

impl Point {
    fn rp(self) -> RealPoint {
        match self {
            Infinity => panic!(),
            Real(rp) => rp
        }
    }
}

// y^2 = x^3 + ax + b (mod q)
#[deriving(Show)]
struct EC {
    a: Mpz,
    b: Mpz,
    q: Mpz,
}

// a^b (mod m)
fn powm(a: &Mpz, b: u32, m: &Mpz) -> Mpz {
    a.powm(&mpz(b), m)
}

fn mpz(u: u32) -> Mpz {
    FromPrimitive::from_u32(u).unwrap()
}

impl EC {
    fn wrap(&self, p: Point) -> Point {
        match p {
            Infinity => Infinity,
            Real(RealPoint { x, y }) => Real(RealPoint { x: x.modulus(&self.q), y: y.modulus(&self.q) })
        }
    }

    fn add(&self, p: Point, q: Point) -> Point {
        // ensure they are (mod q)
        let p = self.wrap(p);
        let q = self.wrap(q);

        let (p_, q_) = (p.clone(), q.clone());
        match (p, q) {
            (Infinity, q) => q,
            (p, Infinity) => p,
            (Real(RealPoint { x: x1, y: y1 }), Real(RealPoint { x: x2, y: y2 })) => {
                let res = if x1 != x2 {
                    let m = ((y2 - y1) * (x2 - x1).invert(&self.q).unwrap());
                    let x3 = (powm(&m, 2, &self.q) - x1 - x2);
                    let y3 = m * (x1 - x3) - y1;
                    self.wrap(Real(RealPoint { x: x3, y: y3 }))
                } else if y1 == (-y2).modulus(&self.q) {
                    Infinity
                } else {
                    // point doubling
                    let m = (mpz(3) * x1 * x1 + self.a) * (mpz(2) * y1).invert(&self.q).unwrap();
                    let x3 = (m * m) - (mpz(2) * x1);
                    let y3 = (m * (x1 - x3)) - y1;
                    self.wrap(Real(RealPoint { x: x3, y: y3 }))
                };
                res
            }
        }
    }

    fn mul(&self, n: Mpz, p: Point) -> Point {
        let (n_, p_) = (n.clone(), p.clone());
        let res = if n == mpz(0) {
            Infinity
        } else if n.modulus(&mpz(2)) == mpz(0) {
            let res = self.mul(n / mpz(2), p);
            self.add(res.clone(), res)
        } else {
            self.add(p.clone(), self.mul(n-mpz(1), p))
        };
        res
    }

    fn neg(&self, p: Point) -> Point {
        match p {
            Infinity => Infinity,
            Real(RealPoint { x, y }) => Real(RealPoint { x: x, y: self.q - y })
        }
    }

}

struct Pubkey<'a> {
    ec: &'a EC,
    g: Point,
    p: Point,
}

struct Seckey<'a> {
    ec: &'a EC,
    n: Mpz,
}

fn encrypt(key: &Pubkey, message: Point) -> (Point, Point) {
    let m = gmp::RandState::new().urandom(&key.ec.q);
    let alpha = key.ec.mul(m.clone(), message.clone());
    let omega = key.ec.mul(m, key.p.clone());
    let y = key.ec.add(message.clone(), omega);
    (y, alpha)
}

fn decrypt(privkey: &Seckey, (y, alpha): (Point, Point)) -> Point {
    let ec = privkey.ec;
    // y - N * a
    ec.wrap(ec.add(y, ec.neg(ec.mul(privkey.n.clone(), alpha))))
}

fn fs<S: std::str::Str>(s: S, m: &str) -> Mpz {
    from_str(s.as_slice()).expect(m)
}

fn main() {
    let args: Args = docopt::Docopt::new(USAGE)
        .and_then(|d| d.decode())
        .unwrap_or_else(|e| e.exit());

    let ec = EC {
        a: fs(args.arg_A, "A invalid"),
        b: fs(args.arg_B, "B invalid"),
        q: fs(args.arg_p, "p invalid"),
    };

    let g = ec.wrap(Real(RealPoint {
        x: fs(args.arg_G1, "G1 invalid"),
        y: fs(args.arg_G2, "G2 invalid"),
    }));

    let p = ec.wrap(Real(RealPoint {
        x: fs(args.arg_P1, "P1 invalid"),
        y: fs(args.arg_P2, "P2 invalid"),
    }));

    let n = fs(args.arg_N, "N invalid").modulus(&ec.q);

    let _pubkey = Pubkey {
        ec: &ec,
        g: g,
        p: p
    };
    let privkey = Seckey {
        ec: &ec,
        n: n
    };

    for line in std::io::stdin().lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => { println!("Error: {}", e); break; }
        };

        let mut nums = line.split(' ');

        let x1 = fs(nums.next().unwrap(), "x1 invalid");
        let y1 = fs(nums.next().unwrap(), "y1 invalid");
        let x2 = fs(nums.next().unwrap(), "x2 invalid");
        let y2 = fs(nums.next().unwrap(), "y2 invalid");

        let y = Real(RealPoint { x: x1, y: y1 });
        let alpha = Real(RealPoint { x: x2, y: y2});

        let dec = decrypt(&privkey, (y, alpha)).rp();
        print!("{}", std::char::from_u32(dec.x.to_u32().expect("over-large decrypted x!")).expect("non-char point!"));
    }
    println!("");
}
