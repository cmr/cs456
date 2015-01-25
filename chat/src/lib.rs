#![allow(unstable, dead_code, non_snake_case)]

extern crate gmp;
extern crate libc;

use gmp::Mpz;
use std::ops::Mul;

#[derive(Show)]
pub struct Pubkey {
    pub p: Mpz,
    pub g: Mpz,
    pub b: Mpz,
}

#[derive(Show)]
pub struct Privkey {
    pub a: Mpz,
}

pub struct State {
    pub gs: gmp::RandState
}

pub fn mpz(u: u32) -> Mpz {
    std::num::FromPrimitive::from_u32(u).unwrap()
}

impl State {
    pub fn new() -> State {
        let mut s = State {
            gs: gmp::RandState::new()
        };
        s.gs.seed_ui(std::rand::random());
        s
    }

    fn random_prime(&mut self, bits: u64, confidence: i32) -> Mpz {
        let mut candidate = self.gs.urandom_2exp(bits);
        while candidate.millerrabin(confidence as libc::c_int) == 0 {
            candidate = self.gs.urandom_2exp(bits);
        }
        candidate
    }

    pub fn genkey(&mut self, bits: u64) -> (Pubkey, Privkey) {
        let (one, two) = (mpz(1), mpz(2));
        let mut q = self.random_prime(bits - 1, 40);
        let mut p = &two * &q + &one;
        while p.millerrabin(20) == 0 {
            q = self.random_prime(bits - 1, 40);
            p = &two * &q + &one;
        }
        // p is a safe prime, and p-1 will be the order of our group. find g:
        let mut g = self.gs.urandom(&p);
        while &g.powm(&q, &p) == &one || &g.powm(&two, &p) == &one {
            g = self.gs.urandom(&p);
        }
        let a = self.gs.urandom(&p);
        let b = g.powm(&a, &p);
        (Pubkey { p: p, g: g, b: b }, Privkey { a: a})
    }

    pub fn encrypt(&mut self, key: &Pubkey, message: Mpz) -> (Mpz, Mpz) {
        let k = self.gs.urandom(&key.p);
        let half = key.g.powm(&k, &key.p);
        let full = key.b.powm(&k, &key.p);
        let imdt = (&message).mul(full);
        let cipher = imdt.modulus(&key.p);
        (half, cipher)
    }

    pub fn decrypt(&self, key: &Pubkey, privkey: &Privkey, (half, cipher): (Mpz, Mpz)) -> Mpz {
        let full = half.powm(&privkey.a, &key.p);
        (cipher * full.invert(&key.p).unwrap()).modulus(&key.p)
    }
}

#[cfg(test)]
mod test {
    use super::State;
    #[test]
    fn smoke() {
        let mut s = State::new();
        let (pu, pr) = s.genkey(256);
        for _ in range(0, 256) {
            let msg = s.gs.urandom(&pu.p);
            let msg_ = s.encrypt(&pu, msg.clone());
            let dec = s.decrypt(&pu, &pr, msg_);
            assert_eq!(msg, dec);
        }
    }
}
