#![allow(dead_code, non_snake_case)]

extern crate gmp;

use gmp::Mpz;

pub struct Pubkey {
    pub p: Mpz,
    pub g: Mpz,
    pub b: Mpz,
}

pub struct Privkey {
    pub a: Mpz,
}

pub fn encrypt(key: &Pubkey, message: Mpz) -> (Mpz, Mpz) {
    let k = gmp::RandState::new().urandom(&key.p);
    let half = key.g.powm(&k, &key.p);
    let full = key.b.powm(&k, &key.p);
    let cipher = (&message * &full).modulus(&key.p);
    (half, cipher)
}

pub fn decrypt(key: &Pubkey, privkey: &Privkey, (half, cipher): (Mpz, Mpz)) -> Mpz {
    let full = half.powm(&privkey.a, &key.p);
    (&cipher * &full.invert(&key.p).unwrap()).modulus(&key.p)
}
