#![allow(unstable, dead_code)]

extern crate crap_elgamal;
extern crate gmp;
extern crate docopt;
extern crate "rustc-serialize" as rustc_serialize;
extern crate crypto;

use gmp::Mpz;
use crap_elgamal::State;
use std::io::net::tcp::*;
use std::io::{Listener, Acceptor};
use crypto::{symmetriccipher, buffer, aes, blockmodes};
use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};

mod daemon;
mod client;

#[derive(RustcDecodable, Debug)]
struct Args {
    cmd_server: bool,
    cmd_client: bool,
    flag_keysize: Option<u64>,
    flag_port: Option<u16>,
    flag_secret: Option<String>,
    arg_server: String,
}

const USAGE: &'static str = "
Insecure, encrypted chat server/client.

Usage: chat server [--port=<port>] [--keysize=<bits>]
       chat client <server> [--secret=<string>]
";

fn fs<S: std::str::Str>(s: S, m: &str) -> Mpz {
    use std::str::FromStr;
    FromStr::from_str(s.as_slice().trim()).expect(m)
}

fn main() {
    let args: Args = docopt::Docopt::new(USAGE)
        .and_then(|d| d.decode())
        .unwrap_or_else(|e| e.exit());

    if args.cmd_server {
        let mut s = State::new();
        let len = args.flag_keysize.unwrap_or(512);
        println!("Generating {}-bit keys...", len);
        let keypair = s.genkey(len);
        println!("Done!");

        let mut sock = TcpListener::bind(("0.0.0.0", args.flag_port.unwrap_or(0))).unwrap();
        let addr = sock.socket_name().unwrap();
        println!("Server listening on: {}", addr);

        let hub = daemon::new(keypair);
        for conn in sock.listen().incoming() {
            match conn {
                Ok(conn) => { hub.send(conn).unwrap(); },
                Err(e) => println!("Accept error: {}", e),
            }
        }
    } else if args.cmd_client {
        let tx = client::connect(args.arg_server, args.flag_secret);
        for line in std::io::stdio::stdin().lock().lines() {
            tx.send(line.unwrap().into_bytes()).unwrap();
            print!("> ");
        }
    }
}

// from rust-crypto examples.

fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor = aes::cbc_encryptor(
        aes::KeySize::KeySize128,
        key,
        iv,
        blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.push_all(write_buffer.take_read_buffer().take_remaining());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    Ok(final_result)
}

fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize128,
        key,
        iv,
        blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.push_all(write_buffer.take_read_buffer().take_remaining());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    Ok(final_result)
}
