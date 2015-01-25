use std;
use {encrypt, decrypt};
use std::rand::{Rng, thread_rng};
use std::io::net::tcp::TcpStream;
use std::sync::mpsc::{Sender, Receiver, channel};
use gmp::Mpz;
use crap_elgamal::{State, Pubkey, mpz};

pub fn connect(server: String, secret: Option<String>) -> Sender<Vec<u8>> {
    let (tx, rx) = channel();
    std::thread::Thread::spawn(move || network(server, secret, rx));
    tx
}

fn network(server: String, secret: Option<String>, rx: Receiver<Vec<u8>>) {
    let mut secret = match secret {
        Some(s) => {
            if s.len() != 16 {
                println!("WARNING: The secret key should be exactly 16 bytes!");
                println!("         If it is short, the extra bytes will be 0s");
                println!("         If it is long, the rest will be truncated");
            }
            let mut s = s.into_bytes();
            s.truncate(16);
            for _ in range(0, 16 - s.len()) {
                s.push(0);
            }
            s
        },
        None => {
            let mut v = [0; 16];
            thread_rng().fill_bytes(&mut v);
            v.iter().map(|&b| b).collect()
        }
    };

    let mut sock = TcpStream::connect(&*server).unwrap();
    // get the server's public key, three NUL-delimited ASCII strings.
    let mut data: Vec<u8> = Vec::new();
    let mut nul_count = 0;
    let mut stdout = std::io::stdio::stdout_raw();
    let mut buf = [0; 1024];

    loop {
        let size = sock.read(&mut buf).unwrap();
        for &byte in buf[..size].iter() {
            if byte == 0 { nul_count += 1; }
            if nul_count == 3 {
                break;
            } else {
                data.push(byte);
            }
        }
        if nul_count == 3 {
            break;
        }
    }

    let mut vals = data.split(|&b| b == 0);

    let p: Mpz = std::str::from_utf8(vals.next().unwrap()).unwrap().parse().unwrap();
    let g: Mpz = std::str::from_utf8(vals.next().unwrap()).unwrap().parse().unwrap();
    let b: Mpz = std::str::from_utf8(vals.next().unwrap()).unwrap().parse().unwrap();

    let pubkey = Pubkey { p: p, g: g, b: b };
    let mut s = State::new();

    let mut iv = [0u8; 16];
    thread_rng().fill_bytes(&mut iv);
    secret.extend(iv.iter().map(|&b| b));

    // slow, but easy. send each byte of the key/IV separately.
    for byte in secret.iter() {
        let (half, cipher) = s.encrypt(&pubkey, mpz(*byte as u32));
        sock.write(&*half.to_string().into_bytes()).unwrap();
        sock.write_u8(0).unwrap();
        sock.write(&*cipher.to_string().into_bytes()).unwrap();
        sock.write_u8(0).unwrap();
    }

    secret.truncate(16); // drop the iv

    // wait for acknowledgement
    sock.read_u8().unwrap();
    println!("Done handshake! Chat is now encrypted...");
    stdout.write(b"> ").unwrap();

    // mainloop
    loop {
        sock.set_read_timeout(Some(10));
        match sock.read(&mut buf) {
            Ok(size) => {
                stdout.write(b"\r< ").unwrap();
                stdout.write(&*decrypt(&buf[..size], &*secret, &iv).ok().unwrap()).unwrap();
                stdout.write(b"> ").unwrap();
            },
            Err(ref e) if e.kind == ::std::io::IoErrorKind::TimedOut => { },
            Err(e) => { println!("Network error: {}", e); break; }
        }
        match rx.try_recv() {
            Ok(s) => {
                let enc = encrypt(&*s, &*secret, &iv).ok().unwrap();
                if enc.len() > <u16 as std::num::Int>::max_value() as usize {
                    println!("Not sending over-long message...");
                    continue;
                }
                sock.write_le_u16(enc.len() as u16).unwrap();
                sock.write(&*enc).unwrap();
            },
            Err(_) => { }
        }
    }
}
