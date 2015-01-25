use std::sync::mpsc::*;
use std::str::from_utf8;
use std::sync::{Arc, Mutex};
use std::thread::Thread;
use std::io::net::tcp::TcpStream;
use crap_elgamal::{Pubkey, Privkey, State};
use std::mem::transmute;
use std::num::ToPrimitive;
use std::collections::DList;
use {encrypt, decrypt};

enum ClientMsg {
    Closed(TcpStream),
    Data(Arc<Vec<u8>>),
}

struct Hub {
    clients: Vec<Sender<ClientMsg>>,
    new_clients: Receiver<TcpStream>,
    keypair: Arc<Mutex<(Pubkey, Privkey)>>,
}

impl Hub {
    fn mainloop(mut self) {
        // this is some fragile stuff
        let mut handles: DList<Handle<ClientMsg>> = DList::new();
        let mut receivers = DList::new();
        let set = Select::new();
        let mut clients_handle = set.handle(&self.new_clients);
        unsafe { clients_handle.add(); }
        loop {
            let id = set.wait();
            if id == clients_handle.id() {
                // we have a new client, or the acceptor has died.
                match clients_handle.recv() {
                    Ok(mut stream) => {
                        println!("Received connection from {}", stream.peer_name().unwrap());
                        let (tx, rx) = client(stream, self.keypair.clone());
                        self.clients.push(tx);
                        receivers.push_back(rx);
                        // This is pretty insane. We transmute receivers.back to get rid of the
                        // immutable borrow. This is OK here because DList won't go moving the
                        // elements on us.
                        handles.push_back(set.handle(unsafe { transmute(receivers.back().unwrap()) }));
                        unsafe { handles.back_mut().unwrap().add() };
                    },
                    Err(_) => println!("The acceptor has closed, the Hub is on its own.")
                }
            } else {
                let mut hdisconnected = None;
                for (hidx, hand) in handles.iter_mut().enumerate() {
                    if id == hand.id() {
                        match hand.recv() {
                            Ok(ClientMsg::Closed(mut stream)) => println!("{} disconnected", stream.peer_name().unwrap()),
                            Ok(ClientMsg::Data(a)) => {
                                let mut cdisconnected = Vec::new();
                                for (cidx, client) in self.clients.iter().enumerate() {
                                    match client.send(ClientMsg::Data(a.clone())) {
                                        Ok(_) => { },
                                        Err(_) => cdisconnected.push(cidx)
                                    }
                                }

                                for (count, idx) in cdisconnected.iter().enumerate() {
                                    self.clients.swap_remove(idx - count);
                                }
                            },
                            Err(_) => hdisconnected = Some(hidx)
                        }
                    }
                }
                match hdisconnected {
                    Some(idx) => {
                        let mut rest = handles.split_off(idx);
                        unsafe { rest.front_mut().unwrap().remove(); }
                        rest.pop_front();
                        handles.append(&mut rest);
                    },
                    None => { }
                }
            }
        }
    }
}

pub fn new(keypair: (Pubkey, Privkey)) -> Sender<TcpStream> {
    let (tx, rx) = channel();
    let hub = Hub {
        clients: Vec::new(),
        new_clients: rx,
        keypair: Arc::new(Mutex::new(keypair)),
    };
    Thread::spawn(move || hub.mainloop());
    tx
}

fn client(stream: TcpStream, keypair: Arc<Mutex<(Pubkey, Privkey)>>) -> (Sender<ClientMsg>, Receiver<ClientMsg>) {
    // the channel we use to communicate messages that we have received and need to send out to the
    // other clients.
    let (in_tx, in_rx) = channel();
    // the channel the hub uses to tell us to send a message to our client
    let (out_tx, out_rx) = channel();

    Thread::spawn(move || {
        let (in_tx, out_rx, mut stream, keypair) = (in_tx, out_rx, stream, keypair);
        let keyp = keypair.lock().unwrap();

        // initial handshake, send the public key, three NUL-delimited ASCII strings.
        stream.write(&*keyp.0.p.to_string().into_bytes()).unwrap();
        stream.write_u8(0).unwrap();
        stream.write(&*keyp.0.g.to_string().into_bytes()).unwrap();
        stream.write_u8(0).unwrap();
        stream.write(&*keyp.0.b.to_string().into_bytes()).unwrap();
        stream.write_u8(0).unwrap();

        // receive 32 encrypted bytes, the key and IV.
        let mut data = Vec::new();
        let mut nul_count = 0;
        loop {
            let mut buf = [0; 1024];
            let size = stream.read(&mut buf).unwrap();
            for &byte in buf[..size].iter() {
                if byte == 0 { nul_count += 1; }
                if nul_count == 64 {
                    break;
                } else {
                    data.push(byte);
                }
            }
            if nul_count == 64 {
                break;
            }
        }

        let s = State::new();
        let mut vals = data.split(|&b| b == 0).map(|s| from_utf8(s).unwrap());

        let mut key = Vec::new();
        for _ in range(0, 16) {
            let ciph = (::fs(vals.next().unwrap(), "half"), ::fs(vals.next().unwrap(), "cipher"));
            key.push(s.decrypt(&keyp.0, &keyp.1, ciph).to_u8().unwrap());
        }

        let mut iv = Vec::new();
        for _ in range(0, 16) {
            let ciph = (::fs(vals.next().unwrap(), "half"), ::fs(vals.next().unwrap(), "cipher"));
            iv.push(s.decrypt(&keyp.0, &keyp.1, ciph).to_u8().unwrap());
        }

        drop(keyp);
        assert!(vals.next().is_none());
        stream.write_u8(0).unwrap();

        println!("Completed client handshake with {}", stream.peer_name().unwrap());


        // we're good to go!
        let mut from_us: Vec<Arc<Vec<u8>>> = Vec::new();
        loop {
            stream.set_read_timeout(Some(10));
            match stream.read_le_u16() {
                Ok(size) => {
                    stream.set_read_timeout(Some(100));
                    let buf = stream.read_exact(size as usize).unwrap();
                    let buf = Arc::new(decrypt(&*buf, &*key, &*iv).ok().expect("decrypt error!"));
                    from_us.push(buf.clone());
                    in_tx.send(ClientMsg::Data(buf)).unwrap();
                },
                Err(ref e) if e.kind == ::std::io::IoErrorKind::TimedOut => { },
                Err(e) => { println!("Network error in client: {}", e); in_tx.send(ClientMsg::Closed(stream)).unwrap(); break; }
            }
            match out_rx.try_recv() {
                Ok(ClientMsg::Data(msg)) => {
                    match from_us
                        .iter()
                        .position(|a| unsafe { transmute::<&Arc<_>, &usize>(a) == transmute::<&Arc<_>, &usize>(&msg) }) {
                        Some(idx) => { from_us.swap_remove(idx); },
                        None => {
                            stream.write(&*encrypt(&**msg, &*key, &*iv).ok().unwrap()).unwrap();
                        }
                    }
                },
                Ok(_) => println!("Bogus message from hub"),
                Err(_) => { }
            }
        }
    });

    (out_tx, in_rx)
}
