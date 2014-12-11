use std::rand::Rng;

pub struct XorShift64Star {
    state: u64
}

impl Rng for XorShift64Star {
    fn next_u32(&mut self) -> u32 {
        // this is probably fine, I don't believe this generator has any bias.
        // throw away the high bits
        self.next_u64() as u32
    }

    // from http://arxiv.org/pdf/1402.6246v2.pdf
    fn next_u64(&mut self) -> u64 {
        self.state ^= self.state >> 12;
        self.state ^= self.state << 25;
        self.state ^= self.state >> 27;

        return self.state * 2685821657736338717;
    }
}

/// Encrypt (and decrypt) a message using a key.
pub fn crypt(key: u64, mut text: Vec<u8>) -> Vec<u8> {
    for i in range(0, 8) {
        assert!(((key >> 8*i) & 0xFF) != 0);
    }

    let mut rng = XorShift64Star { state: key };

    for i in range(0, 8 - (text.len() % 8) % 8) {
        text.push(0);
    }

    let mut output = std::io::MemWriter::with_capacity(text.len());

    assert!(text.len() % 8 == 0);

    for chunk in text.as_slice().chunks(8) {
        let mut rd = std::io::BufReader::new(chunk);
        let val = rd.read_le_u64().unwrap();
        output.write_le_u64(rng.next_u64() ^ val);
    }

    output.unwrap()
}

fn main() {
    let key = std::io::MemReader::new(std::os::args().into_iter().nth(1).unwrap().into_bytes()).read_le_u64().unwrap();
    let input = std::io::stdin().read_to_end().unwrap();
    std::io::stdout().write(crypt(key, input).as_slice());
}
