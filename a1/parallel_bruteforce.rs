//! A dirt-simple brute forcer for my crypto assignment, using a monoalphabetic cipher.

extern crate libc;
extern crate time;

use std::sync::atomic::{AtomicUint, Relaxed, INIT_ATOMIC_UINT};

use std::ascii::AsciiCast;

static CIPHER: &'static str = "
GOXJPTMFMFTRGUICNGYGUFUIBGYNCN
FUXJPTMFMFTRGUICNFZBTGUCFECJOC
NFOGMYCTYYGIUQFUCGUJPMLMXZCJIM
TZNXLJPMYFCNGYTYYGIUQFUCWTYYPZ
ZJYFRBXZJYCFRCWJRTXYHFOJMFCNFF
URJOCNFFGINCNQJUCNGUCNFXFTMJOC
WFUCXOJPMCFFUTYXJPNTSFRGYLJSFM
FRHXLMTLVGUICNGYTYYGIUQFUCGCWT
YFULMXZCFRPYGUITYGQZBFQJUJTBZN
THFCGLYPHYCGCPCGJULGZNFMOJMCNG
YTYYGIUQFUCYPHQGCCNFOJBBJWGUIG
CFQYHXFQTGBTCBFTYCHFOJMFCNFCNG
MRWFFVJOCNFOJBBJWGUIQJUCNOGMYC
ZMJSGRFCNFYPHYCGCPCGJUCTHBFPYF
ROJMCNFBFCCFMYZMFYFUCGUCNFZBTG
UCFECYFLJURRFYLMGHFNJWXJPHMJVF
CNGYLGZNFMCNGMRRFYLMGHFTURGQZB
FQFUCXJPMJWULGZNFMYXYCFQOJMFUL
MXZCGUITURRFLMXZCGUICFECOGBFYX
JPQTXPYFTUXZMJIMTQQGUIBTUIPTIF
JOXJPMLNJGLFTYZTMCJOCNFYPHQGYY
GJUOJMCNFCNGMRZTMCZMJSGRFTBGSF
RFQJUYCMTCGJUJOXJPMYXYCFQOJPMC
NWMGCFTYNJMCMFZJMCJUCNFYCTCGYC
GLTBBFCCFMOMFDPFULGFYJOFUIBGYN
GULJQZTMGYJUWGCNJCNFMBTUIPTIFY
RFCFMQGUFGOFUIBGYNGYLJUYGRFMFR
CNFBFTYCMTURJQJOQJYCUTCPMTBBTU
IPTIFY
";

static mut PERMS_DONE: AtomicUint = INIT_ATOMIC_UINT;

fn do_perm(letters: Vec<char>) {
    let mut s = String::with_capacity(CIPHER.len());
    for &c in CIPHER.as_bytes().iter() {
            if c.to_ascii().is_alphabetic() {
                s.push_char(letters[(c - 'A' as u8) as uint]);
            } else {
                s.push_char(std::char::from_u32(c as u32).unwrap());
            }
    }

    unsafe { PERMS_DONE.fetch_add(1, Relaxed); }

    if s.as_slice().contains("crypto") {
        println!("{}", s);
        unsafe { libc::exit(0) };
    }
}

fn main() {
    let txs = range(0i, 8).map(|_| {
        let (tx, rx) = std::comm::sync_channel(1000);
        spawn(proc() {
            loop {
                let letters = rx.recv();
                do_perm(letters);
            }
        });
        tx
    }).collect::<Vec<SyncSender<Vec<char>>>>();

    let letters = vec!(
        'm',
        'n',
        'o',
        'p',
        'q',
        'r',
        's',
        't',
        'u',
        'v',
        'w',
        'x',
        'y',
        'z',
        'a',
        'b',
        'c',
        'd',
        'e',
        'f',
        'g',
        'h',
        'i',
        'j',
        'k',
        'l',
    );

    let mut txs = txs.iter().cycle();
    let mut old_count = 0;
    let mut old_time = 0;

    for key in letters.as_slice().permutations() {
        let ct = unsafe { PERMS_DONE.load(Relaxed) };
        let tm = time::precise_time_ns();
        if tm - old_time > 1_000_000_000 {
            let diff = ct - old_count;
            println!("Done {} in the past {} ns...", diff, tm - old_time);
            old_count = diff + old_count;
            old_time = tm;
        }

        txs.next().unwrap().send(key);
    }
    println!("Done generating permutations!");
}
