// spicy cic between two processes over one tcp connection, through the party layer of the c api
// M = N = 2^LOG_SIZE and every third element is shared
// each party prints its phase times and the data it sent
// usage: spicy_net receiver|sender ADDR:PORT LOG_SIZE

use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

use rand::RngCore;
use spicy_ffi::party::{fresh_rng, recommended_n_g, ReceiverParty, SenderParty};

struct Chan {
    r: BufReader<TcpStream>,
    w: BufWriter<TcpStream>,
    sent: u64,
    recv: u64,
}

impl Chan {
    fn new(s: TcpStream) -> Self {
        s.set_nodelay(true).expect("TCP_NODELAY");
        Chan { r: BufReader::new(s.try_clone().expect("clone stream")), w: BufWriter::new(s), sent: 0, recv: 0 }
    }
    fn send(&mut self, b: &[u8]) {
        self.w.write_all(&(b.len() as u64).to_le_bytes()).unwrap();
        self.w.write_all(b).unwrap();
        self.w.flush().unwrap();
        self.sent += 8 + b.len() as u64;
    }
    fn recv(&mut self) -> Vec<u8> {
        let mut l = [0u8; 8];
        self.r.read_exact(&mut l).unwrap();
        let mut v = vec![0u8; u64::from_le_bytes(l) as usize];
        self.r.read_exact(&mut v).unwrap();
        self.recv += 8 + v.len() as u64;
        v
    }
}

// element i of a party's set, every third index is shared
fn element(party: &str, i: usize) -> Vec<u8> {
    if i % 3 == 0 { format!("shared-{i}") } else { format!("{party}-{i}") }.into_bytes()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    assert!(a.len() == 4, "usage: spicy_net (sender|receiver) ADDR:PORT LOG_SIZE");
    let (role, addr, lg) = (a[1].as_str(), a[2].as_str(), a[3].parse::<u32>().expect("LOG_SIZE"));
    let n = 1usize << lg;
    let n_g = recommended_n_g(n, n).unwrap();
    let expected = n.div_ceil(3);
    let mut rng = fresh_rng();
    let threads = rayon_threads();
    let s = |d: std::time::Duration| d.as_secs_f64();

    match role {
        "receiver" => {
            let (stream, _) = TcpListener::bind(addr).expect("bind").accept().expect("accept");
            let mut ch = Chan::new(stream);
            ch.recv();
            ch.send(&[1]);
            let (sent0, recv0) = (ch.sent, ch.recv);

            let t0 = Instant::now();
            let items: Vec<Vec<u8>> = (0..n).map(|i| element("r", i)).collect();
            let party = ReceiverParty::register(b"receiver", &items, n_g, &mut rng).unwrap();
            let reg_comp = t0.elapsed();
            ch.send(party.registration());
            let reg_s = ch.recv();
            let commit_wall = t0.elapsed();
            let commit_bytes = (ch.sent - sent0) + (ch.recv - recv0);

            let t1 = Instant::now();
            let mut sid = [0u8; 16];
            rng.fill_bytes(&mut sid);
            ch.send(&sid);
            // verify pi_pow while the sender computes its response
            let (sender, tv) = party.verify_sender(&reg_s, n, n_g).unwrap();
            let resp = ch.recv();
            let wait = t1.elapsed();
            let (idx, t) = party.finish_verified(&sender, &resp, &sid).unwrap();
            let inter_wall = t1.elapsed();
            let total = t0.elapsed();
            ch.send(&(idx.len() as u64).to_le_bytes());
            let inter_bytes = (ch.sent - sent0) + (ch.recv - recv0) - commit_bytes - 8 - 8;

            let ms = |d: std::time::Duration| s(d) * 1e3;
            let ns_ms = |x: u64| x as f64 / 1e6;
            let mb = |b: u64| b as f64 / (1024.0 * 1024.0);
            let ok = idx.len() == expected;
            println!("SPICy CIC, receiver, set size 2^{lg} = {n}, n_g = {n_g}, threads = {threads}");
            println!("Receiver commit phase time: {:.2} ms (computation {:.2} ms)", ms(commit_wall), ms(reg_comp));
            println!("Receiver committed data size: {:.4} MB", mb(party.registration().len() as u64));
            println!("Sender committed data size: {:.4} MB", mb(reg_s.len() as u64));
            println!("Receiver verification of the sender's registration: {:.2} ms", ns_ms(tv.verify_registration_ns));
            println!("Receiver pair setup time: {:.2} ms", ns_ms(t.pair_setup_ns));
            println!("Receiver intersection time: {:.2} ms", ns_ms(t.intersection_ns));
            println!("Receiver computation after registration: {:.2} ms", ns_ms(tv.total_ns + t.total_ns));
            println!("Intersection phase time: {:.2} ms (waiting for the sender {:.2} ms)", ms(inter_wall), ms(wait));
            println!("Sender response size: {:.4} MB", mb(resp.len() as u64));
            println!("Intersection size: {} (expected {expected}, {})", idx.len(), if ok { "correct" } else { "wrong" });
            println!("Whole protocol time: {:.2} ms", ms(total));
            println!("Total communication size sender and receiver: {:.4} MB (commit {:.4} MB, intersection {:.4} MB)", mb(commit_bytes + inter_bytes), mb(commit_bytes), mb(inter_bytes));
            if idx.len() != expected {
                std::process::exit(1);
            }
        }
        "sender" => {
            let mut ch = Chan::new(TcpStream::connect(addr).expect("connect"));
            ch.send(&[1]);
            ch.recv();

            let t0 = Instant::now();
            let items: Vec<Vec<u8>> = (0..n).map(|i| element("s", i)).collect();
            let party = SenderParty::register(b"sender", &items, n_g, &mut rng).unwrap();
            let reg_comp = t0.elapsed();
            // send reg_S first so the receiver verifies pi_pow while the sender proves pi_tok
            ch.send(party.registration());
            let t = Instant::now();
            party.precompute_tokens(1, &mut rng).unwrap();
            let tokens = t.elapsed();
            let reg_r = ch.recv();
            let commit_wall = t0.elapsed();

            let sid = ch.recv();
            let (resp, tm) = party.respond(&reg_r, &sid, &mut rng).unwrap();
            assert_eq!(tm.tokens_ns, 0, "the precomputed token batch was used");
            ch.send(&resp);
            let got = u64::from_le_bytes(ch.recv().try_into().unwrap());
            let ms = |d: std::time::Duration| s(d) * 1e3;
            let ns_ms = |x: u64| x as f64 / 1e6;
            let ok = got as usize == expected;
            println!("SPICy CIC, sender, set size 2^{lg} = {n}, n_g = {n_g}, threads = {threads}");
            println!("Sender commit phase time: {:.2} ms (computation {:.2} ms, token proofs {:.2} ms)", ms(commit_wall), ms(reg_comp), ms(tokens));
            println!("Sender response time: {:.2} ms", ns_ms(tm.total_ns));
            println!("Sender pair setup time: {:.2} ms", ns_ms(tm.pair_setup_ns));
            println!("Sender intersection time: {:.2} ms", ns_ms(tm.intersection_ns));
            println!("Sender data sent: {:.4} MB", ch.sent as f64 / (1024.0 * 1024.0));
            println!("Intersection size reported by the receiver: {got} ({})", if ok { "correct" } else { "wrong" });
        }
        _ => panic!("role must be sender or receiver"),
    }
}

fn rayon_threads() -> String {
    std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "default".into())
}
