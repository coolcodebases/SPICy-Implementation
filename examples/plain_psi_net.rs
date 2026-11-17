// plain psi between two processes over tcp, M = N = 2^LOG_SIZE, every third element shared
// each party prints its phase times and the data it sent
// run: cargo run --release --example plain_psi_net -- receiver BIND_ADDR:PORT LOG_SIZE
// then: ... -- sender PEER_ADDR:PORT LOG_SIZE

use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

use spicy::encoding::psi_encoding::{Codec, PkR};
use spicy::params::{setup, w_r, Params};
use spicy::protocol::plain_psi;
use spicy::serialize::{from_bytes, to_bytes};
use spicy::types::G0Affine;

struct Chan {
    r: BufReader<TcpStream>,
    w: BufWriter<TcpStream>,
    sent: u64,
    recv: u64,
}

impl Chan {
    fn new(s: TcpStream) -> Self {
        s.set_nodelay(true).expect("TCP_NODELAY");
        Chan { r: BufReader::new(s.try_clone().expect("clone")), w: BufWriter::new(s), sent: 0, recv: 0 }
    }
    // queues a frame, flush sends everything queued as one flight
    fn put(&mut self, b: &[u8]) {
        self.w.write_all(&(b.len() as u64).to_le_bytes()).unwrap();
        self.w.write_all(b).unwrap();
        self.sent += 8 + b.len() as u64;
    }
    fn flush(&mut self) {
        self.w.flush().unwrap();
    }
    fn send(&mut self, b: &[u8]) {
        self.put(b);
        self.flush();
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

fn element(party: &str, i: usize) -> Vec<u8> {
    if i % 3 == 0 { format!("shared-{i}") } else { format!("{party}-{i}") }.into_bytes()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    assert!(a.len() == 4, "usage: plain_psi_net (sender|receiver) ADDR:PORT LOG_SIZE");
    let (role, addr, lg) = (a[1].as_str(), a[2].as_str(), a[3].parse::<u32>().expect("LOG_SIZE"));
    let n = 1usize << lg;
    let params = Params::new(n, n).unwrap();
    let pp = setup(&params).unwrap();
    let w = w_r(b"receiver");
    let codec = Codec { w_r: &w, mask: &pp.mask };
    let expected = n.div_ceil(3);
    let mut rng = rand::thread_rng();
    let threads = rayon::current_num_threads();
    let s = |d: std::time::Duration| d.as_secs_f64();

    match role {
        "receiver" => {
            let (stream, _) = TcpListener::bind(addr).expect("bind").accept().expect("accept");
            let mut ch = Chan::new(stream);
            ch.recv();
            ch.send(&[1]);
            let (sent0, recv0) = (ch.sent, ch.recv);

            // committing: KGen_R, send pk_R
            let t0 = Instant::now();
            let y: Vec<Vec<u8>> = (0..n).map(|i| element("r", i)).collect();
            let (pk_r, sk_r) = plain_psi::receiver_setup(&y, &codec, &mut rng).unwrap();
            let reg_comp = t0.elapsed();
            let pk_r_b = to_bytes(&pk_r);
            ch.send(&pk_r_b);
            let commit_wall = t0.elapsed();
            let commit_bytes = (ch.sent - sent0) + (ch.recv - recv0);

            // intersection
            let t1 = Instant::now();
            let pk_s_b = ch.recv();
            let k_s_b = ch.recv();
            let wait = t1.elapsed();
            let t2 = Instant::now();
            let pk_s: Vec<G0Affine> = from_bytes(&pk_s_b).unwrap();
            let k_s: Vec<G0Affine> = from_bytes(&k_s_b).unwrap();
            let out = plain_psi::receiver_output(&y, n, &pk_s, &sk_r, &k_s).unwrap();
            let int_r = t2.elapsed();
            let total = t0.elapsed();
            let inter_wall = total - commit_wall;
            ch.send(&(out.len() as u64).to_le_bytes());
            let inter_bytes = (ch.sent - sent0) + (ch.recv - recv0) - commit_bytes - 8 - 8;
            let ok = out.len() == expected;
            let ms = |d: std::time::Duration| s(d) * 1e3;
            let mb = |b: u64| b as f64 / (1024.0 * 1024.0);
            println!("Our PSI, receiver, set size 2^{lg} = {n}, n_g = {}, threads = {threads}", params.n_g);
            println!("Receiver commit phase time: {:.2} ms (computation {:.2} ms)", ms(commit_wall), ms(reg_comp));
            println!("Receiver committed data size: {:.4} MB", mb(pk_r_b.len() as u64));
            println!("Receiver intersection time: {:.2} ms", ms(int_r));
            println!("Intersection phase time: {:.2} ms (waiting for the sender {:.2} ms)", ms(inter_wall), ms(wait));
            println!("Sender response size: {:.4} MB (pk_S {:.4} MB, K_S {:.4} MB)", mb((pk_s_b.len() + k_s_b.len()) as u64), mb(pk_s_b.len() as u64), mb(k_s_b.len() as u64));
            println!("Intersection size: {} (expected {expected}, {})", out.len(), if ok { "correct" } else { "wrong" });
            println!("Whole protocol time: {:.2} ms", ms(total));
            println!("Total communication size sender and receiver: {:.4} MB (commit {:.4} MB, intersection {:.4} MB)", mb(commit_bytes + inter_bytes), mb(commit_bytes), mb(inter_bytes));
            if !ok {
                std::process::exit(1);
            }
        }
        "sender" => {
            let mut ch = Chan::new(TcpStream::connect(addr).expect("connect"));
            ch.send(&[1]);
            ch.recv();

            let pk_r_b = ch.recv();
            let t0 = Instant::now();
            let pk_r: PkR = from_bytes(&pk_r_b).unwrap();
            let x: Vec<Vec<u8>> = (0..n).map(|i| element("s", i)).collect();
            let (pk_s, sk_s) = plain_psi::sender_setup(n, &w, &mut rng);
            let k_s = plain_psi::sender_intersect(&x, &sk_s, &pk_r, params.poly_len(), &codec, &mut rng).unwrap();
            let int_s = t0.elapsed();
            ch.put(&to_bytes(&pk_s));
            ch.put(&to_bytes(&k_s));
            ch.flush();
            let got = u64::from_le_bytes(ch.recv().try_into().unwrap());
            let ok = got as usize == expected;
            println!("Our PSI, sender, set size 2^{lg} = {n}, threads = {threads}");
            println!("Sender intersection time: {:.2} ms", s(int_s) * 1e3);
            println!("Sender data sent: {:.4} MB", ch.sent as f64 / (1024.0 * 1024.0));
            println!("Intersection size reported by the receiver: {got} ({})", if ok { "correct" } else { "wrong" });
        }
        _ => panic!("role must be sender or receiver"),
    }
}
