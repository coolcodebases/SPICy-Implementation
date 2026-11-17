// wic between two processes over one tcp connection, for network benchmarks
// M = N = 2^LOG_SIZE, every third element shared; last arg "wic" or "strong" runs the same thing
// usage: ws_net receiver|sender ADDR:PORT LOG_SIZE [wic]

use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

use spicy_ws::params::{setup, Params};
use spicy_ws::protocol::messages::{IntersectionMsg, MsgPair, RegistrationR, RegistrationS};
use spicy_ws::protocol::{
    intersection_r_audit, intersection_s, pair_setup_r, pair_setup_s, registration_r, registration_s,
    verify_registration_s,
};
use spicy_ws::serialize::{from_bytes, to_bytes};

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
    // queue a frame, flush sends everything queued as one flight
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

fn peak_rss_bytes() -> u64 {
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) };
    if cfg!(target_os = "macos") { u.ru_maxrss as u64 } else { u.ru_maxrss as u64 * 1024 }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    assert!(a.len() == 4 || a.len() == 5, "usage: ws_net (sender|receiver) ADDR:PORT LOG_SIZE [wic]");
    let (role, addr, lg) = (a[1].as_str(), a[2].as_str(), a[3].parse::<u32>().expect("LOG_SIZE"));
    if let Some(l) = a.get(4) {
        assert!(l == "wic" || l == "strong", "only the WIC protocol is implemented, got {l}");
    }
    let n = 1usize << lg;
    let params = Params::new(n, n).unwrap();
    let pp = setup(&params).unwrap();
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

            let t0 = Instant::now();
            let y: Vec<Vec<u8>> = (0..n).map(|i| element("r", i)).collect();
            let (reg_r, rsec) = registration_r(&pp, b"receiver", &y, &mut rng).unwrap();
            let reg_comp = t0.elapsed();
            let reg_r_b = to_bytes(&reg_r);
            ch.send(&reg_r_b);
            let reg_s_b = ch.recv();
            let commit_wall = t0.elapsed();
            let commit_bytes = (ch.sent - sent0) + (ch.recv - recv0);

            let t1 = Instant::now();
            let reg_s: RegistrationS = from_bytes(&reg_s_b).unwrap();
            let ver = verify_registration_s(&pp, &reg_s).unwrap();
            let verify = t1.elapsed();
            let pair_b = ch.recv();
            let msg_b = ch.recv();
            let wait = t1.elapsed();
            let t2 = Instant::now();
            let msg_pair: MsgPair = from_bytes(&pair_b).unwrap();
            let r_state = pair_setup_r(&pp, &ver, &msg_pair, &rsec).unwrap();
            let pair_r = t2.elapsed();
            let t3 = Instant::now();
            let msg: IntersectionMsg = from_bytes(&msg_b).unwrap();
            // failed-opening count, logged locally only
            let (out, rejected) = intersection_r_audit(&pp, &r_state, &rsec, &msg).unwrap();
            let int_r = t3.elapsed();
            let total = t0.elapsed();
            let inter_wall = total - commit_wall;
            ch.send(&(out.int.len() as u64).to_le_bytes());
            let inter_bytes = (ch.sent - sent0) + (ch.recv - recv0) - commit_bytes - 8 - 8;
            let ok = out.int.len() == expected && rejected == 0;
            let ms = |d: std::time::Duration| s(d) * 1e3;
            let mb = |b: u64| b as f64 / (1024.0 * 1024.0);
            println!("SPICy WIC, receiver, set size 2^{lg} = {n}, n_g = {}, threads = {threads}", params.n_g);
            println!("Receiver commit phase time: {:.2} ms (computation {:.2} ms)", ms(commit_wall), ms(reg_comp));
            println!("Receiver committed data size: {:.4} MB", mb(reg_r_b.len() as u64));
            println!("Sender committed data size: {:.4} MB", mb(reg_s_b.len() as u64));
            println!("Receiver verification of the sender's registration: {:.2} ms", ms(verify));
            println!("Receiver pair setup time: {:.2} ms", ms(pair_r));
            println!("Receiver intersection time: {:.2} ms", ms(int_r));
            println!("Intersection phase time: {:.2} ms (waiting for the sender {:.2} ms)", ms(inter_wall), ms(wait));
            println!("Sender pair setup message size: {:.4} MB", mb(pair_b.len() as u64));
            println!("Sender intersection message size: {:.4} MB", mb(msg_b.len() as u64));
            println!("Intersection size: {} (expected {expected}, rejected openings {rejected}, {})", out.int.len(), if ok { "correct" } else { "wrong" });
            println!("Whole protocol time: {:.2} ms", ms(total));
            println!("Total communication size sender and receiver: {:.4} MB (commit {:.4} MB, intersection {:.4} MB)", mb(commit_bytes + inter_bytes), mb(commit_bytes), mb(inter_bytes));
            println!("Peak memory: {:.1} MB", mb(peak_rss_bytes()));
            if !ok {
                std::process::exit(1);
            }
        }
        "sender" => {
            let mut ch = Chan::new(TcpStream::connect(addr).expect("connect"));
            ch.send(&[1]);
            ch.recv();

            let t0 = Instant::now();
            let x: Vec<Vec<u8>> = (0..n).map(|i| element("s", i)).collect();
            let (reg_s, ssec) = registration_s(&pp, b"sender", &x, &mut rng).unwrap();
            let reg_comp = t0.elapsed();
            let reg_r_b = ch.recv();
            ch.send(&to_bytes(&reg_s));
            let commit_wall = t0.elapsed();

            let t1 = Instant::now();
            let reg_r: RegistrationR = from_bytes(&reg_r_b).unwrap();
            let (msg_pair, s_state) = pair_setup_s(&pp, &ssec, &reg_r, &mut rng).unwrap();
            let pair_s = t1.elapsed();
            let t2 = Instant::now();
            let msg = intersection_s(&s_state, &mut rng);
            let int_s = t2.elapsed();
            ch.put(&to_bytes(&msg_pair));
            ch.put(&to_bytes(&msg));
            ch.flush();
            let got = u64::from_le_bytes(ch.recv().try_into().unwrap());
            let ms = |d: std::time::Duration| s(d) * 1e3;
            let mb = |b: u64| b as f64 / (1024.0 * 1024.0);
            let ok = got as usize == expected;
            println!("SPICy WIC, sender, set size 2^{lg} = {n}, threads = {threads}");
            println!("Sender commit phase time: {:.2} ms (computation {:.2} ms)", ms(commit_wall), ms(reg_comp));
            println!("Sender pair setup time: {:.2} ms", ms(pair_s));
            println!("Sender intersection time: {:.2} ms", ms(int_s));
            println!("Sender data sent: {:.4} MB", mb(ch.sent));
            println!("Intersection size reported by the receiver: {got} ({})", if ok { "correct" } else { "wrong" });
            println!("Peak memory: {:.1} MB", mb(peak_rss_bytes()));
        }
        _ => panic!("role must be sender or receiver"),
    }
}
