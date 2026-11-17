// per-phase timings and message sizes of wic, M = N = 2^LOG_SIZE, half of X in Y
// one json line per repetition
// run: cargo run --release --example bench_phases -- LOG_SIZE [REPS] [LEVEL]

use std::time::Instant;

use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use spicy_ws::params::{setup, Params};
use spicy_ws::protocol::messages::size_of;
use spicy_ws::protocol::{
    intersection_r, intersection_s, pair_setup_r, pair_setup_s, registration_r, registration_s,
    verify_registration_s,
};

fn t<T>(f: impl FnOnce() -> T) -> (T, f64) {
    let s = Instant::now();
    let v = f();
    (v, s.elapsed().as_secs_f64())
}

fn peak_rss_bytes() -> u64 {
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) };
    // ru_maxrss is in bytes on macOS, in KiB on Linux
    if cfg!(target_os = "macos") {
        u.ru_maxrss as u64
    } else {
        u.ru_maxrss as u64 * 1024
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let log: u32 = args.get(1).map(|s| s.parse().unwrap()).unwrap_or(7);
    let reps: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(3);
    let n = 1usize << log;
    let params = Params::new(n, n).unwrap();
    let pp = setup(&params).unwrap();
    let threads = rayon::current_num_threads();
    let x: Vec<Vec<u8>> = (0..n)
        .map(|i| format!("item-{}", 2 * i).into_bytes())
        .collect();
    let y: Vec<Vec<u8>> = (0..n)
        .map(|i| format!("item-{}", 4 * i).into_bytes())
        .collect();
    let mut rng = ChaCha20Rng::seed_from_u64(log as u64);
    {
        for rep in 0..reps {
            // registration
            let ((reg_r, rsec), reg_r_s) =
                t(|| registration_r(&pp, b"receiver", &y, &mut rng).unwrap());
            let ((reg_s, ssec), reg_s_s) =
                t(|| registration_s(&pp, b"sender", &x, &mut rng).unwrap());
            let (ver, ver_s) = t(|| verify_registration_s(&pp, &reg_s).unwrap());
            // pair setup
            let ((msg_pair, s_state), ps_s) =
                t(|| pair_setup_s(&pp, &ssec, &reg_r, &mut rng).unwrap());
            let (r_state, ps_r) = t(|| pair_setup_r(&pp, &ver, &msg_pair, &rsec).unwrap());
            // intersection: one message from the sender, which picks the sid
            let (msg, int_s) = t(|| intersection_s(&s_state, &mut rng));
            let (out, int_r) = t(|| intersection_r(&pp, &r_state, &rsec, &msg).unwrap());
            assert_eq!(out.int.len(), n / 2, "wrong intersection size");
            println!(
                "{{\"protocol\":\"wic\",\"log\":{log},\"rep\":{rep},\"threads\":{threads},\"n_g\":{},\
                 \"reg_r_s\":{reg_r_s:.6},\"reg_s_s\":{reg_s_s:.6},\"verify_reg_s\":{ver_s:.6},\
                 \"pair_s_s\":{ps_s:.6},\"pair_r_s\":{ps_r:.6},\"int_s_s\":{int_s:.6},\"int_r_s\":{int_r:.6},\
                 \"pk_r_bytes\":{},\"reg_s_bytes\":{},\"pair_bytes\":{},\"int_bytes\":{},\"int_size\":{},\
                 \"peak_rss\":{}}}",
                params.n_g,
                size_of(&reg_r),
                size_of(&reg_s),
                size_of(&msg_pair),
                size_of(&msg),
                out.int.len(),
                peak_rss_bytes()
            );
        }
    }
}
