// benchmarks each phase of spicy for both parties (both spartan backends)
// run: cargo bench --bench spicy_bench -- --quick
// set sizes come from SPICY_BENCH_SIZES (default 4,16)

use std::time::Duration;

use ark_serialize::CanonicalSerialize;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use spicy::params::{setup, slack, Params, DEFAULT_STAT_BITS};
use spicy::protocol::messages::size_of;
use spicy::protocol::*;
use spicy::snark::spartan::{SpartanNizk, SpartanSnark};
use spicy::snark::ProofSystem;
use spicy::types::{Fp, G0Affine, GcycAffine};

const SEED: u64 = 2026;

fn sizes() -> Vec<usize> {
    std::env::var("SPICY_BENCH_SIZES")
        .ok()
        .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
        .unwrap_or_else(|| vec![4, 16])
}

fn params(m: usize, n: usize) -> Params {
    match std::env::var("SPICY_BENCH_NG").as_deref() {
        Ok("min") => Params::with_mask_len(m, n, 4 * (n + 1)).unwrap(),
        _ => Params::new(m, n).unwrap(),
    }
}

fn set(prefix: &str, n: usize, step: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| format!("{prefix}{}", i * step).into_bytes()).collect()
}

// peak rss in MiB (ru_maxrss is bytes on macos, KiB on linux)
fn peak_mib() -> f64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // safety: getrusage only writes into the struct we pass
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let raw = ru.ru_maxrss as f64;
    if cfg!(target_os = "macos") {
        raw / (1024.0 * 1024.0)
    } else {
        raw / 1024.0
    }
}

fn bench(c: &mut Criterion) {
    bench_backend::<SpartanNizk>(c, "nizk");
    bench_backend::<SpartanSnark>(c, "snark");
}

fn bench_backend<B: ProofSystem>(c: &mut Criterion, tag: &str) {
    println!("SPICy benchmarks: backend = {}, seed = {SEED}", B::NAME);
    let fp = Fp::from(0u64).compressed_size();
    let g0 = G0Affine::default().compressed_size();
    let gc = GcycAffine::default().compressed_size();
    for n in sizes() {
        let m = n;
        let params = params(m, n);
        let pp = setup(&params).unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(SEED);
        let x = set("e", m, 2);
        let y = set("e", n, 3);
        let (reg_r, rsec) = registration_r(&pp, b"R", &y, &mut rng).unwrap();
        let (reg_s, ssec) = registration_s::<B, _>(&pp, b"S", &x, &mut rng).unwrap();
        let ver = verify_registration_s::<B>(&pp, &reg_s).unwrap();
        let (msg, mut ss) = pair_setup_s::<B, _>(&pp, &ssec, &reg_r, &mut rng).unwrap();
        let rs = pair_setup_r::<B>(&pp, &ver, &msg, &rsec).unwrap();
        let im = intersection_s(b"sid", &mut ss, &mut rng);

        println!(
            "\n== M = N = {n}: 4(N+1) = {}, n_g = {}, slack n' = {} (κ = {DEFAULT_STAT_BITS}) ==",
            params.key_len(),
            params.n_g,
            slack(n, DEFAULT_STAT_BITS)
        );
        println!("  Registration R : {:>8} B  expected 4(N+1) F_p = {}", size_of(&reg_r), params.key_len() * fp);
        println!(
            "  Registration S : {:>8} B  expected (n_g−1) G_cyc = {} + |π_pow| = {}",
            size_of(&reg_s),
            params.n_rows() * gc,
            reg_s.pi_pow.len()
        );
        println!(
            "  Pair setup S   : {:>8} B  expected 4M G0 + 4 G_cyc + 1 G0 = {} + |π_s| = {} + |π_tok| = {} + |π_pair| = {}",
            size_of(&msg),
            (4 * m + 1) * g0 + 4 * gc,
            msg.pi_s.compressed_size(),
            msg.pi_tok.len(),
            msg.pi_pair.len()
        );
        println!("  Intersection S : {:>8} B  expected M + 4M+1 G0, 4M+1 Z_q0 = {}", size_of(&im), (5 * m + 1) * g0 + (4 * m + 1) * fp);

        let mut g = c.benchmark_group(format!("spicy-{tag}/M=N={n}"));
        g.sample_size(10).measurement_time(Duration::from_secs(3)).warm_up_time(Duration::from_millis(500));
        g.bench_function(BenchmarkId::new("registration", "receiver"), |b| {
            b.iter(|| registration_r(&pp, b"R", &y, &mut rng).unwrap())
        });
        g.bench_function(BenchmarkId::new("registration", "sender"), |b| {
            b.iter(|| registration_s::<B, _>(&pp, b"S", &x, &mut rng).unwrap())
        });
        g.bench_function(BenchmarkId::new("registration", "receiver_verify_pow"), |b| {
            b.iter(|| verify_registration_s::<B>(&pp, &reg_s).unwrap())
        });
        let mut r2 = ChaCha20Rng::seed_from_u64(SEED + 1);
        g.bench_function(BenchmarkId::new("pair_setup", "sender"), |b| {
            b.iter(|| pair_setup_s::<B, _>(&pp, &ssec, &reg_r, &mut rng).unwrap())
        });
        g.bench_function(BenchmarkId::new("pair_setup", "receiver"), |b| {
            b.iter(|| pair_setup_r::<B>(&pp, &ver, &msg, &rsec).unwrap())
        });
        g.bench_function(BenchmarkId::new("intersection_sender", "online_with_precomputed"), |b| {
            b.iter_custom(|iters| {
                ss.precompute(iters as usize, &mut r2); // offline, not timed
                let t = std::time::Instant::now();
                for _ in 0..iters {
                    std::hint::black_box(intersection_s(b"sid", &mut ss, &mut rng));
                }
                t.elapsed()
            })
        });
        g.bench_function(BenchmarkId::new("intersection_sender", "including_first_message"), |b| {
            b.iter(|| intersection_s(b"sid", &mut ss, &mut rng))
        });
        g.bench_function(BenchmarkId::new("intersection_receiver", "verify_and_match"), |b| {
            b.iter(|| intersection_r(&pp, b"sid", &rs, &rsec, &im).unwrap())
        });
        g.finish();
        println!("  peak RSS so far: {:.0} MiB", peak_mib());
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
