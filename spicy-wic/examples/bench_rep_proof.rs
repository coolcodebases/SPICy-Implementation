// median prove/verify time of pi_rep over 50 runs
// run: cargo run --release --example bench_rep_proof

use std::time::Instant;

use ark_ec::{AffineRepr, CurveGroup};
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use rand_chacha::ChaCha20Rng;
use spicy_ws::params::w_r;
use spicy_ws::rep_proof::{prove, verify};
use spicy_ws::types::{Fq0, G0Affine};

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn main() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let g0 = G0Affine::generator();
    let w = w_r(b"receiver");
    let ctx = [7u8; 64];
    let (mut tp, mut tv) = (Vec::new(), Vec::new());
    for _ in 0..50 {
        let (s1, s2) = (Fq0::rand(&mut rng), Fq0::rand(&mut rng));
        let pk = (g0 * s1 + w * s2).into_affine();
        let t = Instant::now();
        let p = prove(&ctx, &g0, &w, &pk, &s1, &s2, &mut rng).unwrap();
        tp.push(t.elapsed().as_secs_f64());
        let t = Instant::now();
        assert!(verify(&ctx, &g0, &w, &pk, &p));
        tv.push(t.elapsed().as_secs_f64());
    }
    println!(
        "{{\"threads\":{},\"prove_ms\":{:.3},\"verify_ms\":{:.3}}}",
        rayon::current_num_threads(),
        median(tp) * 1e3,
        median(tv) * 1e3
    );
}
