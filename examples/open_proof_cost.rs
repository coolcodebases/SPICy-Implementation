// cost of pi_open with fiat-shamir, or fischlin with --features fischlin
// run: cargo run --release --example open_proof_cost [--features fischlin]

use std::time::Instant;

use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use spicy::params::{b0, b_slot};
use spicy::sigma::open_relation::{commit_cs, prove_open, verify_open, OpenBases, OpenWitness};
use spicy::types::Fq0;

fn main() {
    let mode = if cfg!(feature = "fischlin") { "Fischlin (r = 16, b = 8, t = 12)" } else { "Fiat–Shamir" };
    println!("Π_open with {mode}");
    println!("{:>6} {:>10} {:>10} {:>10}", "M", "prove", "verify", "size");
    let mut rng = ChaCha20Rng::seed_from_u64(2026);
    for m in [16usize, 64, 256, 1024] {
        let b: Vec<_> = (0..m).map(b_slot).collect();
        let b0 = b0();
        let bases = OpenBases { b: &b, b0: &b0 };
        let wit = OpenWitness {
            a: (0..m).map(|_| Fq0::rand(&mut rng)).collect(),
            b: (0..m).map(|_| Fq0::rand(&mut rng)).collect(),
            r: Fq0::rand(&mut rng),
        };
        let c_s = commit_cs(&bases, &wit);
        let t = Instant::now();
        let pf = prove_open(b"id_S", &bases, &c_s, &wit, &mut rng);
        let tp = t.elapsed();
        let t = Instant::now();
        assert!(verify_open(b"id_S", &bases, &c_s, &pf));
        let tv = t.elapsed();
        println!("{m:>6} {tp:>10.2?} {tv:>10.2?} {:>8} B", pf.compressed_size());
    }
}
