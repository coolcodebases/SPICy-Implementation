// power rows Z_k = Com((z_j^k)_j; r~_k), Z_1 = rt_S
// pre-committed hyrax rows of pi_pow; pi_pair uses commitments derived from them

use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_std::rand::RngCore;
use ark_std::UniformRand;

use crate::params::CycGens;
use crate::types::{Fp, GcycAffine, GcycProjective};

// openings: powers[k-1][j] = z_j^k, blinds[k-1] = r~_k
#[derive(Clone, Debug)]
pub struct PowerRowsSecret {
    pub powers: Vec<Vec<Fp>>,
    pub blinds: Vec<Fp>,
}

// rows[k-1] = Z_k, so rows[0] is rt_S
pub type PowerRows = Vec<GcycAffine>;

// Z_1..Z_(n_g-1) for Registration_S
pub fn build_power_rows<R: RngCore>(
    gens: &CycGens,
    z: &[Fp],
    r1: Fp,
    n_g: usize,
    rng: &mut R,
) -> (PowerRows, PowerRowsSecret) {
    let mut powers = vec![z.to_vec()];
    let mut blinds = vec![r1];
    for k in 2..n_g {
        let prev = &powers[k - 2];
        powers.push(prev.iter().zip(z).map(|(p, zj)| *p * zj).collect());
        blinds.push(Fp::rand(rng));
    }
    // precomputed-generator msm of the spartan prover, variable time
    let _span = tracing::info_span!("power_rows", rows = n_g - 1, m = z.len()).entered();
    let g = crate::snark::spartan::sigma::Gens::cached(z.len());
    debug_assert!(g.vec.g[..z.len()] == gens.g[..z.len()] && g.vec.h == gens.h, "same generators as rt_S");
    #[cfg(feature = "parallel")]
    let rows: Vec<GcycAffine> = {
        use rayon::prelude::*;
        let p: Vec<GcycProjective> = powers.par_iter().zip(blinds.par_iter()).map(|(p, b)| g.commit_vec(p, *b)).collect();
        GcycProjective::normalize_batch(&p)
    };
    #[cfg(not(feature = "parallel"))]
    let rows: Vec<GcycAffine> = {
        let p: Vec<GcycProjective> = powers.iter().zip(&blinds).map(|(p, b)| g.commit_vec(p, *b)).collect();
        GcycProjective::normalize_batch(&p)
    };
    (rows, PowerRowsSecret { powers, blinds })
}

// registered rows of the paterson-stockmeyer layout: Z_k for k = 1..S, plus Z_g = Com((g(z_j))_j; r~_g)
// returned as [Z_1..Z_S, Z_g]; no higher powers, R_pow and R_pair use horner in z_j^S
pub fn build_ps_rows<R: RngCore>(
    gens: &CycGens,
    z: &[Fp],
    r1: Fp,
    s: usize,
    mask: &[Fp],
    rng: &mut R,
) -> (PowerRows, PowerRowsSecret) {
    assert!(s >= 2, "S ≥ 2");
    let mut powers = vec![z.to_vec()];
    let mut blinds = vec![r1];
    for k in 2..=s {
        let prev = &powers[k - 2];
        powers.push(prev.iter().zip(z).map(|(p, zj)| *p * zj).collect());
        blinds.push(Fp::rand(rng));
    }
    powers.push(crate::par::map(z, |zj| crate::field::poly::eval(mask, *zj)));
    blinds.push(Fp::rand(rng));
    let _span = tracing::info_span!("power_rows", rows = s + 1, m = z.len()).entered();
    let g = crate::snark::spartan::sigma::Gens::cached(z.len());
    debug_assert!(g.vec.g[..z.len()] == gens.g[..z.len()] && g.vec.h == gens.h, "same generators as rt_S");
    let p: Vec<GcycProjective> = crate::par::map_range(powers.len(), |k| g.commit_vec(&powers[k], blinds[k]));
    (GcycProjective::normalize_batch(&p), PowerRowsSecret { powers, blinds })
}

// Z_0 = sum_j G^(j)_cyc, the k = 0 row
pub fn z0(gens: &CycGens, m: usize) -> GcycAffine {
    gens.g[..m].iter().map(|g| GcycProjective::from(*g)).sum::<GcycProjective>().into_affine()
}

pub fn power(z: Fp, k: usize) -> Fp {
    z.pow([k as u64])
}

