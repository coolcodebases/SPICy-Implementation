// vector pedersen commitments in G_cyc
// a row commitment is a hyrax row commitment, so registration rows are shared with the spartan proofs

pub mod derived;
pub mod power_rows;

use ark_ec::{CurveGroup, VariableBaseMSM};

use crate::ct;
use crate::params::CycGens;
use crate::types::{Fp, GcycAffine, GcycProjective};

// row commitment Com(values; blind)
pub fn commit_row(gens: &CycGens, values: &[Fp], blind: Fp) -> GcycProjective {
    assert!(values.len() <= gens.g.len(), "row longer than generator vector");
    GcycProjective::msm_unchecked(&gens.g[..values.len()], values) + gens.h * blind
}

// constant-time commit_row for secret values
pub fn commit_row_ct(gens: &CycGens, values: &[Fp], blind: Fp) -> GcycAffine {
    assert!(values.len() <= gens.g.len(), "row longer than generator vector");
    (ct::msm(&gens.g[..values.len()], values) + ct::mul(&gens.h, &blind)).into_affine()
}

pub fn commit_row_affine(gens: &CycGens, values: &[Fp], blind: Fp) -> GcycAffine {
    commit_row(gens, values, blind).into_affine()
}

// per-element commitments C_j, their sum rt_S and its blind r~_1
pub fn vector_pedersen(gens: &CycGens, z: &[Fp], r: &[Fp]) -> (Vec<GcycAffine>, GcycAffine, Fp) {
    assert_eq!(z.len(), r.len());
    let cs: Vec<GcycProjective> = z
        .iter()
        .zip(r)
        .enumerate()
        .map(|(j, (zj, rj))| ct::mul(&gens.g[j], zj) + ct::mul(&gens.h, rj))
        .collect();
    let rt: GcycProjective = cs.iter().sum();
    let blind: Fp = r.iter().sum();
    (GcycProjective::normalize_batch(&cs), rt.into_affine(), blind)
}

// (rt_S, r~_1) as one row commitment, without the unused C_j
// uses the precomputed variable-time msm of the hyrax generators
pub fn vector_pedersen_root(gens: &CycGens, z: &[Fp], r: &[Fp]) -> (GcycAffine, Fp) {
    assert_eq!(z.len(), r.len());
    let blind: Fp = r.iter().sum();
    let g = crate::snark::spartan::sigma::Gens::cached(z.len());
    debug_assert!(g.vec.g[..z.len()] == gens.g[..z.len()] && g.vec.h == gens.h, "same generators");
    (g.commit_vec(z, blind).into_affine(), blind)
}

pub fn verify_opening(gens: &CycGens, c: &GcycAffine, values: &[Fp], blind: Fp) -> bool {
    commit_row_affine(gens, values, blind) == *c
}

