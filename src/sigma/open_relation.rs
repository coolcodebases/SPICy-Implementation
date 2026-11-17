// R_open: knowledge of an opening of C_s = sum_j ([a_j]B_(j,1) + [b_j]B_(j,2)) + [r]B0
// fischlin with the fischlin feature, plain fiat-shamir otherwise
// witness order: a_0..a_(M-1), b_0..b_(M-1), r

use ark_ec::CurveGroup;
use ark_std::rand::RngCore;

use crate::oracle::domain;
#[cfg(not(feature = "fischlin"))]
use crate::sigma::maurer;
use crate::sigma::maurer::LinearStatement;
use crate::transcript::Transcript;
use crate::types::{Fq0, G0Affine};

// (B_(j,1), B_(j,2))_j and B0
#[derive(Clone, Copy, Debug)]
pub struct OpenBases<'a> {
    pub b: &'a [(G0Affine, G0Affine)],
    pub b0: &'a G0Affine,
}

#[derive(Clone, Debug)]
pub struct OpenWitness {
    pub a: Vec<Fq0>,
    pub b: Vec<Fq0>,
    pub r: Fq0,
}

impl OpenWitness {
    pub fn vector(&self) -> Vec<Fq0> {
        let mut w = self.a.clone();
        w.extend_from_slice(&self.b);
        w.push(self.r);
        w
    }
}

// C_s, variable time
pub fn commit_cs(bases: &OpenBases, wit: &OpenWitness) -> G0Affine {
    let mut pts: Vec<G0Affine> = bases.b.iter().map(|p| p.0).collect();
    pts.extend(bases.b.iter().map(|p| p.1));
    pts.push(*bases.b0);
    <crate::types::G0Projective as ark_ec::VariableBaseMSM>::msm_unchecked(&pts, &wit.vector()).into_affine()
}

pub fn linear(bases: &OpenBases, c_s: &G0Affine) -> LinearStatement {
    let m = bases.b.len();
    let mut row = Vec::with_capacity(2 * m + 1);
    for (j, (b1, _)) in bases.b.iter().enumerate() {
        row.push((j, *b1));
    }
    for (j, (_, b2)) in bases.b.iter().enumerate() {
        row.push((m + j, *b2));
    }
    row.push((2 * m, *bases.b0));
    LinearStatement { n_witness: 2 * m + 1, rows: vec![row], image: vec![*c_s] }
}

fn transcript(ctx: &[u8]) -> Transcript {
    let mut t = Transcript::new(domain::OPEN);
    t.append_bytes(b"ctx", ctx);
    t
}

// pi_open proof (fiat-shamir)
#[cfg(not(feature = "fischlin"))]
pub type OpenProof = maurer::SigmaProof;
// pi_open proof (fischlin)
#[cfg(feature = "fischlin")]
pub type OpenProof = crate::sigma::fischlin::FischlinProof;

// Prove(ctx = id_S, C_s, wit) for R_open
pub fn prove_open<R: RngCore>(ctx: &[u8], bases: &OpenBases, c_s: &G0Affine, wit: &OpenWitness, rng: &mut R) -> OpenProof {
    #[cfg(not(feature = "fischlin"))]
    return maurer::prove(&mut transcript(ctx), &linear(bases, c_s), &wit.vector(), rng);
    #[cfg(feature = "fischlin")]
    return crate::sigma::fischlin::prove(&transcript(ctx), &linear(bases, c_s), &wit.vector(), rng);
}

// Vfy(ctx = id_S, C_s, pi_s) for R_open
pub fn verify_open(ctx: &[u8], bases: &OpenBases, c_s: &G0Affine, proof: &OpenProof) -> bool {
    if !bases.b.iter().all(|p| p.0.is_on_curve() && p.1.is_on_curve()) {
        return false;
    }
    #[cfg(not(feature = "fischlin"))]
    return maurer::verify(&mut transcript(ctx), &linear(bases, c_s), proof);
    #[cfg(feature = "fischlin")]
    return crate::sigma::fischlin::verify(&transcript(ctx), &linear(bases, c_s), proof);
}
