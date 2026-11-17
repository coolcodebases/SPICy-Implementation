// zk sum-check with committed round polys (hyrax / spartan)
// each round commits to g_j's coeffs and g_j(r_j), and one dot-product proof links them to the previous claim

use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use ark_std::UniformRand;

use super::mle::powers;
use super::sigma::{DotProductProof, Gens};
use crate::field::poly::{eval, lagrange_interpolate};
use crate::transcript::Transcript;
use crate::types::{Fp, GcycAffine, GcycProjective};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ZkSumcheckProof {
    pub comm_polys: Vec<GcycAffine>,
    pub comm_evals: Vec<GcycAffine>,
    pub proofs: Vec<DotProductProof>,
}

// committed claim, value and blind known only to the prover
#[derive(Clone, Copy, Debug)]
pub struct Claim {
    pub value: Fp,
    pub blind: Fp,
    pub comm: GcycAffine,
}

fn weights(degree: usize, r: Fp, w0: Fp, w1: Fp) -> Vec<Fp> {
    // weights for g(0) + g(1) and for g(r), combined with w0 and w1
    let pw = powers(r, degree + 1);
    (0..=degree).map(|k| w0 * if k == 0 { Fp::from(2u64) } else { Fp::from(1u64) } + w1 * pw[k]).collect()
}

// coeffs of the degree-d poly with g(k) = evals[k]
pub fn coeffs_from_evals(evals: &[Fp]) -> Vec<Fp> {
    let pts: Vec<(Fp, Fp)> = evals.iter().enumerate().map(|(k, e)| (Fp::from(k as u64), *e)).collect();
    let mut c = lagrange_interpolate(&pts).expect("distinct points");
    c.resize(evals.len(), Fp::from(0u64));
    c
}

// prover tables: round_evals gives g_j(0..=d), bind fixes the next variable
pub trait Tables {
    fn round_evals(&self) -> Vec<Fp>;
    fn bind(&mut self, r: Fp);
}

pub fn prove<R: RngCore>(
    t: &mut Transcript,
    gens: &Gens,
    rounds: usize,
    degree: usize,
    mut claim: Claim,
    tables: &mut impl Tables,
    rng: &mut R,
) -> (ZkSumcheckProof, Vec<Fp>, Claim) {
    let mut proof = ZkSumcheckProof { comm_polys: vec![], comm_evals: vec![], proofs: vec![] };
    let mut rs = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let evals = tables.round_evals();
        debug_assert_eq!(evals.len(), degree + 1);
        let coeffs = coeffs_from_evals(&evals);
        let r_poly = Fp::rand(rng);
        let comm_poly = gens.commit_vec(&coeffs, r_poly).into_affine();
        t.append(b"sc/poly", &comm_poly);
        let r: Fp = t.challenge_scalar(b"sc/r");
        let value = eval(&coeffs, r);
        let blind = Fp::rand(rng);
        let comm = gens.commit_scalar(value, blind).into_affine();
        t.append(b"sc/eval", &comm);
        let w0: Fp = t.challenge_scalar(b"sc/w0");
        let w1: Fp = t.challenge_scalar(b"sc/w1");
        let a = weights(degree, r, w0, w1);
        let target_blind = w0 * claim.blind + w1 * blind;
        let target = (GcycProjective::from(claim.comm) * w0 + comm * w1).into_affine();
        let dp = DotProductProof::prove(t, gens, &coeffs, r_poly, &a, target_blind, &comm_poly, &target, rng);
        proof.comm_polys.push(comm_poly);
        proof.comm_evals.push(comm);
        proof.proofs.push(dp);
        tables.bind(r);
        rs.push(r);
        claim = Claim { value, blind, comm };
    }
    (proof, rs, claim)
}

// returns the challenges and the commitment to the final claim
pub fn verify(
    t: &mut Transcript,
    gens: &Gens,
    proof: &ZkSumcheckProof,
    rounds: usize,
    degree: usize,
    mut comm_claim: GcycAffine,
) -> Option<(Vec<Fp>, GcycAffine)> {
    if proof.comm_polys.len() != rounds || proof.comm_evals.len() != rounds || proof.proofs.len() != rounds {
        return None;
    }
    // replay the transcript to fix all challenges, then check the group equations in parallel
    let mut rs = Vec::with_capacity(rounds);
    let mut checks = Vec::with_capacity(rounds);
    for j in 0..rounds {
        t.append(b"sc/poly", &proof.comm_polys[j]);
        let r: Fp = t.challenge_scalar(b"sc/r");
        t.append(b"sc/eval", &proof.comm_evals[j]);
        let w0: Fp = t.challenge_scalar(b"sc/w0");
        let w1: Fp = t.challenge_scalar(b"sc/w1");
        let a = weights(degree, r, w0, w1);
        // the target's commitment is absorbed by the dot-product transcript
        let target = (GcycProjective::from(comm_claim) * w0 + proof.comm_evals[j] * w1).into_affine();
        let c = proof.proofs[j].verify_transcript(t, gens, &a, &proof.comm_polys[j], &target)?;
        checks.push((j, a, target, c));
        rs.push(r);
        comm_claim = proof.comm_evals[j];
    }
    let ok = crate::par::map(&checks, |(j, a, target, c)| proof.proofs[*j].check(gens, a, &proof.comm_polys[*j], target, *c));
    ok.into_iter().all(|b| b).then_some((rs, comm_claim))
}
