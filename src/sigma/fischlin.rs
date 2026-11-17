// fischlin transform of maurer's sigma protocol, used for pi_open
// sum variant, r = 16, b = 8, t = 12, S = r
// prover keeps per repetition the e with smallest H_b and restarts if the sum exceeds S
// verifier: e_i < 2^t, f(z_i) = a_i + e_i Y (one batched msm), sum of H_b at most S

use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use ark_std::UniformRand;

use crate::sigma::maurer::LinearStatement;
use crate::transcript::Transcript;
use crate::types::{Fq0, G0Affine, G0Projective};

pub const REPS: usize = 16;
pub const HASH_BITS: u32 = 8;
pub const CHALLENGE_BITS: u32 = 12;
pub const SUM_BOUND: u64 = REPS as u64;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct FischlinRound {
    pub commitment: Vec<G0Affine>,
    pub e: u64,
    pub response: Vec<Fq0>,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct FischlinProof {
    pub rounds: Vec<FischlinRound>,
}

fn absorb_statement(t: &mut Transcript, stmt: &LinearStatement) {
    t.append_u64(b"n_witness", stmt.n_witness as u64);
    t.append_u64(b"n_rows", stmt.rows.len() as u64);
    for row in &stmt.rows {
        t.append_u64(b"row_len", row.len() as u64);
        for (i, b) in row {
            t.append_u64(b"idx", *i as u64);
            t.append(b"base", b);
        }
    }
    t.append(b"image", &stmt.image);
}

// H_b: first b bits of the hash
fn h_b(base: &Transcript, i: usize, e: u64, z: &[Fq0]) -> u64 {
    let mut t = base.clone();
    t.append_u64(b"i", i as u64);
    t.append_u64(b"e", e);
    t.append(b"z", &z.to_vec());
    let out = t.challenge_bytes(b"fischlin");
    (out[0] as u64) >> (8 - HASH_BITS)
}

fn base_transcript(t: &Transcript, stmt: &LinearStatement, com: &[Vec<G0Affine>]) -> Transcript {
    let mut base = t.clone();
    absorb_statement(&mut base, stmt);
    base.append_u64(b"fischlin_r", REPS as u64);
    for a in com {
        base.append(b"commitment", a);
    }
    base
}

// t carries the domain and context
pub fn prove<R: RngCore>(t: &Transcript, stmt: &LinearStatement, w: &[Fq0], rng: &mut R) -> FischlinProof {
    assert_eq!(w.len(), stmt.n_witness);
    loop {
        let kappas: Vec<Vec<Fq0>> = (0..REPS).map(|_| (0..stmt.n_witness).map(|_| Fq0::rand(rng)).collect()).collect();
        let com: Vec<Vec<G0Affine>> = kappas.iter().map(|k| G0Projective::normalize_batch(&stmt.apply(k))).collect();
        let base = base_transcript(t, stmt, &com);
        let search = |i: usize| -> (u64, u64, Vec<Fq0>) {
            let mut z = kappas[i].clone();
            let mut best: Option<(u64, u64, Vec<Fq0>)> = None;
            for e in 0..(1u64 << CHALLENGE_BITS) {
                // response updated incrementally
                if e > 0 {
                    for (zk, wk) in z.iter_mut().zip(w) {
                        *zk += wk;
                    }
                }
                let h = h_b(&base, i, e, &z);
                if best.as_ref().is_none_or(|b| h < b.0) {
                    best = Some((h, e, z.clone()));
                    if h == 0 {
                        break;
                    }
                }
            }
            best.expect("at least one challenge")
        };
        #[cfg(feature = "parallel")]
        let found: Vec<(u64, u64, Vec<Fq0>)> = {
            use rayon::prelude::*;
            (0..REPS).into_par_iter().map(search).collect()
        };
        #[cfg(not(feature = "parallel"))]
        let found: Vec<(u64, u64, Vec<Fq0>)> = (0..REPS).map(search).collect();
        if found.iter().map(|f| f.0).sum::<u64>() <= SUM_BOUND {
            let rounds = com
                .into_iter()
                .zip(found)
                .map(|(commitment, (_, e, response))| FischlinRound { commitment, e, response })
                .collect();
            return FischlinProof { rounds };
        }
    }
}

pub fn verify(t: &Transcript, stmt: &LinearStatement, proof: &FischlinProof) -> bool {
    if proof.rounds.len() != REPS || stmt.image.len() != stmt.rows.len() {
        return false;
    }
    if proof.rounds.iter().any(|r| {
        r.commitment.len() != stmt.rows.len() || r.response.len() != stmt.n_witness || r.e >= (1u64 << CHALLENGE_BITS)
    }) {
        return false;
    }
    let com: Vec<Vec<G0Affine>> = proof.rounds.iter().map(|r| r.commitment.clone()).collect();
    let base = base_transcript(t, stmt, &com);
    let sum: u64 = proof.rounds.iter().enumerate().map(|(i, r)| h_b(&base, i, r.e, &r.response)).sum();
    if sum > SUM_BOUND {
        return false;
    }
    // every round's equation, batched with random weights
    let mut rng = rand::thread_rng();
    let (mut bases, mut scalars) = (Vec::new(), Vec::new());
    for r in &proof.rounds {
        let e = Fq0::from(r.e);
        for (k, row) in stmt.rows.iter().enumerate() {
            let mut wb = [0u8; 16];
            rng.fill_bytes(&mut wb);
            let rho = Fq0::from_le_bytes_mod_order(&wb);
            for (idx, b) in row {
                bases.push(*b);
                scalars.push(rho * r.response[*idx]);
            }
            bases.push(r.commitment[k]);
            scalars.push(-rho);
            bases.push(stmt.image[k]);
            scalars.push(-(rho * e));
        }
    }
    G0Projective::msm_unchecked(&bases, &scalars).is_zero()
}

// special-soundness extraction from two accepting transcripts
pub fn extract(e1: u64, z1: &[Fq0], e2: u64, z2: &[Fq0]) -> Option<Vec<Fq0>> {
    if e1 == e2 || z1.len() != z2.len() {
        return None;
    }
    let inv = (Fq0::from(e1) - Fq0::from(e2)).inverse()?;
    Some(z1.iter().zip(z2).map(|(a, b)| (*a - b) * inv).collect())
}

