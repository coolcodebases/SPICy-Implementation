// key relation R_key, proved at every intersection
// linear in (a_j, b_j) for public tau; maurer proof under ctx = (id_S, sid, d)
// witness order: (a_j, b_j, gamma_(j,1), gamma_(j,2)) at 4j..4j+3, then r at 4M

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::oracle::domain;
use crate::sigma::maurer::{self, LinearStatement, Precommit, SigmaProof};
use crate::transcript::Transcript;
use crate::types::{Fq0, G0Affine, G0Projective};

// public part of the key statement without the prf values, which only enter the image
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct KeyStatement {
    pub tau: Fq0,
    pub c_s: G0Affine,
    pub pk_s: Vec<G0Affine>,
    pub u: Vec<G0Affine>,
    pub t: Vec<G0Affine>,
    pub t2: Vec<G0Affine>,
}

#[derive(Clone, Debug)]
pub struct KeyWitness {
    pub a: Vec<Fq0>,
    pub b: Vec<Fq0>,
    pub gamma1: Vec<Fq0>,
    pub gamma2: Vec<Fq0>,
    pub r: Fq0,
}

impl KeyWitness {
    pub fn vector(&self) -> Vec<Fq0> {
        let m = self.a.len();
        let mut w = Vec::with_capacity(4 * m + 1);
        for j in 0..m {
            w.extend([self.a[j], self.b[j], self.gamma1[j], self.gamma2[j]]);
        }
        w.push(self.r);
        w
    }
}

#[derive(Clone, Copy, Debug)]
pub struct KeyBases<'a> {
    pub g0: &'a G0Affine,
    pub h0: &'a G0Affine,
    pub h0p: &'a G0Affine,
    pub w_r: &'a G0Affine,
    pub b: &'a [(G0Affine, G0Affine)],
    pub b0: &'a G0Affine,
}

// slot scalars (s_(j,1), s_(j,2)) from (a_j, b_j)
pub fn slot_scalars(tau: &Fq0, a: &Fq0, b: &Fq0) -> (Fq0, Fq0) {
    (*a + *tau * b, *b + tau.square() * a)
}

fn well_formed(stmt: &KeyStatement, m: usize, bases: &KeyBases) -> bool {
    stmt.pk_s.len() == m
        && stmt.u.len() == m
        && stmt.t.len() == m
        && stmt.t2.len() == m
        && bases.b.len() == m
        && stmt.pk_s.iter().all(|p| !p.is_zero())
}

// linear map of R_key, None if the statement is malformed or some pk_(S,j) = O
pub fn linear(stmt: &KeyStatement, k: &[G0Affine], bases: &KeyBases) -> Option<LinearStatement> {
    let m = k.len();
    if !well_formed(stmt, m, bases) {
        return None;
    }
    let tau = stmt.tau;
    let tau2 = tau.square();
    let neg = |p: &G0Affine| (-p.into_group()).into_affine();
    let g0 = bases.g0.into_group();
    let w = bases.w_r.into_group();
    let pk_a = (g0 + w * tau2).into_affine();
    let pk_b = (g0 * tau + w).into_affine();
    let (neg_g0, neg_h0, neg_h0p) = (neg(bases.g0), neg(bases.h0), neg(bases.h0p));
    // per-slot bases
    let per_slot: Vec<G0Projective> = crate::par::map_range(m, |j| {
        let (t, t2, u) = (stmt.t[j].into_group(), stmt.t2[j].into_group(), stmt.u[j].into_group());
        [t + t2 * tau2, t * tau + t2, u * tau, u * tau2]
    })
    .into_iter()
    .flatten()
    .collect();
    let per_slot = G0Projective::normalize_batch(&per_slot);

    let mut rows = Vec::with_capacity(4 * m + 1);
    let mut image = Vec::with_capacity(4 * m + 1);
    let mut cs_row = Vec::with_capacity(2 * m + 1);
    for (j, (b1, b2)) in bases.b.iter().enumerate() {
        cs_row.push((4 * j, *b1));
        cs_row.push((4 * j + 1, *b2));
    }
    cs_row.push((4 * m, *bases.b0));
    rows.push(cs_row);
    image.push(stmt.c_s);
    for j in 0..m {
        let (ia, ib, ig1, ig2) = (4 * j, 4 * j + 1, 4 * j + 2, 4 * j + 3);
        let [tt, tt2, tu, tu2] = [per_slot[4 * j], per_slot[4 * j + 1], per_slot[4 * j + 2], per_slot[4 * j + 3]];
        rows.push(vec![(ia, pk_a), (ib, pk_b)]);
        image.push(stmt.pk_s[j]);
        rows.push(vec![(ia, tt), (ib, tt2), (ig1, neg_h0), (ig2, neg_h0p)]);
        image.push(k[j]);
        rows.push(vec![(ia, stmt.u[j]), (ib, tu), (ig1, neg_g0)]);
        image.push(G0Affine::zero());
        rows.push(vec![(ia, tu2), (ib, stmt.u[j]), (ig2, neg_g0)]);
        image.push(G0Affine::zero());
    }
    Some(LinearStatement { n_witness: 4 * m + 1, rows, image })
}

// lin with one session's prf values as the image of the k_(S,j) rows
pub fn with_prf_values(lin: &LinearStatement, k: &[G0Affine]) -> Option<LinearStatement> {
    if lin.image.len() != 4 * k.len() + 1 {
        return None;
    }
    let mut out = lin.clone();
    for (j, kj) in k.iter().enumerate() {
        out.image[4 * j + 2] = *kj;
    }
    Some(out)
}

fn transcript(ctx: &[u8]) -> Transcript {
    let mut t = Transcript::new(domain::KEY);
    t.append_bytes(b"ctx", ctx);
    t
}

// offline first message for pi_key, single use
pub fn precommit_key<R: ark_std::rand::RngCore>(lin: &LinearStatement, rng: &mut R) -> Precommit {
    maurer::precommit(lin, rng)
}

pub fn prove_key(ctx: &[u8], lin: &LinearStatement, wit: &KeyWitness, pre: Precommit) -> SigmaProof {
    maurer::prove_with(&mut transcript(ctx), lin, &wit.vector(), pre)
}

pub fn verify_key(ctx: &[u8], lin: &LinearStatement, proof: &SigmaProof) -> bool {
    maurer::verify(&mut transcript(ctx), lin, proof)
}

// unbatched verification
pub fn verify_key_each(ctx: &[u8], lin: &LinearStatement, proof: &SigmaProof) -> bool {
    maurer::verify_each(&mut transcript(ctx), lin, proof)
}
