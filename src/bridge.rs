// elgamal product bridge and one-time token batches
// a TokenBatch is not Clone and is consumed by value

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_std::rand::RngCore;
use ark_std::UniformRand;

use crate::ct;
use crate::types::{Fq0, G0Affine, G0Projective};

// elgamal commitment Com_EG(R; beta)
pub fn com_eg(r: &G0Affine, beta: &Fq0, g0: &G0Affine, h: &G0Affine) -> (G0Affine, G0Affine) {
    let u = ct::mul(g0, beta).into_affine();
    let t = (r.into_group() + ct::mul(h, beta)).into_affine();
    (u, t)
}

// scale an elgamal commitment by s
pub fn linear_scale(s: &Fq0, ut: &(G0Affine, G0Affine)) -> (G0Affine, G0Affine) {
    ((ut.0 * s).into_affine(), (ut.1 * s).into_affine())
}

// one token: beta_j with U_j = [beta_j]G0, V_j = [beta_j]H0, V'_j = [beta_j]H0'
#[derive(Debug)]
pub struct Token {
    pub beta: Fq0,
    pub u: G0Affine,
    pub v: G0Affine,
    pub v2: G0Affine,
}

// fresh token batch, one token per slot, not Clone
#[derive(Debug)]
pub struct TokenBatch(pub Vec<Token>);

#[derive(Clone, Copy, Debug)]
pub struct TokenBases {
    pub g0: G0Affine,
    pub h0: G0Affine,
    pub h0p: G0Affine,
}

// constant-time fixed-base tables for the token bases
#[derive(Clone, Debug)]
pub struct TokenTables {
    g0: ct::FixedBase<ark_pallas::PallasConfig>,
    h0: ct::FixedBase<ark_pallas::PallasConfig>,
    h0p: ct::FixedBase<ark_pallas::PallasConfig>,
}

impl TokenTables {
    pub fn new(bases: &TokenBases) -> Self {
        TokenTables {
            g0: ct::FixedBase::new(&bases.g0),
            h0: ct::FixedBase::new(&bases.h0),
            h0p: ct::FixedBase::new(&bases.h0p),
        }
    }
}

// token with a random nonzero beta
pub fn sample_token<R: RngCore>(bases: &TokenBases, rng: &mut R) -> Token {
    sample_token_with(&TokenTables::new(bases), rng)
}

// sample_token with precomputed tables
pub fn sample_token_with<R: RngCore>(tables: &TokenTables, rng: &mut R) -> Token {
    loop {
        let beta = Fq0::rand(rng);
        if beta.is_zero() {
            continue;
        }
        let u = tables.g0.mul(&beta).into_affine();
        if u.is_zero() {
            continue;
        }
        let v = tables.h0.mul(&beta).into_affine();
        let v2 = tables.h0p.mul(&beta).into_affine();
        return Token { beta, u, v, v2 };
    }
}

impl TokenBatch {
    pub fn sample<R: RngCore>(m: usize, bases: &TokenBases, rng: &mut R) -> Self {
        let tables = TokenTables::new(bases);
        TokenBatch(crate::par::map_rng(m, rng, |_, r| sample_token_with(&tables, r)))
    }

    // batch for the decoded pairs (R_j, R'_j) of PairSetup_S
    // beta_j is resampled while U_j, T_j or T'_j is O
    pub fn sample_bridged<R: RngCore>(decoded: &[(G0Projective, G0Projective)], bases: &TokenBases, rng: &mut R) -> Self {
        let tables = TokenTables::new(bases);
        TokenBatch(crate::par::map_rng(decoded.len(), rng, |j, r| loop {
            let t = sample_token_with(&tables, r);
            if !(decoded[j].0 + t.v).is_zero() && !(decoded[j].1 + t.v2).is_zero() {
                break t;
            }
        }))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

