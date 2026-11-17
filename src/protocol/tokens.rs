// token batches for PairSetup_S
// TokenBundle is not Clone and pair setup consumes it, so each batch serves exactly one pair

use ark_ec::AffineRepr;
use ark_std::rand::RngCore;
use ark_std::UniformRand;

use super::registration::sender_ctx;
use crate::bridge::TokenBatch;
use crate::circuits::r_tok::{RTok, TokStatement, TokWitness};
use crate::curve::coords;
use crate::error::Result;
use crate::params::PublicParams;
use crate::serialize::to_bytes;
use crate::snark::ProofSystem;
use crate::types::Fp;

// a batch with its proof, single use
#[derive(Debug)]
pub struct TokenBundle {
    pub batch: TokenBatch,
    pub stmt: TokStatement,
    pub wit: TokWitness,
    pub pi_tok: Vec<u8>,
    pub id_s: Vec<u8>,
}

// commit to V_j, V'_j and prove R_tok
#[tracing::instrument(level = "info", skip_all)]
pub fn prove_tokens<B: ProofSystem, R: RngCore>(
    pp: &PublicParams,
    id_s: &[u8],
    batch: TokenBatch,
    rng: &mut R,
) -> Result<TokenBundle> {
    let v: Vec<(Fp, Fp)> = batch.0.iter().map(|t| coords(&t.v).expect("V ≠ O")).collect();
    let v2: Vec<(Fp, Fp)> = batch.0.iter().map(|t| coords(&t.v2).expect("V' ≠ O")).collect();
    let r_v = (Fp::rand(rng), Fp::rand(rng));
    let r_v2 = (Fp::rand(rng), Fp::rand(rng));
    let col = |p: &[(Fp, Fp)], y: bool| -> Vec<Fp> { p.iter().map(|q| if y { q.1 } else { q.0 }).collect() };
    let g = crate::snark::spartan::sigma::Gens::cached(v.len());
    debug_assert!(g.vec.g[..v.len()] == pp.gens.g[..v.len()] && g.vec.h == pp.gens.h, "same generators as pp");
    let com = |vals: Vec<Fp>, r: Fp| ark_ec::CurveGroup::into_affine(g.commit_vec(&vals, r));
    let c_v = (com(col(&v, false), r_v.0), com(col(&v, true), r_v.1));
    let c_v2 = (com(col(&v2, false), r_v2.0), com(col(&v2, true), r_v2.1));
    let stmt = TokStatement { c_v, c_v2, u: batch.0.iter().map(|t| t.u).collect() };
    debug_assert!(stmt.u.iter().all(|u| !u.is_zero()));
    let wit = TokWitness { beta: batch.0.iter().map(|t| t.beta).collect(), v, v2, r_v, r_v2 };
    let pi_tok = to_bytes(&B::prove::<RTok, _>(&sender_ctx(id_s), &stmt, &wit, rng)?);
    Ok(TokenBundle { batch, stmt, wit, pi_tok, id_s: id_s.to_vec() })
}
