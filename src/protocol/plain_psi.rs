// plain psi from OPRF, the baseline without consistency proofs

use ark_ec::AffineRepr;
use ark_std::rand::RngCore;
use rand::seq::SliceRandom;

use crate::encoding::psi_encoding::{Codec, PkR};
use crate::error::{AbortReason, Result, SpicyError};
use crate::oprf::{eval_s, kgen_r, kgen_s, SkR, SlotKey};
use crate::types::G0Affine;

// KGen_R: receiver's key
pub fn receiver_setup<R: RngCore>(y: &[Vec<u8>], codec: &Codec, rng: &mut R) -> Result<(PkR, SkR)> {
    kgen_r(y, codec, rng)
}

// Intersection_S: one sender key per slot
pub fn sender_setup<R: RngCore>(m: usize, w_r: &G0Affine, rng: &mut R) -> (Vec<G0Affine>, Vec<SlotKey>) {
    kgen_s(m, w_r, rng)
}

// Intersection_S: abort if deg pk_R > N_max, shuffle X, then k_(S,j) per slot
pub fn sender_intersect<R: RngCore>(
    x: &[Vec<u8>],
    sk_s: &[SlotKey],
    pk_r: &PkR,
    poly_len: usize,
    codec: &Codec,
    rng: &mut R,
) -> Result<Vec<G0Affine>> {
    let pk_r = pk_r.normalized(poly_len).ok_or(SpicyError::abort(AbortReason::DegreeTooLarge {
        len: pk_r.polys.iter().map(Vec::len).max().unwrap_or(0),
        max: poly_len,
    }))?;
    let mut x = x.to_vec();
    x.shuffle(rng);
    let slots: Vec<(&Vec<u8>, &SlotKey)> = x.iter().zip(sk_s).collect();
    Ok(crate::par::map(&slots, |(xj, k)| eval_s(&pk_r, codec, k, xj)))
}

// Intersection_R
pub fn receiver_output(y: &[Vec<u8>], m: usize, pk_s: &[G0Affine], sk_r: &SkR, k_s: &[G0Affine]) -> Result<Vec<Vec<u8>>> {
    if pk_s.len() != m || k_s.len() != m {
        return Err(SpicyError::abort(AbortReason::MalformedMessage("number of Sender pairs")));
    }
    if pk_s.iter().any(|p| p.is_zero() || !p.is_on_curve()) || k_s.iter().any(|k| !k.is_on_curve()) {
        return Err(SpicyError::abort(AbortReason::BadPoint));
    }
    // key table [rho_i]pk_{S,j}
    let digits = crate::batch_affine::SignedDigits::new(&sk_r.rho);
    let cols: Vec<Vec<G0Affine>> = crate::par::map(pk_s, |pk| crate::batch_affine::fixed_base_many_signed(pk, &digits));
    // collect the matching y_i
    Ok((0..y.len()).filter(|&i| cols.iter().zip(k_s).any(|(col, k)| col[i] == *k)).map(|i| y[i].clone()).collect())
}
