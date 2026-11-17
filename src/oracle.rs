// random oracles: H1 into F_p, H_G into G0, and the H_t domain tags
// all domain-separated sha-512; no hash is ever evaluated inside a circuit or sigma proof

use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use sha2::{Digest, Sha512};

use crate::types::Fp;

// domain tags
pub mod domain {
    pub const H1: &[u8] = b"SPICy/H1";
    pub const POW: &[u8] = b"SPICy/H_pow";
    pub const TOK: &[u8] = b"SPICy/H_tok";
    pub const PAIR: &[u8] = b"SPICy/H_pair";
    pub const OPEN: &[u8] = b"SPICy/H_open";
    pub const KEY: &[u8] = b"SPICy/H_key";
    pub const TAU: &[u8] = b"SPICy/H_tau";
    pub const DIGEST: &[u8] = b"SPICy/H_digest";
}

fn sha512_parts(tag: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update((tag.len() as u64).to_le_bytes());
    h.update(tag);
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize().into()
}

// H1: bytes -> F_p by wide reduction
pub fn h1(msg: &[u8]) -> Fp {
    Fp::from_le_bytes_mod_order(&sha512_parts(domain::H1, &[msg]))
}

// H(t || parts), used for the pair digest d
pub fn h_domain(tag: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    sha512_parts(tag, parts)
}

// try-and-increment hash to a cofactor-1 short weierstrass curve, sign of y from a hash bit
pub fn hash_to_curve<P: SWCurveConfig>(label: &[u8]) -> Affine<P>
where
    P::BaseField: PrimeField,
{
    debug_assert_eq!(P::COFACTOR, &[1u64]);
    for ctr in 0u64.. {
        let h = sha512_parts(b"SPICy/hash-to-curve", &[label, &ctr.to_le_bytes()]);
        let x = P::BaseField::from_le_bytes_mod_order(&h);
        let greatest = h[63] & 1 == 1;
        if let Some(pt) = Affine::<P>::get_point_from_x_unchecked(x, greatest) {
            if !pt.is_zero() && pt.is_on_curve() {
                return pt;
            }
        }
    }
    unreachable!()
}

