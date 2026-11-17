// random oracles: H1, hash to curve, H_tag, H_pad, H_com, pair digest
// all sha-512 with domain separation

use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use sha2::{Digest, Sha512};

use crate::types::Fp;

pub mod domain {
    pub const H1: &[u8] = b"SPICy/H1";
    pub const DIGEST: &[u8] = b"SPICy-WS/H_digest";
    pub const TAG: &[u8] = b"SPICy-WS/H_tag";
    // H_pad, pad of the nonce r_j
    pub const MASK: &[u8] = b"SPICy-WS/H_pad";
    // H_com, sender's hash leaves
    pub const COM: &[u8] = b"SPICy-WS/H_com";
    // context of pi_rep, H(id_S)
    pub const REP_CTX: &[u8] = b"SPICy-WS/pi_rep/ctx";
    // fischlin oracle of pi_rep
    pub const REP: &[u8] = b"SPICy-WS/pi_rep/fischlin";
    // hedged pi_rep nonces from witness, statement and fresh randomness
    pub const REP_NONCE: &[u8] = b"SPICy-WS/pi_rep/nonce";
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

// H1 into F_p by wide reduction
pub fn h1(msg: &[u8]) -> Fp {
    Fp::from_le_bytes_mod_order(&sha512_parts(domain::H1, &[msg]))
}

// domain-separated H(t || parts)
pub fn h_domain(tag: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    sha512_parts(tag, parts)
}

// try-and-increment hash to a cofactor-1 short weierstrass curve
// x = H(label || ctr) until x^3+ax+b is a square, sign of y from a hash bit
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

