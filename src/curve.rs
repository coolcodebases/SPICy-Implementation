// affine coordinate helpers on E

use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};

use crate::types::{Fp, Fq0, G0Affine, N0};

pub type Xy = (Fp, Fp);

pub fn coords(p: &G0Affine) -> Option<Xy> {
    p.xy().map(|(x, y)| (*x, *y))
}

pub fn from_coords(p: Xy) -> G0Affine {
    G0Affine::new_unchecked(p.0, p.1)
}

// big-endian n0-bit decomposition of a scalar
pub fn scalar_bits_be(beta: &Fq0) -> Vec<bool> {
    let mut le = beta.into_bigint().to_bits_le();
    le.truncate(N0);
    le.reverse();
    le
}

pub fn is_identity(p: &G0Affine) -> bool {
    p.is_zero()
}
