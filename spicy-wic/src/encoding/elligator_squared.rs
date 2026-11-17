// elligator squared over E: decode phi(u) + phi(v), SamplePreimage by rejection

use ark_ec::{AffineRepr, CurveGroup};
use ark_std::rand::{CryptoRng, Rng, RngCore};
use ark_std::UniformRand;

use crate::error::{Result, SpicyError};
use crate::field::swu::{phi, phi_inverse, D_MAX};
use crate::types::{Fp, G0Affine, G0Projective};

// iteration cap
pub const MAX_ITERATIONS: usize = 4096;

// largest fibre of phi
const FIBRE_MAX: usize = 5;

pub fn decode_pair(u: Fp, v: Fp) -> G0Projective {
    phi(u).into_group() + phi(v)
}

// SamplePreimage(R)
pub fn sample_preimage<R: RngCore + CryptoRng>(r: &G0Affine, rng: &mut R) -> Result<(Fp, Fp)> {
    for _ in 0..MAX_ITERATIONS {
        let u = Fp::rand(rng);
        let j = rng.gen_range(0..D_MAX); // drawn early
        if j >= FIBRE_MAX {
            continue; // at most 5 preimages
        }
        let q = (r.into_group() - crate::field::swu::phi_vt(u)).into_affine();
        if q.is_zero() {
            continue; // S is empty
        }
        let s = phi_inverse(&q);
        if j < s.len() {
            return Ok((u, s[j]));
        }
    }
    Err(SpicyError::SamplingFailed)
}

