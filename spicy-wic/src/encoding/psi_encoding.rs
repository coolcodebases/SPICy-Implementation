// Encode_PSI / Decode_PSI with the four-polynomial key
// pk_R has one polynomial P_c per coordinate through (0, w0[c]) and (a_i, t_{i,c})

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};
use ark_std::UniformRand;

use crate::encoding::elligator_squared::{decode_pair, sample_preimage};
use crate::field::poly::{eval, interpolate};
use crate::oracle::h1;
use crate::types::{Fp, Fq0, G0Affine, G0Projective};

pub const NPOLYS: usize = 4;

// pk_R = (P_1, P_2, P_3, P_4), coeffs low to high
// serialized as common length (u64) then all coeffs, shorter polys zero-padded
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PkR {
    pub polys: Vec<Vec<Fp>>,
}

impl ark_serialize::Valid for PkR {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}

impl CanonicalSerialize for PkR {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut w: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        if self.polys.len() != NPOLYS {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        let len = self.polys.iter().map(Vec::len).max().unwrap_or(0);
        (len as u64).serialize_with_mode(&mut w, compress)?;
        for p in &self.polys {
            for k in 0..len {
                p.get(k).copied().unwrap_or_default().serialize_with_mode(&mut w, compress)?;
            }
        }
        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        let len = self.polys.iter().map(Vec::len).max().unwrap_or(0);
        8 + NPOLYS * len * Fp::zero().serialized_size(compress)
    }
}

impl CanonicalDeserialize for PkR {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut r: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let len = u64::deserialize_with_mode(&mut r, compress, validate)? as usize;
        // do not preallocate from an untrusted length
        let mut polys = Vec::with_capacity(NPOLYS);
        for _ in 0..NPOLYS {
            let mut p = Vec::new();
            for _ in 0..len {
                p.push(Fp::deserialize_with_mode(&mut r, compress, validate)?);
            }
            polys.push(p);
        }
        Ok(PkR { polys })
    }
}

impl PkR {
    pub fn len(&self) -> usize {
        self.polys.iter().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // zero-pad every poly to len coeffs; None if not four polys or one has degree >= len
    pub fn normalized(&self, len: usize) -> Option<PkR> {
        if self.polys.len() != NPOLYS {
            return None;
        }
        let mut polys = Vec::with_capacity(NPOLYS);
        for p in &self.polys {
            if p.len() > len && p[len..].iter().any(|c| !c.is_zero()) {
                return None;
            }
            let mut q = p.clone();
            q.resize(len, Fp::zero());
            polys.push(q);
        }
        Some(PkR { polys })
    }
}

// KGen_R: P_c through (0, w0[c]) and every (a_i, t_{i,c})
// errors if two a_i are equal or one is 0
pub fn interpolate_key(points: &[(Fp, [Fp; 4])], w0: [Fp; NPOLYS]) -> crate::error::Result<PkR> {
    let polys = crate::par::map_range(NPOLYS, |c| {
        let pts: Vec<(Fp, Fp)> = std::iter::once((Fp::zero(), w0[c])).chain(points.iter().map(|(a, t)| (*a, t[c]))).collect();
        interpolate(&pts)
    });
    Ok(PkR { polys: polys.into_iter().collect::<crate::error::Result<Vec<_>>>()? })
}

#[derive(Clone, Copy, Debug)]
pub struct Codec<'a> {
    pub w_r: &'a G0Affine,
    pub mask: &'a [Fp],
}

// Encode_PSI output: rho_e, a = H1(e) and targets w = (u, v, u', v' + g(a))
#[derive(Clone, Debug)]
pub struct Encoded {
    pub rho: Fq0,
    pub a: Fp,
    pub w: [Fp; 4],
}

// Encode_PSI(e)
pub fn encode_psi<R: RngCore + CryptoRng>(e: &[u8], codec: &Codec, rng: &mut R) -> crate::error::Result<Encoded> {
    let rho = loop {
        let r = Fq0::rand(rng);
        if !r.is_zero() {
            break r;
        }
    };
    let r_e = crate::ct::mul(&G0Affine::generator(), &rho).into_affine();
    let r_e2 = crate::ct::mul(codec.w_r, &rho).into_affine();
    let (u, v) = sample_preimage(&r_e, rng)?;
    let (u2, v2) = sample_preimage(&r_e2, rng)?;
    let a = h1(e);
    let ga = eval(codec.mask, a);
    Ok(Encoded { rho, a, w: [u, v, u2, v2 + ga] })
}

// (P_1(z), P_2(z), P_3(z), P_4(z) - g(z)) for a hashed z
pub fn decode_inputs(pk: &PkR, codec: &Codec, z: Fp) -> [Fp; 4] {
    let p = &pk.polys;
    [eval(&p[0], z), eval(&p[1], z), eval(&p[2], z), eval(&p[3], z) - eval(codec.mask, z)]
}

pub fn decode_psi(pk: &PkR, codec: &Codec, z: Fp) -> (G0Projective, G0Projective) {
    let [u, v, u2, v2] = decode_inputs(pk, codec, z);
    (decode_pair(u, v), decode_pair(u2, v2))
}

// Decode_PSI(P, e)
pub fn decode_psi_msg(pk: &PkR, codec: &Codec, e: &[u8]) -> (G0Projective, G0Projective) {
    decode_psi(pk, codec, h1(e))
}

