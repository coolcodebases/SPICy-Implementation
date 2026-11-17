// mutual oprf from the hash proof system on L_R = {([rho]G0, [rho]W_R)}
// both parties get [rho]pk_{S,l}

use std::collections::HashSet;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_std::rand::{CryptoRng, RngCore};
use ark_std::UniformRand;

use crate::ct;
use crate::encoding::psi_encoding::{decode_psi_msg, encode_psi, interpolate_key, Codec, PkR, NPOLYS};
use crate::error::{Result, SpicyError};
use crate::oracle::h1;
use crate::types::{Fp, Fq0, G0Affine};

// sk_R = (rho_j) for j in [N]
#[derive(Clone)]
pub struct SkR {
    pub rho: Vec<Fq0>,
}

// slot key sk_{S,l} = (s1, s2)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotKey {
    pub s1: Fq0,
    pub s2: Fq0,
}

impl SlotKey {
    // pk_{S,l} = [s1]G0 + [s2]W_R
    pub fn projection(&self, w_r: &G0Affine) -> G0Affine {
        (ct::mul(&G0Affine::generator(), &self.s1) + ct::mul(w_r, &self.s2)).into_affine()
    }

    // hash of a word: [s1]D + [s2]D'
    pub fn hash(&self, d: &G0Affine, d2: &G0Affine) -> G0Affine {
        (ct::mul(d, &self.s1) + ct::mul(d2, &self.s2)).into_affine()
    }
}

// KGen_S: one key per slot, resampled if its projection is O
pub fn kgen_s<R: RngCore + CryptoRng>(t: usize, w_r: &G0Affine, rng: &mut R) -> (Vec<G0Affine>, Vec<SlotKey>) {
    (0..t)
        .map(|_| loop {
            let k = SlotKey { s1: Fq0::rand(rng), s2: Fq0::rand(rng) };
            let pk = k.projection(w_r);
            if !pk.is_zero() {
                break (pk, k);
            }
        })
        .unzip()
}

// a_j = H1(msg_j), checked distinct and nonzero (0 is used for w0)
pub fn check_distinct(msgs: &[Vec<u8>]) -> Result<Vec<Fp>> {
    let mut seen = HashSet::new();
    let mut hs = HashSet::new();
    let mut out = Vec::with_capacity(msgs.len());
    for m in msgs {
        if !seen.insert(m.clone()) {
            return Err(SpicyError::Input("duplicate element in set".into()));
        }
        let a = h1(m);
        if a.is_zero() {
            return Err(SpicyError::Input("H1 value 0 is reserved for w0".into()));
        }
        if !hs.insert(a) {
            return Err(SpicyError::Input("H1 collision between distinct elements".into()));
        }
        out.push(a);
    }
    Ok(out)
}

// KGen_R; rejects empty set, duplicates, equal H1 values and H1 value 0
pub fn kgen_r<R: RngCore + CryptoRng>(msgs: &[Vec<u8>], codec: &Codec, rng: &mut R) -> Result<(PkR, SkR)> {
    if msgs.is_empty() {
        return Err(SpicyError::Input("Receiver set must be non-empty".into()));
    }
    check_distinct(msgs)?;
    let mut rho = Vec::with_capacity(msgs.len());
    let mut pts = Vec::with_capacity(msgs.len());
    for enc in crate::par::map_rng(msgs.len(), rng, |i, r| encode_psi(&msgs[i], codec, r)) {
        let enc = enc?;
        rho.push(enc.rho);
        pts.push((enc.a, enc.w));
    }
    let w0 = [0; NPOLYS].map(|_| Fp::rand(rng));
    let pk = interpolate_key(&pts, w0)?;
    Ok((pk, SkR { rho }))
}

// Eval_S: k_S = [s1]D + [s2]D' with (D, D') = Decode_PSI(pk_R, msg_S)
pub fn eval_s(pk_r: &PkR, codec: &Codec, key: &SlotKey, msg: &[u8]) -> G0Affine {
    let (d, d2) = decode_psi_msg(pk_r, codec, msg);
    key.hash(&d.into_affine(), &d2.into_affine())
}

// Eval_R(pk_S, sk_R): k_(R,j,l) = [rho_j]pk_{S,l}, as out[j][l]
pub fn eval_r(pk_s: &[G0Affine], sk_r: &SkR) -> Vec<Vec<G0Affine>> {
    crate::par::map(&sk_r.rho, |r| pk_s.iter().map(|pk| ct::mul(pk, r).into_affine()).collect())
}

// Match(k_S, {k_(R,j)}) for the slot of k_S
pub fn match_(k_s: &G0Affine, k_r: &[G0Affine]) -> bool {
    k_r.contains(k_s)
}

impl std::fmt::Debug for SkR {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SkR(<secret>)")
    }
}

