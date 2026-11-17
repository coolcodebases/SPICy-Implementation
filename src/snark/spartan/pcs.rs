// non-hiding hyrax pcs for public multilinear polys, used by spark
// rows committed with blind 0, v~(r) = L^T*V*R opened by the log-size dot product proof

use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::ipa::DotProductProofLog;
use super::mle::{eq_table, inner};
use super::sigma::Gens;
use crate::transcript::Transcript;
use crate::types::{Fp, GcycAffine, GcycProjective};

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DenseComm {
    pub num_vars: u32,
    pub rows: Vec<GcycAffine>,
}

// (row vars, column vars) for nv variables
pub fn split(nv: usize) -> (usize, usize) {
    let c = nv.div_ceil(2);
    (nv - c, c)
}

// vector generators needed for up to nv variables
pub fn width_for(nv: usize) -> usize {
    1 << split(nv).1
}

pub fn commit(gens: &Gens, v: &[Fp]) -> DenseComm {
    assert!(v.len().is_power_of_two());
    let nv = v.len().trailing_zeros() as usize;
    let w = 1 << split(nv).1;
    let rows: Vec<GcycProjective> =
        ark_std::cfg_chunks!(v, w).map(|row| gens.commit_vec(row, Fp::zero())).collect();
    DenseComm { num_vars: nv as u32, rows: GcycProjective::normalize_batch(&rows) }
}

// open v~(r), returns (value, proof); transcript absorbs the commitment and the point
pub fn open<R: RngCore>(
    t: &mut Transcript,
    gens: &Gens,
    comm: &DenseComm,
    v: &[Fp],
    r: &[Fp],
    rng: &mut R,
) -> (Fp, DotProductProofLog) {
    let (rv_, cv_) = split(r.len());
    assert_eq!(v.len(), 1 << r.len());
    let l = eq_table(&r[..rv_]);
    let rr = eq_table(&r[rv_..]);
    let w = 1 << cv_;
    let mut tvec = vec![Fp::zero(); w];
    for (i, row) in v.chunks(w).enumerate() {
        for c in 0..w {
            tvec[c] += l[i] * row[c];
        }
    }
    let value = inner(&tvec, &rr);
    let c_l = GcycProjective::msm_unchecked(&comm.rows, &l).into_affine();
    let c_y = (gens.gs * value).into_affine();
    t.append(b"pcs/point", &r.to_vec());
    let proof = DotProductProofLog::prove(t, gens, &tvec, Fp::zero(), &rr, Fp::zero(), &c_l, &c_y, rng);
    (value, proof)
}

pub fn verify(t: &mut Transcript, gens: &Gens, comm: &DenseComm, r: &[Fp], value: Fp, proof: &DotProductProofLog) -> bool {
    let (rv_, _) = split(r.len());
    if comm.num_vars as usize != r.len() || comm.rows.len() != 1 << rv_ {
        return false;
    }
    let l = eq_table(&r[..rv_]);
    let rr = eq_table(&r[rv_..]);
    let c_l = GcycProjective::msm_unchecked(&comm.rows, &l).into_affine();
    let c_y = (gens.gs * value).into_affine();
    t.append(b"pcs/point", &r.to_vec());
    proof.verify(t, gens, &rr, &c_l, &c_y)
}

