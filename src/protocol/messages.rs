// protocol messages
// proofs travel as canonical backend bytes and are only decoded (with full point validation) by the verifier

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::circuits::r_tok::PointCom;
use crate::encoding::psi_encoding::PkR;
use crate::sigma::maurer::SigmaProof;
use crate::sigma::open_relation::OpenProof;
use crate::types::{G0Affine, GcycAffine};

// registration_R output: id_R and pk_R
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RegistrationR {
    pub id_r: Vec<u8>,
    pub pk_r: PkR,
}

// registration_S output: id_S, power rows, pi_pow
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RegistrationS {
    pub id_s: Vec<u8>,
    // rows[0] = Z_1 = rt_S, rows[k-1] = Z_k for k up to S, rows[S] = Z_g
    pub rows: Vec<GcycAffine>,
    pub pi_pow: Vec<u8>,
}

impl RegistrationS {
    pub fn rt_s(&self) -> GcycAffine {
        self.rows[0]
    }
}

// msg_pair = (C_V, C_V', (U_j, T_j, T'_j, pk_{S,j})_j, pi_tok, pi_pair, C_s, pi_s)
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct MsgPair {
    pub c_v: PointCom,
    pub c_v2: PointCom,
    pub u: Vec<G0Affine>,
    pub t: Vec<G0Affine>,
    pub t2: Vec<G0Affine>,
    pub pk_s: Vec<G0Affine>,
    pub pi_tok: Vec<u8>,
    pub pi_pair: Vec<u8>,
    pub c_s: G0Affine,
    pub pi_s: OpenProof,
}

// intersection message (k_(S,j))_j and pi_key
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct IntersectionMsg {
    pub k_s: Vec<G0Affine>,
    pub pi_key: SigmaProof,
}

pub fn size_of<T: CanonicalSerialize>(t: &T) -> usize {
    t.compressed_size()
}
