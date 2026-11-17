// protocol messages and their sizes

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::encoding::psi_encoding::PkR;
use crate::leaves::{Leaf, NONCE_BYTES};
use crate::rep_proof::RepProof;
use crate::types::G0Affine;

// lambda bits
pub const TAG_BYTES: usize = 16;
pub type Tag = [u8; TAG_BYTES];

// lambda bits
pub const E_BYTES: usize = NONCE_BYTES;

// Registration_R: id_R and pk_R
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RegistrationR {
    pub id_r: Vec<u8>,
    pub pk_r: PkR,
}

// Registration_S: id_S and the M hash leaves in slot order
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RegistrationS {
    pub id_s: Vec<u8>,
    pub leaves: Vec<Leaf>,
}

// msg_pair: pk_S = [s1]G0 + [s2]W_R and pi_rep
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct MsgPair {
    pub pk_s: G0Affine,
    pub proof: RepProof,
}

// lambda bits
pub const SID_BYTES: usize = 16;

// intersection message: sid and one (tag_j, e_j) per slot, e_j concatenated
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct IntersectionMsg {
    pub sid: Vec<u8>,
    pub tags: Vec<Tag>,
    pub e: Vec<u8>,
}

impl IntersectionMsg {
    // masked nonce of slot j
    pub fn e_of(&self, j: usize) -> &[u8] {
        &self.e[j * E_BYTES..(j + 1) * E_BYTES]
    }
    pub fn e_of_mut(&mut self, j: usize) -> &mut [u8] {
        &mut self.e[j * E_BYTES..(j + 1) * E_BYTES]
    }
}

// compressed encoding size in bytes
pub fn size_of<T: CanonicalSerialize>(t: &T) -> usize {
    t.compressed_size()
}
