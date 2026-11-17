// sender's explicit commitment, one hash leaf per element: C_j = H_com(id_S, j, z_j, r_j)

use crate::oracle::{domain, h_domain};

// 2*lambda bits
pub const LEAF_BYTES: usize = 32;
// lambda bits
pub const NONCE_BYTES: usize = 16;

pub type Leaf = [u8; LEAF_BYTES];
pub type Nonce = [u8; NONCE_BYTES];

// C = H_com(id_S, j, z, r), z canonically encoded
pub fn leaf(id_s: &[u8], slot: usize, z_enc: &[u8; 32], r: &Nonce) -> Leaf {
    let h = h_domain(domain::COM, &[id_s, &(slot as u64).to_le_bytes(), z_enc, r]);
    h[..LEAF_BYTES].try_into().unwrap()
}

// does (z, r) open c as slot slot of id_s?
pub fn opens(id_s: &[u8], slot: usize, c: &Leaf, z_enc: &[u8; 32], r: &Nonce) -> bool {
    leaf(id_s, slot, z_enc, r) == *c
}

