// registration: receiver publishes pk_R from KGen_R, sender the M hash leaves in random slot order with no proof

use std::collections::HashSet;

use ark_std::rand::{CryptoRng, RngCore};
use rand::seq::SliceRandom;

use super::messages::{RegistrationR, RegistrationS};
use super::pair_setup::enc_fp;
use crate::encoding::psi_encoding::{Codec, PkR};
use crate::error::{AbortReason, Result, SpicyError};
use crate::leaves::{leaf, Leaf, Nonce, NONCE_BYTES};
use crate::oprf::{check_distinct, kgen_r, SkR};
use crate::params::{w_r, PublicParams};
use crate::types::{Fp, G0Affine};

// sk_R = (rho_i) and the receiver's elements, same order
#[derive(Clone)]
pub struct ReceiverSecret {
    pub id_r: Vec<u8>,
    pub w_r: G0Affine,
    pub pk_r: PkR,
    pub sk_r: SkR,
    pub elements: Vec<Vec<u8>>,
    // z_i = H1(y_i)
    pub z: Vec<Fp>,
}

// Registration_R(1^lambda, Y, pp)
pub fn registration_r<R: RngCore + CryptoRng>(
    pp: &PublicParams,
    id_r: &[u8],
    y: &[Vec<u8>],
    rng: &mut R,
) -> Result<(RegistrationR, ReceiverSecret)> {
    if y.len() != pp.params.n {
        return Err(SpicyError::Input(format!("|Y| = {} ≠ N = {}", y.len(), pp.params.n)));
    }
    let w = w_r(id_r);
    let codec = Codec { w_r: &w, mask: &pp.mask };
    let (pk_r, sk_r) = kgen_r(y, &codec, rng)?;
    let z = check_distinct(y)?;
    Ok((
        RegistrationR { id_r: id_r.to_vec(), pk_r: pk_r.clone() },
        ReceiverSecret { id_r: id_r.to_vec(), w_r: w, pk_r, sk_r, elements: y.to_vec(), z },
    ))
}

// sender's secret state; elements[j] is the element in slot j
#[derive(Clone)]
pub struct SenderSecret {
    pub id_s: Vec<u8>,
    pub elements: Vec<Vec<u8>>,
    // z_j = H1(x_j)
    pub z: Vec<Fp>,
    // nonces r_j
    pub r: Vec<Nonce>,
    pub leaves: Vec<Leaf>,
}

// Registration_S(1^lambda, X, pp)
pub fn registration_s<R: RngCore + CryptoRng>(
    pp: &PublicParams,
    id_s: &[u8],
    x: &[Vec<u8>],
    rng: &mut R,
) -> Result<(RegistrationS, SenderSecret)> {
    let m = pp.params.m;
    if x.len() != m {
        return Err(SpicyError::Input(format!("|X| = {} ≠ M = {m}", x.len())));
    }
    let mut x = x.to_vec();
    x.shuffle(rng);
    let z = check_distinct(&x)?; // z_j = H1(x_j), distinct
    let r: Vec<Nonce> = (0..m)
        .map(|_| {
            let mut n = [0u8; NONCE_BYTES];
            rng.fill_bytes(&mut n);
            n
        })
        .collect();
    let leaves: Vec<Leaf> = crate::par::map_range(m, |j| leaf(id_s, j, &enc_fp(&z[j]), &r[j]));
    Ok((
        RegistrationS { id_s: id_s.to_vec(), leaves: leaves.clone() },
        SenderSecret { id_s: id_s.to_vec(), elements: x, z, r, leaves },
    ))
}

// sender registration with exactly M distinct leaves
#[derive(Clone, Debug)]
pub struct VerifiedSender {
    reg: RegistrationS,
}

impl VerifiedSender {
    pub fn reg(&self) -> &RegistrationS {
        &self.reg
    }
}

// checks there are M leaves, all distinct
pub fn verify_registration_s(pp: &PublicParams, reg: &RegistrationS) -> Result<VerifiedSender> {
    let bad = |r| Err(SpicyError::abort(r));
    if reg.leaves.len() != pp.params.m {
        return bad(AbortReason::MalformedMessage("number of leaves"));
    }
    let set: HashSet<&Leaf> = reg.leaves.iter().collect();
    if set.len() != reg.leaves.len() {
        return bad(AbortReason::MalformedMessage("repeated leaf"));
    }
    Ok(VerifiedSender { reg: reg.clone() })
}

impl std::fmt::Debug for ReceiverSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReceiverSecret(<secret>)")
    }
}

impl std::fmt::Debug for SenderSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SenderSecret(<secret>)")
    }
}
