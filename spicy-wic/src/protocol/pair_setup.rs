// pair setup, once per pair of registered sets
// sender picks one key (s1, s2), computes k_j = [s1]D_j + [s2]D'_j at Decode_PSI(pk_R, z_j), sends pk_S and pi_rep
// one key serves all slots; receiver gets K_i = [rho_i]pk_S

use ark_ec::{AffineRepr, CurveGroup};
use ark_std::rand::{CryptoRng, RngCore};
use ark_std::UniformRand;
use zeroize::Zeroize;

use super::messages::{MsgPair, RegistrationR};
use super::registration::{ReceiverSecret, SenderSecret, VerifiedSender};
use crate::ct;
use crate::encoding::psi_encoding::{decode_psi, Codec, PkR};
use crate::error::{AbortReason, Result, SpicyError};
use crate::leaves::{Leaf, Nonce};
use crate::oracle::{domain, h_domain};
use crate::params::{w_r, PublicParams};
use crate::rep_proof;
use crate::serialize::to_bytes;
use crate::types::{Fp, Fq0, G0Affine, G0Projective};

fn leaves_bytes(leaves: &[Leaf]) -> Vec<u8> {
    leaves.concat()
}

// label of pi_rep, H(id_S)
pub fn rep_context(id_s: &[u8]) -> [u8; 64] {
    h_domain(domain::REP_CTX, &[id_s])
}

// pair digest d
pub fn pair_digest(id_s: &[u8], id_r: &[u8], pk_r: &PkR, leaves: &[Leaf], pk_s: &G0Affine) -> [u8; 64] {
    h_domain(domain::DIGEST, &[id_s, id_r, &to_bytes(pk_r), &leaves_bytes(leaves), &to_bytes(pk_s)])
}

// compressed encodings of points and field elements, inputs of H_tag and H_pad
pub type PointEnc = [u8; 33];
pub fn enc_point(p: &G0Affine) -> PointEnc {
    to_bytes(p).try_into().expect("Pallas points compress to 33 bytes")
}
pub fn enc_fp(z: &Fp) -> [u8; 32] {
    to_bytes(z).try_into().expect("F_p elements encode to 32 bytes")
}

// sender state after pair setup; secret, wiped on drop, Debug prints only d and the size
pub struct SenderPairState {
    pub d: [u8; 64],
    // z_j and k_j in slot order
    pub(crate) z_enc: Vec<[u8; 32]>,
    pub(crate) k_enc: Vec<PointEnc>,
    // r_j in slot order
    pub(crate) r: Vec<Nonce>,
}

impl Drop for SenderPairState {
    fn drop(&mut self) {
        self.k_enc.iter_mut().for_each(|k| k.zeroize());
        self.z_enc.iter_mut().for_each(|z| z.zeroize());
        self.r.iter_mut().for_each(|r| r.zeroize());
    }
}

impl std::fmt::Debug for SenderPairState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderPairState").field("d", &self.d).field("slots", &self.k_enc.len()).finish_non_exhaustive()
    }
}

impl SenderPairState {
    // secret state accessors
    #[doc(hidden)]
    pub fn k_enc(&self) -> &[PointEnc] {
        &self.k_enc
    }
    #[doc(hidden)]
    pub fn z_enc(&self) -> &[[u8; 32]] {
        &self.z_enc
    }
    #[doc(hidden)]
    pub fn nonces(&self) -> &[Nonce] {
        &self.r
    }
}

// PairSetup_S(pk_R, (z_j, r_j))
pub fn pair_setup_s<R: RngCore + CryptoRng>(
    pp: &PublicParams,
    sender: &SenderSecret,
    reg_r: &RegistrationR,
    rng: &mut R,
) -> Result<(MsgPair, SenderPairState)> {
    let m = pp.params.m;
    let poly_len = pp.params.poly_len();
    // the only check on pk_R
    let pk_r = reg_r.pk_r.normalized(poly_len).ok_or(SpicyError::abort(AbortReason::DegreeTooLarge {
        len: reg_r.pk_r.polys.iter().map(Vec::len).max().unwrap_or(0),
        max: poly_len,
    }))?;
    let w = w_r(&reg_r.id_r);
    // resample if pk_S = O
    let (mut s1, mut s2, pk_s) = loop {
        let (s1, s2) = (Fq0::rand(rng), Fq0::rand(rng));
        let pk = (ct::mul(&pp.g0, &s1) + ct::mul(&w, &s2)).into_affine();
        if !pk.is_zero() {
            break (s1, s2, pk);
        }
    };
    let codec = Codec { w_r: &w, mask: &pp.mask };
    let k: Vec<G0Projective> = crate::par::map_range(m, |j| {
        let (d1, d2) = decode_psi(&pk_r, &codec, sender.z[j]);
        ct::mul(&d1.into_affine(), &s1) + ct::mul(&d2.into_affine(), &s2)
    });
    let k = G0Projective::normalize_batch(&k);
    // pi_rep for (W_R, pk_S), label id_S
    let ctx = rep_context(&sender.id_s);
    let proof = rep_proof::prove(&ctx, &pp.g0, &w, &pk_s, &s1, &s2, rng)?;
    s1.zeroize();
    s2.zeroize();
    let msg = MsgPair { pk_s, proof };
    // d over the normalised key
    let d = pair_digest(&sender.id_s, &reg_r.id_r, &pk_r, &sender.leaves, &pk_s);
    let state = SenderPairState {
        d,
        z_enc: sender.z.iter().map(enc_fp).collect(),
        k_enc: crate::par::map(&k, enc_point),
        r: sender.r.clone(),
    };
    Ok((msg, state))
}

// receiver state after pair setup; secret, wiped on drop, Debug prints only public fields
pub struct ReceiverPairState {
    pub d: [u8; 64],
    pub id_s: Vec<u8>,
    pub leaves: Vec<Leaf>,
    // z_i and K_i = [rho_i]pk_S in receiver order
    pub(crate) z_enc: Vec<[u8; 32]>,
    pub(crate) k_enc: Vec<PointEnc>,
}

impl Drop for ReceiverPairState {
    fn drop(&mut self) {
        self.k_enc.iter_mut().for_each(|k| k.zeroize());
        self.z_enc.iter_mut().for_each(|z| z.zeroize());
    }
}

impl std::fmt::Debug for ReceiverPairState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiverPairState").field("d", &self.d).field("id_s", &self.id_s).finish_non_exhaustive()
    }
}

// PairSetup_R(leaves, msg_pair, sk_R)
pub fn pair_setup_r(
    pp: &PublicParams,
    sender: &VerifiedSender,
    msg: &MsgPair,
    receiver: &ReceiverSecret,
) -> Result<ReceiverPairState> {
    if msg.pk_s.is_zero() || !msg.pk_s.is_on_curve() {
        return Err(SpicyError::abort(AbortReason::BadPoint));
    }
    let reg = sender.reg();
    let ctx = rep_context(&reg.id_s);
    if !rep_proof::verify(&ctx, &pp.g0, &receiver.w_r, &msg.pk_s, &msg.proof) {
        return Err(SpicyError::abort(AbortReason::BadProof));
    }
    let pk_r = receiver
        .pk_r
        .normalized(pp.params.poly_len())
        .ok_or(SpicyError::Input("own pk_R exceeds the degree bound".into()))?;
    let d = pair_digest(&reg.id_s, &receiver.id_r, &pk_r, &reg.leaves, &msg.pk_s);
    let k: Vec<G0Projective> = crate::par::map(&receiver.sk_r.rho, |rho| ct::mul(&msg.pk_s, rho));
    let k = G0Projective::normalize_batch(&k);
    Ok(ReceiverPairState {
        d,
        id_s: reg.id_s.clone(),
        leaves: reg.leaves.clone(),
        z_enc: receiver.z.iter().map(enc_fp).collect(),
        k_enc: crate::par::map(&k, enc_point),
    })
}
