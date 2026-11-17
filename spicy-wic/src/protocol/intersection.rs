// intersection: one message from the sender, which picks the sid
// per slot j: tag_j = H_tag(sid, d, z_j, k_j), e_j = r_j xor H_pad(sid, d, j, z_j, k_j)
// receiver accepts (y_i, j) iff its tag matches tag_j and the unmasked r opens leaf L_j
// a failed opening is dropped, not an abort; aborts only on wrong count, wrong sid length, repeated tags

use std::collections::HashMap;

use ark_std::rand::{CryptoRng, RngCore};

use super::messages::{IntersectionMsg, Tag, E_BYTES, SID_BYTES, TAG_BYTES};
use super::pair_setup::{PointEnc, ReceiverPairState, SenderPairState};
use super::registration::ReceiverSecret;
use crate::error::{AbortReason, Result, SpicyError};
use crate::leaves::{opens, Nonce, NONCE_BYTES};
use crate::oracle::{domain, h_domain};
use crate::params::PublicParams;

// H_tag(sid, d, z, k) cut to lambda bits
pub fn h_tag(sid: &[u8], d: &[u8; 64], z: &[u8; 32], k: &PointEnc) -> Tag {
    let h = h_domain(domain::TAG, &[sid, d, z, k]);
    h[..TAG_BYTES].try_into().unwrap()
}

// H_pad(sid, d, j, z, k) cut to lambda bits
pub fn h_mask(sid: &[u8], d: &[u8; 64], slot: usize, z: &[u8; 32], k: &PointEnc) -> Nonce {
    let h = h_domain(domain::MASK, &[sid, d, &(slot as u64).to_le_bytes(), z, k]);
    h[..E_BYTES].try_into().unwrap()
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

// Intersection_S with a fresh sid
pub fn intersection_s<R: RngCore + CryptoRng>(state: &SenderPairState, rng: &mut R) -> IntersectionMsg {
    let mut sid = vec![0u8; SID_BYTES];
    rng.fill_bytes(&mut sid);
    intersection_s_with_sid(&sid, state)
}

// Intersection_S for a given sid; reusing a sid just repeats an earlier message
pub fn intersection_s_with_sid(sid: &[u8], state: &SenderPairState) -> IntersectionMsg {
    let m = state.k_enc.len();
    let rows: Vec<(Tag, Vec<u8>)> = crate::par::map_range(m, |j| {
        let (z, k) = (&state.z_enc[j], &state.k_enc[j]);
        let e = xor(&state.r[j], &h_mask(sid, &state.d, j, z, k));
        (h_tag(sid, &state.d, z, k), e)
    });
    let mut tags = Vec::with_capacity(m);
    let mut e = Vec::with_capacity(m * E_BYTES);
    for (t, ej) in rows {
        tags.push(t);
        e.extend_from_slice(&ej);
    }
    IntersectionMsg { sid: sid.to_vec(), tags, e }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    // INT, in the receiver's order
    pub int: Vec<Vec<u8>>,
}

// Intersection_R; a failed opening is not visible in the output
pub fn intersection_r(
    pp: &PublicParams,
    state: &ReceiverPairState,
    receiver: &ReceiverSecret,
    msg: &IntersectionMsg,
) -> Result<Output> {
    intersection_r_audit(pp, state, receiver, msg).map(|(out, _)| out)
}

// intersection_r plus the count of matched tags whose opening failed, for local logs only
pub fn intersection_r_audit(
    pp: &PublicParams,
    state: &ReceiverPairState,
    receiver: &ReceiverSecret,
    msg: &IntersectionMsg,
) -> Result<(Output, usize)> {
    let m = pp.params.m;
    let sid = &msg.sid[..];
    if msg.sid.len() != SID_BYTES {
        return Err(SpicyError::abort(AbortReason::MalformedMessage("sid length")));
    }
    if msg.tags.len() != m || msg.e.len() != m * E_BYTES {
        return Err(SpicyError::abort(AbortReason::WrongMessageCount {
            expected: m,
            got: msg.tags.len().min(msg.e.len() / E_BYTES),
        }));
    }
    // tag to slot; a repeated tag aborts
    let mut slot_of: HashMap<&Tag, usize> = HashMap::with_capacity(m);
    for (j, t) in msg.tags.iter().enumerate() {
        if slot_of.insert(t, j).is_some() {
            return Err(SpicyError::abort(AbortReason::MalformedMessage("repeated tag")));
        }
    }
    let n = receiver.elements.len();
    // per element: None (no tag hit), Some(false) (opening failed), Some(true) (accepted)
    let verdict: Vec<Option<(usize, bool)>> = crate::par::map_range(n, |i| {
        let (z, k) = (&state.z_enc[i], &state.k_enc[i]);
        let j = *slot_of.get(&h_tag(sid, &state.d, z, k))?;
        let plain = xor(msg.e_of(j), &h_mask(sid, &state.d, j, z, k));
        let r: Nonce = plain[..NONCE_BYTES].try_into().unwrap();
        Some((j, opens(&state.id_s, j, &state.leaves[j], z, &r)))
    });
    let mut out = Output { int: Vec::new() };
    let mut rejected = 0;
    for (i, v) in verdict.into_iter().enumerate() {
        match v {
            Some((_, true)) => out.int.push(receiver.elements[i].clone()),
            Some((_, false)) => rejected += 1,
            None => {}
        }
    }
    Ok((out, rejected))
}
