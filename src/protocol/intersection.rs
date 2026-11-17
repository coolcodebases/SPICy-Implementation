// intersection (Intersection_S / Intersection_R)

use std::collections::BTreeSet;

use ark_std::rand::RngCore;

use super::messages::IntersectionMsg;
use super::pair_setup::{ReceiverPairState, SenderPairState};
use super::registration::ReceiverSecret;
use crate::error::{AbortReason, Relation, Result, SpicyError};
use crate::params::PublicParams;
use crate::sigma::context;
use crate::sigma::key_relation::{precommit_key, prove_key, verify_key, with_prf_values};

// session context from id_S, sid and d
pub fn session_ctx(id_s: &[u8], sid: &[u8], d: &[u8]) -> Vec<u8> {
    context(&[b"id_S", id_s, b"sid", sid, b"d", d])
}

// same k_(S,j) every session, fresh pi_key bound to (id_S, sid, d)
#[tracing::instrument(level = "info", skip_all)]
pub fn intersection_s<R: RngCore>(sid: &[u8], state: &mut SenderPairState, rng: &mut R) -> IntersectionMsg {
    let ctx = session_ctx(&state.id_s, sid, &state.d);
    let pre = state.pool.pop().unwrap_or_else(|| precommit_key(&state.lin, rng));
    let pi_key = prove_key(&ctx, &state.lin, &state.wit, pre);
    IntersectionMsg { k_s: state.k.clone(), pi_key }
}

// returns INT in the receiver's order, or aborts
#[tracing::instrument(level = "info", skip_all)]
pub fn intersection_r(
    pp: &PublicParams,
    sid: &[u8],
    state: &ReceiverPairState,
    receiver: &ReceiverSecret,
    msg: &IntersectionMsg,
) -> Result<Vec<Vec<u8>>> {
    let m = pp.params.m;
    if msg.k_s.len() != m {
        return Err(SpicyError::abort(AbortReason::WrongMessageCount { expected: m, got: msg.k_s.len() }));
    }
    if msg.k_s.iter().any(|k| !k.is_on_curve()) {
        return Err(SpicyError::abort(AbortReason::BadPoint));
    }
    // verify pi_key
    let lin = with_prf_values(&state.lin, &msg.k_s).ok_or(SpicyError::abort(AbortReason::MalformedMessage("k_S")))?;
    if !verify_key(&session_ctx(&state.id_s, sid, &state.d), &lin, &msg.pi_key) {
        return Err(SpicyError::abort(AbortReason::ProofRejected(Relation::Key)));
    }
    // collect the matching y_i
    let mut hit = BTreeSet::new();
    for (j, kj) in msg.k_s.iter().enumerate() {
        hit.extend(state.k_r.matches(j, kj));
    }
    Ok(hit.into_iter().map(|i| receiver.elements[i].clone()).collect())
}
