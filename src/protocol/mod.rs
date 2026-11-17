// the spicy protocol and the plain psi baseline

pub mod intersection;
pub mod key_table;
pub mod messages;
pub mod pair_setup;
pub mod plain_psi;
pub mod registration;
pub mod tokens;

use ark_std::rand::RngCore;

use crate::error::Result;
use crate::params::PublicParams;
use crate::snark::ProofSystem;

pub use intersection::{intersection_r, intersection_s};
pub use pair_setup::{pair_setup_r, pair_setup_s, ReceiverPairState, SenderPairState};
pub use registration::{registration_r, registration_s, verify_registration_s, ReceiverSecret, SenderSecret};
pub use tokens::{prove_tokens, TokenBundle};

// registration, pair setup and some intersection sessions between honest parties
pub fn run_all<B: ProofSystem, R: RngCore>(
    pp: &PublicParams,
    x: &[Vec<u8>],
    y: &[Vec<u8>],
    sessions: usize,
    rng: &mut R,
) -> Result<Vec<Vec<Vec<u8>>>> {
    let (reg_r, rsec) = registration_r(pp, b"receiver", y, rng)?;
    let (reg_s, ssec) = registration_s::<B, _>(pp, b"sender", x, rng)?;
    let verified = verify_registration_s::<B>(pp, &reg_s)?;
    let (msg_pair, mut s_state) = pair_setup_s::<B, _>(pp, &ssec, &reg_r, rng)?;
    let r_state = pair_setup_r::<B>(pp, &verified, &msg_pair, &rsec)?;
    let mut outs = Vec::with_capacity(sessions);
    for s in 0..sessions {
        let sid = format!("session-{s}").into_bytes();
        let msg = intersection_s(&sid, &mut s_state, rng);
        outs.push(intersection_r(pp, &sid, &r_state, &rsec, &msg)?);
    }
    Ok(outs)
}
