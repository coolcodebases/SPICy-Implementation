// wic protocol: registration, pair setup, intersection
// guarantees X' subset of X but allows omission

pub mod intersection;
pub mod messages;
pub mod pair_setup;
pub mod registration;
pub mod registry;

use ark_std::rand::{CryptoRng, RngCore};

use crate::error::Result;
use crate::params::PublicParams;

pub use intersection::{intersection_r, intersection_r_audit, intersection_s, intersection_s_with_sid, Output};
pub use pair_setup::{pair_setup_r, pair_setup_s, ReceiverPairState, SenderPairState};
pub use registry::Registry;
pub use registration::{registration_r, registration_s, verify_registration_s, ReceiverSecret, SenderSecret};

// honest sender vs receiver for sessions intersections, returns the receiver's outputs
pub fn run_all<R: RngCore + CryptoRng>(
    pp: &PublicParams,
    x: &[Vec<u8>],
    y: &[Vec<u8>],
    sessions: usize,
    rng: &mut R,
) -> Result<Vec<Output>> {
    let (reg_r, rsec) = registration_r(pp, b"receiver", y, rng)?;
    let (reg_s, ssec) = registration_s(pp, b"sender", x, rng)?;
    let verified = verify_registration_s(pp, &reg_s)?;
    let (msg_pair, s_state) = pair_setup_s(pp, &ssec, &reg_r, rng)?;
    let r_state = pair_setup_r(pp, &verified, &msg_pair, &rsec)?;
    (0..sessions)
        .map(|_| {
            let msg = intersection_s(&s_state, rng);
            intersection_r(pp, &r_state, &rsec, &msg)
        })
        .collect()
}
