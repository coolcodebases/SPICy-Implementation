// in-memory bulletin board, each identity registers once and is never overwritten
// real deployments need an authenticated board

use std::collections::HashMap;

use super::messages::{RegistrationR, RegistrationS};
use crate::error::{AbortReason, Result, SpicyError};
use crate::params::PublicParams;
use crate::serialize::to_bytes;

// receiver keys by identity
#[derive(Default)]
pub struct Registry {
    receivers: HashMap<Vec<u8>, Vec<u8>>,
    senders: HashMap<Vec<u8>, Vec<u8>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    // store normalised pk_R for id_R; a different key for a stored identity is refused
    pub fn register_receiver(&mut self, pp: &PublicParams, reg: &RegistrationR) -> Result<()> {
        let canon = reg.pk_r.normalized(pp.params.poly_len()).ok_or(SpicyError::abort(AbortReason::DegreeTooLarge {
            len: reg.pk_r.polys.iter().map(Vec::len).max().unwrap_or(0),
            max: pp.params.poly_len(),
        }))?;
        let enc = to_bytes(&canon);
        match self.receivers.get(&reg.id_r) {
            Some(stored) if *stored != enc => Err(SpicyError::abort(AbortReason::MalformedMessage(
                "a different key is already registered for this Receiver identity",
            ))),
            Some(_) => Ok(()),
            None => {
                self.receivers.insert(reg.id_r.clone(), enc);
                Ok(())
            }
        }
    }

    // store id_S's leaves; different leaves for a stored identity are refused
    pub fn register_sender(&mut self, reg: &RegistrationS) -> Result<()> {
        let enc = to_bytes(&reg.leaves);
        match self.senders.get(&reg.id_s) {
            Some(stored) if *stored != enc => Err(SpicyError::abort(AbortReason::MalformedMessage(
                "different leaves are already registered for this Sender identity",
            ))),
            Some(_) => Ok(()),
            None => {
                self.senders.insert(reg.id_s.clone(), enc);
                Ok(())
            }
        }
    }

    // are reg's leaves the ones registered for its identity?
    pub fn is_registered_sender(&self, reg: &RegistrationS) -> bool {
        self.senders.get(&reg.id_s).is_some_and(|stored| *stored == to_bytes(&reg.leaves))
    }

    // is reg the key registered for its identity?
    pub fn is_registered(&self, pp: &PublicParams, reg: &RegistrationR) -> bool {
        match (self.receivers.get(&reg.id_r), reg.pk_r.normalized(pp.params.poly_len())) {
            (Some(stored), Some(canon)) => *stored == to_bytes(&canon),
            _ => false,
        }
    }
}
