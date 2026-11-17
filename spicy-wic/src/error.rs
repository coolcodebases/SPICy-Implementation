// errors and abort reasons
// receiver aborts only on malformed msgs and bad pi_rep, never on a failed opening

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbortReason {
    // point not on E, or O where O is not allowed
    BadPoint,
    // Intersection_R: not exactly M pairs
    WrongMessageCount { expected: usize, got: usize },
    // PairSetup_S: pk_R is not four polys of degree at most N
    DegreeTooLarge { len: usize, max: usize },
    // message sizes don't match registration
    MalformedMessage(&'static str),
    // PairSetup_R: pi_rep fails for (W_R, pk_S) with label id_S
    BadProof,
}

#[derive(Debug, Error)]
pub enum SpicyError {
    #[error("protocol abort: {0:?}")]
    Abort(AbortReason),
    #[error("invalid parameters: {0}")]
    Params(String),
    #[error("invalid input: {0}")]
    Input(String),
    #[error("rejection sampling did not terminate")]
    SamplingFailed,
    #[error("serialization: {0}")]
    Serialization(String),
}

impl SpicyError {
    pub fn abort(r: AbortReason) -> Self {
        SpicyError::Abort(r)
    }
}

impl From<ark_serialize::SerializationError> for SpicyError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        SpicyError::Serialization(format!("{e:?}"))
    }
}

pub type Result<T> = std::result::Result<T, SpicyError>;
