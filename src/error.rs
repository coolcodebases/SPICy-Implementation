// errors and abort reasons

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    Pow,
    Tok,
    Pair,
    Open,
    Key,
}

// why a party aborted
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbortReason {
    // PairSetup_R or Intersection_R rejected a proof
    ProofRejected(Relation),
    // PairSetup_R / Intersection_R: invalid point, or O where it isn't allowed
    BadPoint,
    // Intersection_R: not exactly M prf values
    WrongMessageCount { expected: usize, got: usize },
    // PairSetup_S: pk_R isn't four polys of degree at most N
    // this is the only check the honest sender makes on pk_R
    DegreeTooLarge { len: usize, max: usize },
    // statement sizes don't match registration
    MalformedMessage(&'static str),
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
    #[error("constraint synthesis failed: {0}")]
    Synthesis(String),
    #[error("prover witness does not satisfy the relation: {0}")]
    UnsatisfiedWitness(String),
    #[error("serialization: {0}")]
    Serialization(String),
}

impl SpicyError {
    pub fn abort(r: AbortReason) -> Self {
        SpicyError::Abort(r)
    }
}

impl From<ark_relations::r1cs::SynthesisError> for SpicyError {
    fn from(e: ark_relations::r1cs::SynthesisError) -> Self {
        SpicyError::Synthesis(format!("{e:?}"))
    }
}

impl From<ark_serialize::SerializationError> for SpicyError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        SpicyError::Serialization(format!("{e:?}"))
    }
}

pub type Result<T> = std::result::Result<T, SpicyError>;
