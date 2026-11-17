// proof systems for the F_p relations (pi_pow, pi_tok, pi_pair)
// spartan is zk spartan + hyrax over G_cyc with the statement's rows as first witness rows; transparent is for debugging only

pub mod cache;
pub mod matrix;
pub mod r1cs;
pub mod spartan;
pub mod transparent;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;

use crate::circuits::CommittedRelation;
use crate::error::Result;

pub trait ProofSystem {
    type Proof: Clone + std::fmt::Debug + CanonicalSerialize + CanonicalDeserialize;
    const NAME: &'static str;
    const ZERO_KNOWLEDGE: bool;

    // ctx (prover identity) goes into the fiat-shamir transcript
    fn prove<Rel: CommittedRelation, R: RngCore>(
        ctx: &[u8],
        stmt: &Rel::Statement,
        wit: &Rel::Witness,
        rng: &mut R,
    ) -> Result<Self::Proof>;

    fn verify<Rel: CommittedRelation>(ctx: &[u8], stmt: &Rel::Statement, proof: &Self::Proof) -> bool;
}

// H_t domain bound to a context: t || 0 || len(ctx) || ctx
pub fn domain_with_ctx(domain: &[u8], ctx: &[u8]) -> Vec<u8> {
    let mut d = domain.to_vec();
    d.push(0);
    d.extend_from_slice(&(ctx.len() as u64).to_le_bytes());
    d.extend_from_slice(ctx);
    d
}

// hyrax row width W: power of two >= M, balanced against witness size (about sqrt n)
// deterministic in the statement so prover and verifier agree
pub fn choose_width<Rel: CommittedRelation>(stmt: &Rel::Statement) -> Result<usize> {
    if let Some(w) = Rel::fixed_width(stmt) {
        return Ok(w.max(Rel::m(stmt)).max(2).next_power_of_two());
    }
    let w0 = Rel::m(stmt).max(2).next_power_of_two();
    // only the witness count is needed
    let num_wit = match Rel::slot_layout(stmt, None, w0) {
        Some(l) => l.num_witnesses()?,
        None => r1cs::shape(Rel::circuit(stmt, None, w0))?.num_wit,
    };
    let log_n = (num_wit.max(2) as f64).log2().ceil() as u32;
    Ok(w0.max(1usize << log_n.div_ceil(2)))
}

// R rows of width W with R*W = 2^s >= max(#witness, #instance)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub width: usize,
    pub rows: usize,
    pub ext_rows: usize,
}

impl Layout {
    pub fn new(width: usize, num_wit: usize, num_inst: usize, ext_rows: usize) -> Self {
        let rows_needed = num_wit.div_ceil(width).max(ext_rows).max(1);
        let mut rows = rows_needed.next_power_of_two();
        while rows * width < num_inst {
            rows *= 2;
        }
        Layout { width, rows, ext_rows }
    }

    // padded witness length 2^s
    pub fn half(&self) -> usize {
        self.rows * self.width
    }
}
