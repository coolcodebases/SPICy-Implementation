// transparent backend: the proof is the witness
// verifier checks the r1cs and the row openings
// not zero-knowledge, debugging only

use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;

use super::{cache, r1cs, Layout, ProofSystem};
use crate::circuits::CommittedRelation;
use crate::error::{Result as SResult, SpicyError};
use crate::params::CycGens;
use crate::pedersen::commit_row_affine;
use crate::types::Fp;

pub const HEADER: &[u8; 24] = b"SPICY-INSECURE-NOT-ZK-v1";

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct TransparentProof {
    pub header: Vec<u8>,
    // bound context (prover identity)
    pub ctx: Vec<u8>,
    pub witness: Vec<Fp>,
    pub ext_blinds: Vec<Fp>,
}

pub struct Transparent;

impl ProofSystem for Transparent {
    type Proof = TransparentProof;
    const NAME: &'static str = "transparent (NOT zero-knowledge)";
    const ZERO_KNOWLEDGE: bool = false;

    fn prove<Rel: CommittedRelation, R: RngCore>(
        ctx: &[u8],
        stmt: &Rel::Statement,
        wit: &Rel::Witness,
        _rng: &mut R,
    ) -> SResult<TransparentProof> {
        let _span = tracing::info_span!("prove", relation = Rel::NAME, backend = Self::NAME).entered();
        let cached = cache::shape::<Rel>(stmt)?;
        let width = cached.width;
        let a = r1cs::prove_values::<Rel>(stmt, wit, width, &cached.r1cs)?;
        let io = Rel::public_inputs(stmt).ok_or_else(|| SpicyError::Input("malformed statement".into()))?;
        if a.instance[1..] != io[..] {
            return Err(SpicyError::Synthesis("public input order mismatch".into()));
        }
        Ok(TransparentProof {
            header: HEADER.to_vec(),
            ctx: super::domain_with_ctx(Rel::DOMAIN, ctx),
            witness: a.witness.clone(),
            ext_blinds: Rel::external_openings(wit).into_iter().map(|(_, b)| b).collect(),
        })
    }

    fn verify<Rel: CommittedRelation>(ctx: &[u8], stmt: &Rel::Statement, proof: &TransparentProof) -> bool {
        let _span = tracing::info_span!("verify", relation = Rel::NAME, backend = Self::NAME).entered();
        let run = || -> Option<bool> {
            if proof.header != HEADER || proof.ctx != super::domain_with_ctx(Rel::DOMAIN, ctx) {
                return Some(false);
            }
            let cached = cache::shape::<Rel>(stmt).ok()?;
            let (width, shape) = (cached.width, &*cached.r1cs);
            let mut inst = vec![Fp::from(1u64)];
            inst.extend(Rel::public_inputs(stmt)?);
            let ext = Rel::external_rows(stmt);
            let layout = Layout::new(width, shape.num_wit, shape.num_inst, ext.len());
            if proof.ext_blinds.len() != ext.len() || proof.witness.len() != shape.num_wit {
                return Some(false);
            }
            let gens = CycGens::derive(width);
            let mut padded = proof.witness.clone();
            padded.resize(layout.half(), Fp::zero());
            for (r, c) in ext.iter().enumerate() {
                let row = &padded[r * width..(r + 1) * width];
                if commit_row_affine(&gens, row, proof.ext_blinds[r]) != *c {
                    return Some(false);
                }
            }
            Some(shape.is_satisfied(&inst, &proof.witness))
        };
        run().unwrap_or(false)
    }
}
