// registration (Registration_R / Registration_S)

use ark_ec::AffineRepr;
use ark_std::rand::RngCore;
use ark_std::UniformRand;
use rand::seq::SliceRandom;

use super::messages::{RegistrationR, RegistrationS};
use crate::circuits::r_pow::{PowStatement, PowWitness, RPow};
use crate::encoding::psi_encoding::{Codec, PkR};
use crate::error::{AbortReason, Relation, Result, SpicyError};
use crate::oprf::{check_distinct, kgen_r, SkR};
use crate::params::{w_r, PublicParams};
use crate::pedersen::power_rows::{build_ps_rows, PowerRows, PowerRowsSecret};
use crate::pedersen::vector_pedersen_root;
use crate::serialize::{from_bytes, to_bytes};
use crate::sigma::context;
use crate::snark::ProofSystem;
use crate::types::{Fp, G0Affine};

// receiver's secret state; elements are in the order of sk_R
#[derive(Clone, Debug)]
pub struct ReceiverSecret {
    pub id_r: Vec<u8>,
    pub w_r: G0Affine,
    pub pk_r: PkR,
    pub sk_r: SkR,
    pub elements: Vec<Vec<u8>>,
}

// (pk_R, sk_R) from OPRF KGen_R
#[tracing::instrument(level = "info", skip_all)]
pub fn registration_r<R: RngCore>(
    pp: &PublicParams,
    id_r: &[u8],
    y: &[Vec<u8>],
    rng: &mut R,
) -> Result<(RegistrationR, ReceiverSecret)> {
    if y.len() != pp.params.n {
        return Err(SpicyError::Input(format!("|Y| = {} ≠ N = {}", y.len(), pp.params.n)));
    }
    let w = w_r(id_r);
    let codec = Codec { w_r: &w, mask: &pp.mask };
    let (pk_r, sk_r) = kgen_r(y, &codec, rng)?;
    Ok((
        RegistrationR { id_r: id_r.to_vec(), pk_r: pk_r.clone() },
        ReceiverSecret { id_r: id_r.to_vec(), w_r: w, pk_r, sk_r, elements: y.to_vec() },
    ))
}

// sender's secret state; elements[j] sits in slot j
#[derive(Clone, Debug)]
pub struct SenderSecret {
    pub id_s: Vec<u8>,
    pub elements: Vec<Vec<u8>>,
    pub z: Vec<Fp>,
    pub rows: PowerRows,
    pub rows_secret: PowerRowsSecret,
    // pi_pow as published, it goes into tau
    pub pi_pow: Vec<u8>,
}

// context of the sender's proofs: its identity
pub fn sender_ctx(id_s: &[u8]) -> Vec<u8> {
    context(&[b"id_S", id_s])
}

// Registration_S
#[tracing::instrument(level = "info", skip_all)]
pub fn registration_s<B: ProofSystem, R: RngCore>(
    pp: &PublicParams,
    id_s: &[u8],
    x: &[Vec<u8>],
    rng: &mut R,
) -> Result<(RegistrationS, SenderSecret)> {
    let m = pp.params.m;
    if x.len() != m {
        return Err(SpicyError::Input(format!("|X| = {} ≠ M = {m}", x.len())));
    }
    let mut x = x.to_vec();
    x.shuffle(rng);
    let z = check_distinct(&x)?;
    let r: Vec<Fp> = (0..m).map(|_| Fp::rand(rng)).collect();
    // only rt_S and r_1 leave this function
    let (rt, r1) = vector_pedersen_root(&pp.gens, &z, &r);
    // power rows in paterson-stockmeyer form
    let (rows, rows_secret) = build_ps_rows(&pp.gens, &z, r1, pp.params.ps_step, &pp.mask, rng);
    debug_assert_eq!(rows[0], rt);
    let stmt = PowStatement { m, n_g: pp.params.n_g, rows: rows.clone() };
    let wit = PowWitness { powers: rows_secret.powers.clone(), blinds: rows_secret.blinds.clone() };
    let pi_pow = to_bytes(&B::prove::<RPow, _>(&sender_ctx(id_s), &stmt, &wit, rng)?);
    Ok((
        RegistrationS { id_s: id_s.to_vec(), rows: rows.clone(), pi_pow: pi_pow.clone() },
        SenderSecret { id_s: id_s.to_vec(), elements: x, z, rows, rows_secret, pi_pow },
    ))
}

// a sender registration whose pi_pow was verified
// pair setup only takes this type
#[derive(Clone, Debug)]
pub struct VerifiedSender(RegistrationS);

impl VerifiedSender {
    pub fn reg(&self) -> &RegistrationS {
        &self.0
    }
}

// pi_pow verify plus well-formedness of the registration
#[tracing::instrument(level = "info", skip_all)]
pub fn verify_registration_s<B: ProofSystem>(pp: &PublicParams, reg: &RegistrationS) -> Result<VerifiedSender> {
    let bad = |r| Err(SpicyError::abort(r));
    if reg.rows.len() != pp.params.n_rows() {
        return bad(AbortReason::MalformedMessage("number of power rows"));
    }
    if reg.rows.iter().any(|p| p.is_zero() || !p.is_on_curve()) {
        return bad(AbortReason::BadPoint);
    }
    let Ok(proof) = from_bytes::<B::Proof>(&reg.pi_pow) else {
        return bad(AbortReason::ProofRejected(Relation::Pow));
    };
    let stmt = PowStatement { m: pp.params.m, n_g: pp.params.n_g, rows: reg.rows.clone() };
    if !B::verify::<RPow>(&sender_ctx(&reg.id_s), &stmt, &proof) {
        return bad(AbortReason::ProofRejected(Relation::Pow));
    }
    Ok(VerifiedSender(reg.clone()))
}
