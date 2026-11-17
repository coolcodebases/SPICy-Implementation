// one-time pair setup (PairSetup_S / PairSetup_R)
// receiver checks pi_pair against its own pk_R and the registered rows, then computes all N*M keys k_(R,i,j)

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_std::rand::RngCore;
use ark_std::UniformRand;

use super::messages::{MsgPair, RegistrationR};
use super::registration::{sender_ctx, ReceiverSecret, SenderSecret, VerifiedSender};
use super::tokens::{prove_tokens, TokenBundle};
use crate::bridge::{TokenBases, TokenBatch};
use crate::circuits::r_pair::{PairStatement, PairWitness, RPair};
use crate::circuits::r_tok::{RTok, TokStatement};
use crate::ct;
use crate::encoding::psi_encoding::PkR;
use crate::encoding::elligator_squared::decode_pair;
use crate::error::{AbortReason, Relation, Result, SpicyError};
use crate::oracle::{domain, h_domain};
use crate::params::{w_r, PublicParams};
use crate::pedersen::derived::{block_commitments, block_openings};
use crate::pedersen::power_rows::z0;
use crate::serialize::{from_bytes, to_bytes};
use crate::sigma::key_relation::{self, slot_scalars, KeyBases, KeyStatement, KeyWitness};
use crate::sigma::maurer::{LinearStatement, Precommit};
use crate::sigma::open_relation::{commit_cs, prove_open, verify_open, OpenBases, OpenWitness};
use crate::snark::ProofSystem;
use crate::types::{Fq0, G0Affine, G0Projective, GcycAffine};

// the coin tau
pub fn coin(id_s: &[u8], id_r: &[u8], pk_r: &PkR, rows: &[GcycAffine], pi_pow: &[u8], c_s: &G0Affine, pi_s: &crate::sigma::open_relation::OpenProof) -> Fq0 {
    let h = h_domain(
        domain::TAU,
        &[id_s, id_r, &to_bytes(pk_r), &to_bytes(&rows.to_vec()), pi_pow, &to_bytes(c_s), &to_bytes(pi_s)],
    );
    Fq0::from_le_bytes_mod_order(&h)
}

pub fn pair_digest(pk_r: &PkR, rt_s: &GcycAffine, msg: &MsgPair) -> [u8; 64] {
    h_domain(domain::DIGEST, &[&to_bytes(pk_r), &to_bytes(rt_s), &to_bytes(msg)])
}

fn key_bases<'a>(pp: &'a PublicParams, w: &'a G0Affine) -> KeyBases<'a> {
    KeyBases { g0: &pp.g0, h0: &pp.h0, h0p: &pp.h0p, w_r: w, b: &pp.b, b0: &pp.b0 }
}

// sender state after pair setup plus a pool of precomputed R_key first messages
// not Clone
#[derive(Debug)]
pub struct SenderPairState {
    pub id_s: Vec<u8>,
    pub d: [u8; 64],
    pub stmt_key: KeyStatement,
    // k_(S,j), same in every session
    pub k: Vec<G0Affine>,
    pub lin: LinearStatement,
    pub wit: KeyWitness,
    pub(crate) pool: Vec<Precommit>,
}

impl SenderPairState {
    // precompute n first messages for pi_key, each is used once
    pub fn precompute<R: RngCore>(&mut self, n: usize, rng: &mut R) {
        for _ in 0..n {
            self.pool.push(key_relation::precommit_key(&self.lin, rng));
        }
    }

    pub fn precomputed(&self) -> usize {
        self.pool.len()
    }
}

// PairSetup_S relations without the proofs
#[derive(Debug)]
pub struct PairRelations {
    pub pk_r: PkR,
    pub w_r: G0Affine,
    pub r: Vec<G0Affine>,
    pub r2: Vec<G0Affine>,
    // consumed by pair setup
    pub tokens: TokenBundle,
    pub pair_stmt: PairStatement,
    pub pair_wit: PairWitness,
}

// token batch with pi_tok made before the receiver is known
// pair setup samples a fresh batch instead if some T_j or T'_j would be O
// single use
#[tracing::instrument(level = "info", skip_all)]
pub fn precompute_tokens<B: ProofSystem, R: RngCore>(pp: &PublicParams, sender: &SenderSecret, rng: &mut R) -> Result<TokenBundle> {
    let bases = TokenBases { g0: pp.g0, h0: pp.h0, h0p: pp.h0p };
    let batch = TokenBatch::sample(pp.params.m, &bases, rng);
    prove_tokens::<B, R>(pp, &sender.id_s, batch, rng)
}

// PairSetup_S without pi_pair
pub fn build_pair_relations<B: ProofSystem, R: RngCore>(
    pp: &PublicParams,
    sender: &SenderSecret,
    reg_r: &RegistrationR,
    rng: &mut R,
) -> Result<PairRelations> {
    build_pair_relations_with::<B, R>(pp, sender, reg_r, None, rng)
}

// build_pair_relations with an optional precomputed token batch
#[tracing::instrument(level = "info", skip_all)]
pub fn build_pair_relations_with<B: ProofSystem, R: RngCore>(
    pp: &PublicParams,
    sender: &SenderSecret,
    reg_r: &RegistrationR,
    pre: Option<TokenBundle>,
    rng: &mut R,
) -> Result<PairRelations> {
    let m = pp.params.m;
    let poly_len = pp.params.poly_len();
    // check the degree of pk_R
    let pk_r = reg_r.pk_r.normalized(poly_len).ok_or(SpicyError::abort(AbortReason::DegreeTooLarge {
        len: reg_r.pk_r.polys.iter().map(Vec::len).max().unwrap_or(0),
        max: poly_len,
    }))?;
    let w = w_r(&reg_r.id_r);
    // openings of the block commitments
    let rs = &sender.rows_secret;
    let (s_ps, nb) = (pp.params.ps_step, pp.params.key_blocks());
    let blk_open = block_openings(&rs.powers, &rs.blinds, &pk_r.polys, s_ps, nb);
    let blocks = block_commitments(z0(&pp.gens, m), &sender.rows, &pk_r.polys, s_ps, nb);
    let mut pair_wit = PairWitness {
        blocks: blk_open.iter().map(|o| o.0.clone()).collect(),
        block_blinds: blk_open.iter().map(|o| o.1).collect(),
        zs: rs.powers[s_ps - 1].clone(),
        zs_blind: rs.blinds[s_ps - 1],
        v: Vec::new(),
        v2: Vec::new(),
        r_v: Default::default(),
        r_v2: Default::default(),
    };
    // decode the pairs
    let decoded: Vec<(G0Projective, G0Projective)> = crate::par::map_range(m, |j| {
        let [u, v, u2, v2] = pair_wit.dec(j);
        (decode_pair(u, v), decode_pair(u2, v2))
    });
    // resample beta_j if U_j, T_j or T'_j is O
    let usable = |b: &TokenBundle| {
        b.id_s == sender.id_s
            && b.batch.0.len() == m
            && b.batch.0.iter().zip(&decoded).all(|(tk, d)| !(d.0 + tk.v).is_zero() && !(d.1 + tk.v2).is_zero())
    };
    let tokens = match pre {
        Some(b) if usable(&b) => b,
        _ => {
            let bases = TokenBases { g0: pp.g0, h0: pp.h0, h0p: pp.h0p };
            let batch = TokenBatch::sample_bridged(&decoded, &bases, rng);
            prove_tokens::<B, R>(pp, &sender.id_s, batch, rng)?
        }
    };
    let t: Vec<G0Projective> = decoded.iter().zip(&tokens.batch.0).map(|(d, tk)| d.0 + tk.v).collect();
    let t2: Vec<G0Projective> = decoded.iter().zip(&tokens.batch.0).map(|(d, tk)| d.1 + tk.v2).collect();
    let (t, t2) = (G0Projective::normalize_batch(&t), G0Projective::normalize_batch(&t2));
    let r: Vec<G0Affine> = G0Projective::normalize_batch(&decoded.iter().map(|d| d.0).collect::<Vec<_>>());
    let r2: Vec<G0Affine> = G0Projective::normalize_batch(&decoded.iter().map(|d| d.1).collect::<Vec<_>>());
    let pair_stmt = PairStatement { blocks, zs: sender.rows[s_ps - 1], c_v: tokens.stmt.c_v, c_v2: tokens.stmt.c_v2, t, t2 };
    pair_wit.v = tokens.wit.v.clone();
    pair_wit.v2 = tokens.wit.v2.clone();
    pair_wit.r_v = tokens.wit.r_v;
    pair_wit.r_v2 = tokens.wit.r_v2;
    Ok(PairRelations { pk_r, w_r: w, r, r2, tokens, pair_stmt, pair_wit })
}

// PairSetup_S
pub fn pair_setup_s<B: ProofSystem, R: RngCore>(
    pp: &PublicParams,
    sender: &SenderSecret,
    reg_r: &RegistrationR,
    rng: &mut R,
) -> Result<(MsgPair, SenderPairState)> {
    pair_setup_s_with::<B, R>(pp, sender, reg_r, None, rng)
}

// pair_setup_s with an optional precomputed token batch
#[tracing::instrument(level = "info", skip_all)]
pub fn pair_setup_s_with<B: ProofSystem, R: RngCore>(
    pp: &PublicParams,
    sender: &SenderSecret,
    reg_r: &RegistrationR,
    pre: Option<TokenBundle>,
    rng: &mut R,
) -> Result<(MsgPair, SenderPairState)> {
    let m = pp.params.m;
    let PairRelations { pk_r, w_r: w, r, r2, tokens, pair_stmt, pair_wit } =
        build_pair_relations_with::<B, R>(pp, sender, reg_r, pre, rng)?;
    let (t, t2) = (pair_stmt.t.clone(), pair_stmt.t2.clone());
    let pi_pair = to_bytes(&B::prove::<RPair, _>(&sender_ctx(&sender.id_s), &pair_stmt, &pair_wit, rng)?);
    // resample everything if some pk_{S,j} = O
    let open_bases = OpenBases { b: &pp.b, b0: &pp.b0 };
    let _sp = tracing::info_span!("keys_and_coin").entered();
    let (open_wit, c_s, pi_s, tau, pk_s, s) = loop {
        let open_wit = OpenWitness {
            a: (0..m).map(|_| Fq0::rand(rng)).collect(),
            b: (0..m).map(|_| Fq0::rand(rng)).collect(),
            r: Fq0::rand(rng),
        };
        let c_s = commit_cs(&open_bases, &open_wit);
        let pi_s = prove_open(&sender_ctx(&sender.id_s), &open_bases, &c_s, &open_wit, rng);
        let tau = coin(&sender.id_s, &reg_r.id_r, &pk_r, &sender.rows, &sender.pi_pow, &c_s, &pi_s);
        let s: Vec<(Fq0, Fq0)> = (0..m).map(|j| slot_scalars(&tau, &open_wit.a[j], &open_wit.b[j])).collect();
        let pk_s: Vec<G0Projective> = crate::par::map(&s, |(s1, s2)| ct::mul(&pp.g0, s1) + ct::mul(&w, s2));
        if pk_s.iter().all(|p| !p.is_zero()) {
            break (open_wit, c_s, pi_s, tau, G0Projective::normalize_batch(&pk_s), s);
        }
    };
    drop(_sp);
    let _sp = tracing::info_span!("k_s").entered();
    let k: Vec<G0Projective> = crate::par::map_range(m, |j| ct::mul(&r[j], &s[j].0) + ct::mul(&r2[j], &s[j].1));
    let k = G0Projective::normalize_batch(&k);
    let gamma1: Vec<Fq0> = (0..m).map(|j| s[j].0 * tokens.batch.0[j].beta).collect();
    let gamma2: Vec<Fq0> = (0..m).map(|j| s[j].1 * tokens.batch.0[j].beta).collect();
    let msg = MsgPair {
        c_v: tokens.stmt.c_v,
        c_v2: tokens.stmt.c_v2,
        u: tokens.stmt.u.clone(),
        t,
        t2,
        pk_s,
        pi_tok: tokens.pi_tok.clone(),
        pi_pair,
        c_s,
        pi_s,
    };
    let d = pair_digest(&pk_r, &sender.rows[0], &msg);
    drop(tokens); // the batch is consumed here
    let stmt_key = KeyStatement { tau, c_s, pk_s: msg.pk_s.clone(), u: msg.u.clone(), t: msg.t.clone(), t2: msg.t2.clone() };
    drop(_sp);
    let _sp = tracing::info_span!("lin_key").entered();
    let lin = key_relation::linear(&stmt_key, &k, &key_bases(pp, &w)).expect("honest key statement is well formed");
    let wit = KeyWitness { a: open_wit.a.clone(), b: open_wit.b.clone(), gamma1, gamma2, r: open_wit.r };
    Ok((msg, SenderPairState { id_s: sender.id_s.clone(), d, stmt_key, k, lin, wit, pool: Vec::new() }))
}

// [rho_i]pk for all the receiver's scalars, variable time
pub fn k_r_column(pk: &G0Affine, rho: &[Fq0]) -> Vec<G0Affine> {
    crate::batch_affine::fixed_base_many(pk, rho)
}

// receiver state after pair setup
#[derive(Clone, Debug)]
pub struct ReceiverPairState {
    pub id_s: Vec<u8>,
    pub tau: Fq0,
    pub d: [u8; 64],
    // R_key's map with a placeholder for k, filled in per session
    pub lin: LinearStatement,
    pub k_r: super::key_table::KeyTable,
}

// PairSetup_R. pi_pow was already checked when the VerifiedSender was built
#[tracing::instrument(level = "info", skip_all)]
pub fn pair_setup_r<B: ProofSystem>(
    pp: &PublicParams,
    sender: &VerifiedSender,
    msg: &MsgPair,
    receiver: &ReceiverSecret,
) -> Result<ReceiverPairState> {
    let reg = sender.reg();
    let m = pp.params.m;
    let abort = |r| Err(SpicyError::abort(r));
    let _sp_checks = tracing::info_span!("point_checks").entered();
    // all points in their groups and not O
    if [msg.u.len(), msg.t.len(), msg.t2.len(), msg.pk_s.len()].iter().any(|l| *l != m) {
        return abort(AbortReason::MalformedMessage("msg_pair length"));
    }
    let g0_pts = msg.u.iter().chain(&msg.t).chain(&msg.t2).chain(&msg.pk_s).chain(std::iter::once(&msg.c_s));
    if g0_pts.clone().any(|p| p.is_zero() || !p.is_on_curve()) {
        return abort(AbortReason::BadPoint);
    }
    let cyc = [msg.c_v.0, msg.c_v.1, msg.c_v2.0, msg.c_v2.1];
    if cyc.iter().any(|p| p.is_zero() || !p.is_on_curve()) {
        return abort(AbortReason::BadPoint);
    }
    drop(_sp_checks);
    // proof checks and the key table run in parallel, but the reported abort is still the first failing check in the order pi_tok, pi_pair, pi_s
    let sctx = sender_ctx(&reg.id_s);
    let pk_own = receiver
        .pk_r
        .normalized(pp.params.poly_len())
        .ok_or(SpicyError::Input("own pk_R has a polynomial of degree above N".into()))?;
    let s_ps = pp.params.ps_step;
    let check_tok = || {
        let _sp = tracing::info_span!("check_pi_tok").entered();
        let tok_stmt = TokStatement { c_v: msg.c_v, c_v2: msg.c_v2, u: msg.u.clone() };
        from_bytes::<B::Proof>(&msg.pi_tok).map(|p| B::verify::<RTok>(&sctx, &tok_stmt, &p)).unwrap_or(false)
    };
    let check_pair = || {
        let _sp = tracing::info_span!("check_pi_pair").entered();
        // block commitments from the Receiver's own pk_R
        let blocks = block_commitments(z0(&pp.gens, m), &reg.rows, &pk_own.polys, s_ps, pp.params.key_blocks());
        let pair_stmt = PairStatement {
            blocks,
            zs: reg.rows[s_ps - 1],
            c_v: msg.c_v,
            c_v2: msg.c_v2,
            t: msg.t.clone(),
            t2: msg.t2.clone(),
        };
        from_bytes::<B::Proof>(&msg.pi_pair).map(|p| B::verify::<RPair>(&sctx, &pair_stmt, &p)).unwrap_or(false)
    };
    let check_open = || verify_open(&sctx, &OpenBases { b: &pp.b, b0: &pp.b0 }, &msg.c_s, &msg.pi_s);
    // key table k_(R,i,j)
    let rho = &receiver.sk_r.rho;
    let key_table = || {
        let _sp = tracing::info_span!("k_r_table", entries = rho.len() * m).entered();
        let digits = crate::batch_affine::SignedDigits::new(rho);
        let cols = crate::par::map(&msg.pk_s, |pk: &G0Affine| crate::batch_affine::fixed_base_many_signed(pk, &digits));
        super::key_table::KeyTable::from_full_columns(cols)
    };
    let ((ok_tok, ok_pair), (ok_open, k_r)) =
        crate::par::join(|| crate::par::join(check_tok, check_pair), || crate::par::join(check_open, key_table));
    if !ok_tok {
        return abort(AbortReason::ProofRejected(Relation::Tok));
    }
    if !ok_pair {
        return abort(AbortReason::ProofRejected(Relation::Pair));
    }
    if !ok_open {
        return abort(AbortReason::ProofRejected(Relation::Open));
    }
    let _sp_lin = tracing::info_span!("coin_digest_lin").entered();
    let tau = coin(&reg.id_s, &receiver.id_r, &receiver.pk_r, &reg.rows, &reg.pi_pow, &msg.c_s, &msg.pi_s);
    let d = pair_digest(&receiver.pk_r, &reg.rt_s(), msg);
    let stmt_key = KeyStatement { tau, c_s: msg.c_s, pk_s: msg.pk_s.clone(), u: msg.u.clone(), t: msg.t.clone(), t2: msg.t2.clone() };
    let lin = key_relation::linear(&stmt_key, &vec![G0Affine::zero(); m], &key_bases(pp, &receiver.w_r))
        .ok_or(SpicyError::abort(AbortReason::BadPoint))?;
    drop(_sp_lin);
    Ok(ReceiverPairState { id_s: reg.id_s.clone(), tau, d, lin, k_r })
}

