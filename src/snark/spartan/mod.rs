// zk spartan with hyrax witness commitments over G_cyc
// (Az) o (Bz) = Cz with z = (w, 1, io), the first ext_rows rows of w open the given pre-committed rows
// two zk sum-checks, then w~(r_y) opened with hyrax + log-size dot product; verifier evaluates M(r_x, r_y) itself, or checks a spark proof in snark mode
// the verifier-supplied row commitments are how pi_pow, pi_tok and pi_pair share Z_k and C_V

pub mod ipa;
pub mod mle;
pub mod pcs;
pub mod product;
pub mod spark;
pub mod sigma;
pub mod sumcheck;

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{One, Zero, Field};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use ark_std::UniformRand;
use zeroize::Zeroize;

use self::ipa::DotProductProofLog;
use self::mle::{eq_eval, eq_table, fold, inner, log2, mle_eval, sum_arrays};
use self::sigma::{EqualityProof, Gens, ProductProof};
use self::spark::{SparkKey, SparkProof};
use self::sumcheck::{Claim, Tables, ZkSumcheckProof};
use super::r1cs::{self, R1cs};
use super::{cache, Layout, ProofSystem};
use crate::circuits::CommittedRelation;
use crate::error::{Result as SResult, SpicyError};
use crate::transcript::Transcript;
use crate::types::{Fp, GcycAffine, GcycProjective};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SpartanProof {
    pub fresh_rows: Vec<GcycAffine>,
    pub sc1: ZkSumcheckProof,
    pub c_va: GcycAffine,
    pub c_vb: GcycAffine,
    pub c_vc: GcycAffine,
    pub c_vab: GcycAffine,
    pub prod: ProductProof,
    pub eq1: EqualityProof,
    pub sc2: ZkSumcheckProof,
    pub c_vw: GcycAffine,
    pub hyrax: DotProductProofLog,
    pub eq2: EqualityProof,
    // snark mode only: M(r_x, r_y) in the clear and its spark proof
    pub m_eval: Option<Fp>,
    pub spark: Option<SparkProof>,
}

fn col(layout: &Layout, num_inst: usize, k: usize) -> usize {
    if k < num_inst {
        layout.half() + k
    } else {
        k - num_inst
    }
}

fn absorb_instance(t: &mut Transcript, shape: &R1cs, layout: &Layout, io: &[Fp], rows: &[GcycAffine]) {
    for d in shape.dims() {
        t.append_u64(b"dims", d);
    }
    t.append_u64(b"width", layout.width as u64);
    t.append_u64(b"rows", layout.rows as u64);
    t.append_u64(b"ext_rows", layout.ext_rows as u64);
    t.append(b"io", &io.to_vec());
    t.append(b"row_comms", &rows.to_vec());
}

// phase-1 tables with eq factored per variable (gruen 2024)
// the prover evaluates the quadratic factor q at 0, 1, 2 and never folds an eq table
struct Phase1 {
    tau: Vec<Fp>,
    // suffix[j] = eq(tau_{j+1..}, .), over the variables after round j
    suffix: Vec<Vec<Fp>>,
    round: usize,
    prefix: Fp,
    a: Vec<Fp>,
    b: Vec<Fp>,
    c: Vec<Fp>,
}

impl Phase1 {
    fn new(tau: Vec<Fp>, a: Vec<Fp>, b: Vec<Fp>, c: Vec<Fp>) -> Self {
        // suffix tables from the last variable backwards
        let n = tau.len();
        let mut suffix = vec![Vec::new(); n];
        if n > 0 {
            suffix[n - 1] = vec![Fp::one()];
            for k in (0..n - 1).rev() {
                let t = tau[k + 1];
                let rest = &suffix[k + 1];
                let mut out = Vec::with_capacity(2 * rest.len());
                out.extend(rest.iter().map(|v| *v - *v * t));
                out.extend(rest.iter().map(|v| *v * t));
                suffix[k] = out;
            }
        }
        Phase1 { tau, suffix, round: 0, prefix: Fp::one(), a, b, c }
    }
}

impl Tables for Phase1 {
    fn round_evals(&self) -> Vec<Fp> {
        let half = self.a.len() / 2;
        let e = &self.suffix[self.round];
        let q = sum_arrays::<3>(half, |i| {
            let (a0, a1) = (self.a[i], self.a[i + half]);
            let (b0, b1) = (self.b[i], self.b[i + half]);
            let (c0, c1) = (self.c[i], self.c[i + half]);
            // values at X = 2
            let (a2, b2, c2) = (a1.double() - a0, b1.double() - b0, c1.double() - c0);
            let w = e[i];
            [w * (a0 * b0 - c0), w * (a1 * b1 - c1), w * (a2 * b2 - c2)]
        });
        // q(3) from the quadratic through q(0), q(1), q(2)
        let q3 = q[2].double() + q[2] - q[1].double() - q[1] + q[0];
        let t = self.tau[self.round];
        let l = |x: u64| {
            let x = Fp::from(x);
            (Fp::one() - t) * (Fp::one() - x) + t * x
        };
        [q[0], q[1], q[2], q3].iter().enumerate().map(|(x, qx)| self.prefix * l(x as u64) * qx).collect()
    }

    fn bind(&mut self, r: Fp) {
        let t = self.tau[self.round];
        self.prefix *= (Fp::one() - t) * (Fp::one() - r) + t * r;
        self.round += 1;
        fold(&mut self.a, r);
        fold(&mut self.b, r);
        fold(&mut self.c, r);
    }
}

struct Phase2 {
    m: Vec<Fp>,
    z: Vec<Fp>,
}

impl Tables for Phase2 {
    fn round_evals(&self) -> Vec<Fp> {
        let half = self.m.len() / 2;
        sum_arrays::<3>(half, |i| {
            let (m0, dm) = (self.m[i], self.m[i + half] - self.m[i]);
            let (z0, dz) = (self.z[i], self.z[i + half] - self.z[i]);
            let (mut mx, mut zx) = (m0, z0);
            let mut e = [Fp::zero(); 3];
            for slot in e.iter_mut() {
                *slot = mx * zx;
                mx += dm;
                zx += dz;
            }
            e
        })
        .to_vec()
    }

    fn bind(&mut self, r: Fp) {
        fold(&mut self.m, r);
        fold(&mut self.z, r);
    }
}

// M_{r_x}(y) for all y, length 2*half
fn m_rx(shape: &R1cs, layout: &Layout, eq_rx: &[Fp], ra: Fp, rb: Fp, rc: Fp) -> Vec<Fp> {
    // gathered over the cached transposes
    let [ta, tb, tc] = shape.transposes();
    let w = [ra, rb, rc];
    let at = |k: usize| -> Fp {
        let mut acc = Fp::zero();
        for (t, wm) in [ta, tb, tc].into_iter().zip(w) {
            if !t.row_raw(k).0.is_empty() {
                acc += wm * t.dot_row(k, |i| eq_rx[i]);
            }
        }
        acc
    };
    // z = (w, 0.., 1, io, 0..): witness k -> k - num_inst, instance k -> half + k
    let half = layout.half();
    let mut out = crate::par::map_range(shape.num_wit, |w| at(shape.num_inst + w));
    out.resize(half, Fp::zero());
    out.extend(crate::par::map_range(shape.num_inst, at));
    out.resize(2 * half, Fp::zero());
    debug_assert_eq!(col(layout, shape.num_inst, 0), half);
    out
}

fn absorb_mode(t: &mut Transcript, spark: Option<&SparkKey>) {
    t.append_u64(b"mode/spark", spark.is_some() as u64);
    if let Some(k) = spark {
        k.absorb(t);
    }
}

// M(r_x, r_y) from the sparse matrices, nizk mode
pub fn direct_m_eval(shape: &R1cs, layout: &Layout, rx: &[Fp], ry: &[Fp], w: [Fp; 3]) -> Fp {
    let eq_rx_t = eq_table(rx);
    let eq_ry_t = eq_table(ry);
    let [m] = sum_arrays::<1>(shape.num_cons, |i| {
        let mut acc = Fp::zero();
        for (mat, wm) in [(&shape.a, w[0]), (&shape.b, w[1]), (&shape.c, w[2])] {
            let s: Fp = mat.dot_row(i, |k| eq_ry_t[col(layout, shape.num_inst, k)]);
            acc += wm * s;
        }
        [eq_rx_t[i] * acc]
    });
    m
}

#[allow(clippy::too_many_arguments)]
pub fn prove_r1cs<R: RngCore>(
    domain: &[u8],
    shape: &R1cs,
    layout: &Layout,
    instance: &[Fp],
    witness: &[Fp],
    ext_rows: &[GcycAffine],
    ext_open: &[(Vec<Fp>, Fp)],
    spark: Option<&SparkKey>,
    rng: &mut R,
) -> SResult<SpartanProof> {
    let n = layout.half();
    let width = layout.width;
    let gens = Gens::cached(width.max(4));
    let mut w = witness.to_vec();
    w.resize(n, Fp::zero());

    // row blinds: given for pre-committed rows, fresh otherwise
    let mut blinds = Vec::with_capacity(layout.rows);
    // pre-committed rows are not checked against their commitments
    blinds.extend(ext_open.iter().map(|(_, blind)| *blind));
    while blinds.len() < layout.rows {
        blinds.push(Fp::rand(rng));
    }
    let _stage0 = tracing::info_span!("commit_witness_rows").entered();
    let fresh: Vec<GcycProjective> = ark_std::cfg_into_iter!(layout.ext_rows..layout.rows)
        .map(|r| gens.commit_vec(&w[r * width..(r + 1) * width], blinds[r]))
        .collect();
    let fresh_rows = GcycProjective::normalize_batch(&fresh);
    let mut rows = ext_rows.to_vec();
    rows.extend_from_slice(&fresh_rows);

    let mut t = Transcript::new(domain);
    absorb_instance(&mut t, shape, layout, &instance[1..], &rows);
    absorb_mode(&mut t, spark);

    drop(_stage0);
    let _stage1 = tracing::info_span!("az_bz_cz").entered();
    let mut z = w.clone();
    z.extend_from_slice(instance);
    z.resize(2 * n, Fp::zero());

    let m_cons = shape.num_cons.max(2).next_power_of_two();
    let mv = |mat: &r1cs::Matrix| {
        let mut out = crate::par::map_range(mat.num_rows(), |i| mat.dot_row(i, |k| z[col(layout, shape.num_inst, k)]));
        out.resize(m_cons, Fp::zero());
        out
    };
    let (az, bz, cz) = (mv(&shape.a), mv(&shape.b), mv(&shape.c));
    let tau: Vec<Fp> = t.challenge_scalars(b"tau", log2(m_cons));

    drop(_stage1);
    let _stage2 = tracing::info_span!("sumcheck_phase1").entered();
    // phase 1
    let mut p1 = Phase1::new(tau.clone(), az, bz, cz);
    let zero_claim = Claim { value: Fp::zero(), blind: Fp::zero(), comm: GcycAffine::zero() };
    let (sc1, rx, c1) = sumcheck::prove(&mut t, &gens, log2(m_cons), 3, zero_claim, &mut p1, rng);
    let (va, vb, vc) = (p1.a[0], p1.b[0], p1.c[0]);
    let (ra_, rb_, rc_, rab_) = (Fp::rand(rng), Fp::rand(rng), Fp::rand(rng), Fp::rand(rng));
    let c_va = gens.commit_scalar(va, ra_).into_affine();
    let c_vb = gens.commit_scalar(vb, rb_).into_affine();
    let c_vc = gens.commit_scalar(vc, rc_).into_affine();
    let c_vab = gens.commit_scalar(va * vb, rab_).into_affine();
    for c in [&c_va, &c_vb, &c_vc, &c_vab] {
        t.append(b"v", c);
    }
    let prod = ProductProof::prove(&mut t, &gens, (va, ra_, &c_va), (vb, rb_, &c_vb), (rab_, &c_vab), rng);
    let eq_rx = eq_eval(&tau, &rx);
    let target1 = ((GcycProjective::from(c_vab) - c_vc) * eq_rx).into_affine();
    let eq1 = EqualityProof::prove(&mut t, &gens, &c1.comm, c1.blind, &target1, eq_rx * (rab_ - rc_), rng);

    drop(_stage2);
    let _stage3 = tracing::info_span!("sumcheck_phase2").entered();
    // phase 2
    let ra: Fp = t.challenge_scalar(b"rA");
    let rb: Fp = t.challenge_scalar(b"rB");
    let rc: Fp = t.challenge_scalar(b"rC");
    let claim2 = Claim {
        value: ra * va + rb * vb + rc * vc,
        blind: ra * ra_ + rb * rb_ + rc * rc_,
        comm: (c_va * ra + c_vb * rb + c_vc * rc).into_affine(),
    };
    let m = {
        let _s = tracing::info_span!("m_rx").entered();
        m_rx(shape, layout, &eq_table(&rx), ra, rb, rc)
    };
    let mut p2 = Phase2 { m, z };
    let (sc2, ry, c2) = sumcheck::prove(&mut t, &gens, log2(2 * n), 2, claim2, &mut p2, rng);
    let m_eval = p2.m[0];
    let spark_proof = spark.map(|key| {
        let _span = tracing::info_span!("spark_prove").entered();
        t.append(b"m_eval", &m_eval);
        spark::prove(&mut t, key, &rx, &ry, [ra, rb, rc], rng)
    });

    drop(_stage3);
    let _stage4 = tracing::info_span!("hyrax_open").entered();
    // hyrax opening of w~ at r_y[1..]
    let (ry0, rest) = (ry[0], &ry[1..]);
    let log_r = log2(layout.rows);
    let l = eq_table(&rest[..log_r]);
    let rv = eq_table(&rest[log_r..]);
    // rows combined with weights l, in parallel over blocks of 64 columns
    const BLK: usize = 64;
    let mut tvec: Vec<Fp> = crate::par::map_range(width.div_ceil(BLK), |b| {
        let (c0, c1) = (b * BLK, ((b + 1) * BLK).min(width));
        let mut acc = vec![Fp::zero(); c1 - c0];
        for r in 0..layout.rows {
            if l[r].is_zero() {
                continue;
            }
            for (a, x) in acc.iter_mut().zip(&w[r * width + c0..r * width + c1]) {
                if !x.is_zero() {
                    *a += l[r] * x;
                }
            }
        }
        acc
    })
    .concat();
    let tblind: Fp = (0..layout.rows).map(|r| l[r] * blinds[r]).sum();
    let vw = inner(&tvec, &rv);
    let r_vw = Fp::rand(rng);
    let c_vw = gens.commit_scalar(vw, r_vw).into_affine();
    t.append(b"vw", &c_vw);
    let c_l = GcycProjective::msm_unchecked(&rows, &l).into_affine();
    let hyrax = DotProductProofLog::prove(&mut t, &gens, &tvec, tblind, &rv, r_vw, &c_l, &c_vw, rng);

    let io_eval = mle_eval(instance, rest);
    debug_assert_eq!(p2.z[0], (Fp::one() - ry0) * vw + ry0 * io_eval);
    let c_z = GcycProjective::from(c_vw) * (Fp::one() - ry0) + gens.gs * (ry0 * io_eval);
    let target2 = (c_z * m_eval).into_affine();
    let eq2 = EqualityProof::prove(&mut t, &gens, &c2.comm, c2.blind, &target2, m_eval * (Fp::one() - ry0) * r_vw, rng);

    drop(_stage4);
    // wipe the prover's copies of the witness and row blinds
    w.zeroize();
    blinds.zeroize();
    tvec.zeroize();
    p2.z.zeroize();

    Ok(SpartanProof {
        fresh_rows,
        sc1,
        c_va,
        c_vb,
        c_vc,
        c_vab,
        prod,
        eq1,
        sc2,
        c_vw,
        hyrax,
        eq2,
        m_eval: spark.map(|_| m_eval),
        spark: spark_proof,
    })
}

pub fn verify_r1cs(
    domain: &[u8],
    shape: &R1cs,
    layout: &Layout,
    instance: &[Fp],
    ext_rows: &[GcycAffine],
    proof: &SpartanProof,
    spark: Option<&SparkKey>,
) -> bool {
    let n = layout.half();
    let width = layout.width;
    if instance.len() != shape.num_inst
        || instance[0] != Fp::one()
        || ext_rows.len() != layout.ext_rows
        || proof.fresh_rows.len() != layout.rows - layout.ext_rows
        || instance.len() > n
    {
        return false;
    }
    let gens = Gens::cached(width.max(4));
    let mut rows = ext_rows.to_vec();
    rows.extend_from_slice(&proof.fresh_rows);

    let mut t = Transcript::new(domain);
    absorb_instance(&mut t, shape, layout, &instance[1..], &rows);
    absorb_mode(&mut t, spark);
    let m_cons = shape.num_cons.max(2).next_power_of_two();
    let tau: Vec<Fp> = t.challenge_scalars(b"tau", log2(m_cons));

    let Some((rx, c1)) = sumcheck::verify(&mut t, &gens, &proof.sc1, log2(m_cons), 3, GcycAffine::zero()) else {
        return false;
    };
    for c in [&proof.c_va, &proof.c_vb, &proof.c_vc, &proof.c_vab] {
        t.append(b"v", c);
    }
    if !proof.prod.verify(&mut t, &gens, &proof.c_va, &proof.c_vb, &proof.c_vab) {
        return false;
    }
    let eq_rx = eq_eval(&tau, &rx);
    let target1 = ((GcycProjective::from(proof.c_vab) - proof.c_vc) * eq_rx).into_affine();
    if !proof.eq1.verify(&mut t, &gens, &c1, &target1) {
        return false;
    }

    let ra: Fp = t.challenge_scalar(b"rA");
    let rb: Fp = t.challenge_scalar(b"rB");
    let rc: Fp = t.challenge_scalar(b"rC");
    let comm2 = (proof.c_va * ra + proof.c_vb * rb + proof.c_vc * rc).into_affine();
    let Some((ry, c2)) = sumcheck::verify(&mut t, &gens, &proof.sc2, log2(2 * n), 2, comm2) else {
        return false;
    };

    // M(r_x, r_y): spark proof (snark mode) or direct evaluation (nizk mode)
    let m_eval = match (spark, &proof.spark, proof.m_eval) {
        (Some(key), Some(sp), Some(me)) => {
            t.append(b"m_eval", &me);
            if !spark::verify(&mut t, key, &rx, &ry, [ra, rb, rc], me, sp) {
                return false;
            }
            me
        }
        (None, None, None) => direct_m_eval(shape, layout, &rx, &ry, [ra, rb, rc]),
        _ => return false,
    };

    let (ry0, rest) = (ry[0], &ry[1..]);
    let log_r = log2(layout.rows);
    let l = eq_table(&rest[..log_r]);
    let rv = eq_table(&rest[log_r..]);
    t.append(b"vw", &proof.c_vw);
    let c_l = GcycProjective::msm_unchecked(&rows, &l).into_affine();
    if !proof.hyrax.verify(&mut t, &gens, &rv, &c_l, &proof.c_vw) {
        return false;
    }

    let io_eval = mle_eval(instance, rest);
    let c_z = GcycProjective::from(proof.c_vw) * (Fp::one() - ry0) + gens.gs * (ry0 * io_eval);
    let target2 = (c_z * m_eval).into_affine();
    proof.eq2.verify(&mut t, &gens, &c2, &target2)
}

// spartan + hyrax: SPARK = false is the nizk (verifier evaluates the matrices itself), SPARK = true the snark with computation commitment
pub struct SpartanBackend<const SPARK: bool>;

// default backend
pub type SpartanNizk = SpartanBackend<false>;
// snark with spark, for very large sender sets
pub type SpartanSnark = SpartanBackend<true>;
pub type Spartan = SpartanNizk;

impl<const SPARK: bool> ProofSystem for SpartanBackend<SPARK> {
    type Proof = SpartanProof;
    const NAME: &'static str =
        if SPARK { "Spartan SNARK (SPARK) + Hyrax over Vesta" } else { "Spartan NIZK + Hyrax over Vesta" };
    const ZERO_KNOWLEDGE: bool = true;

    fn prove<Rel: CommittedRelation, R: RngCore>(
        ctx: &[u8],
        stmt: &Rel::Statement,
        wit: &Rel::Witness,
        rng: &mut R,
    ) -> SResult<SpartanProof> {
        let _span = tracing::info_span!("prove", relation = Rel::NAME, backend = Self::NAME).entered();
        let cached = cache::shape::<Rel>(stmt)?;
        let (width, shape) = (cached.width, &*cached.r1cs);
        let key = if SPARK { Some(cache::spark_key::<Rel>(stmt)?) } else { None };
        let a = r1cs::prove_values::<Rel>(stmt, wit, width, shape)?;
        let io = Rel::public_inputs(stmt).ok_or_else(|| SpicyError::Input("malformed statement".into()))?;
        if a.instance[1..] != io[..] {
            return Err(SpicyError::Synthesis("public input order mismatch".into()));
        }
        let ext = Rel::external_rows(stmt);
        let layout = Layout::new(width, shape.num_wit, shape.num_inst, ext.len());
        prove_r1cs(
            &super::domain_with_ctx(Rel::DOMAIN, ctx),
            shape,
            &layout,
            &a.instance,
            &a.witness,
            &ext,
            &Rel::external_openings(wit),
            key.as_deref(),
            rng,
        )
    }

    fn verify<Rel: CommittedRelation>(ctx: &[u8], stmt: &Rel::Statement, proof: &SpartanProof) -> bool {
        let _span = tracing::info_span!("verify", relation = Rel::NAME, backend = Self::NAME).entered();
        let run = || -> Option<bool> {
            let cached = cache::shape::<Rel>(stmt).ok()?;
            let (width, shape) = (cached.width, &*cached.r1cs);
            let key = if SPARK { Some(cache::spark_key::<Rel>(stmt).ok()?) } else { None };
            let mut inst = vec![Fp::one()];
            inst.extend(Rel::public_inputs(stmt)?);
            let ext = Rel::external_rows(stmt);
            if ext.iter().any(|p| !p.is_on_curve()) {
                return Some(false);
            }
            let layout = Layout::new(width, shape.num_wit, shape.num_inst, ext.len());
            Some(verify_r1cs(&super::domain_with_ctx(Rel::DOMAIN, ctx), shape, &layout, &inst, &ext, proof, key.as_deref()))
        };
        run().unwrap_or(false)
    }
}

