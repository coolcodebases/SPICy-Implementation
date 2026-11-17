// spark: computation commitment to the matrices and an argument for M(r_x, r_y)
// degree-3 sum-check plus offline memory checking with grand products
// not zk

use ark_ff::{Field, One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;

use super::ipa::DotProductProofLog;
use super::mle::{eq_eval, eq_table, fold, log2, mle_eval};
use super::pcs::{self, DenseComm};
use super::product::{self, eval_cubic, BatchedProductProof};
use super::sigma::Gens;
use crate::snark::r1cs::R1cs;
use crate::snark::Layout;
use crate::transcript::Transcript;
use crate::types::Fp;

// prover-side dense form of the matrices
#[derive(Clone, Debug)]
pub struct SparkDense {
    pub row_idx: Vec<usize>,
    pub col_idx: Vec<usize>,
    // the nine committed polys: row, col, valA, valB, valC, read_row, audit_row, read_col, audit_col
    pub polys: Vec<Vec<Fp>>,
}

const ROW: usize = 0;
const COL: usize = 1;
const VAL: usize = 2;
const READ_ROW: usize = 5;
const AUDIT_ROW: usize = 6;
const READ_COL: usize = 7;
const AUDIT_COL: usize = 8;

// public computation commitment plus the prover's dense data
#[derive(Clone, Debug)]
pub struct SparkKey {
    pub log_nnz: usize,
    pub log_rows: usize,
    pub log_cols: usize,
    pub comms: Vec<DenseComm>,
    pub dense: SparkDense,
    pub gens: std::sync::Arc<Gens>,
}

impl SparkKey {
    // digest for fiat-shamir
    pub fn absorb(&self, t: &mut Transcript) {
        t.append_u64(b"spark/log_nnz", self.log_nnz as u64);
        t.append_u64(b"spark/log_rows", self.log_rows as u64);
        t.append_u64(b"spark/log_cols", self.log_cols as u64);
        t.append(b"spark/comms", &self.comms);
    }
}

fn to_fp(x: usize) -> Fp {
    Fp::from(x as u64)
}

// encoder: build and commit the sparse form of (A, B, C)
pub fn preprocess(shape: &R1cs, layout: &Layout) -> SparkKey {
    let m_rows = shape.num_cons.max(2).next_power_of_two();
    let m_cols = 2 * layout.half();
    let mut entries: Vec<(usize, usize, usize, Fp)> = vec![];
    for (mi, mat) in [&shape.a, &shape.b, &shape.c].into_iter().enumerate() {
        for i in 0..mat.num_rows() {
            for (v, k) in mat.row(i) {
                entries.push((i, super::col(layout, shape.num_inst, k), mi, v));
            }
        }
    }
    let nnz = entries.len().max(2).next_power_of_two();
    entries.resize(nnz, (0, 0, 0, Fp::zero()));
    let mut polys = vec![vec![Fp::zero(); nnz]; 9];
    let mut audit_row = vec![0u64; m_rows];
    let mut audit_col = vec![0u64; m_cols];
    let (mut row_idx, mut col_idx) = (vec![0; nnz], vec![0; nnz]);
    for (k, (r, c, mi, v)) in entries.into_iter().enumerate() {
        row_idx[k] = r;
        col_idx[k] = c;
        polys[ROW][k] = to_fp(r);
        polys[COL][k] = to_fp(c);
        polys[VAL + mi][k] = v;
        polys[READ_ROW][k] = Fp::from(audit_row[r]);
        polys[READ_COL][k] = Fp::from(audit_col[c]);
        audit_row[r] += 1;
        audit_col[c] += 1;
    }
    polys[AUDIT_ROW] = audit_row.into_iter().map(Fp::from).collect();
    polys[AUDIT_COL] = audit_col.into_iter().map(Fp::from).collect();
    let (log_nnz, log_rows, log_cols) = (log2(nnz), log2(m_rows), log2(m_cols));
    let max_nv = log_nnz.max(log_rows).max(log_cols);
    let gens = Gens::cached(pcs::width_for(max_nv).max(4));
    let comms = polys.iter().map(|p| pcs::commit(&gens, p)).collect();
    SparkKey { log_nnz, log_rows, log_cols, comms, dense: SparkDense { row_idx, col_idx, polys }, gens }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SparkProof {
    pub comm_erx: DenseComm,
    pub comm_ery: DenseComm,
    pub sumcheck: Vec<[Fp; 4]>,
    // valA, valB, valC, E_rx, E_ry at r_k
    pub evals_k: Vec<Fp>,
    pub open_k: Vec<DotProductProofLog>,
    // circuits [RS_row, WS_row, RS_col, WS_col], length N
    pub gp_nnz: BatchedProductProof,
    // circuits [Init_row, Audit_row]
    pub gp_rows: BatchedProductProof,
    // circuits [Init_col, Audit_col]
    pub gp_cols: BatchedProductProof,
    // row, col, E_rx, E_ry, read_row, read_col at the nnz leaf point
    pub evals_nnz: Vec<Fp>,
    pub open_nnz: Vec<DotProductProofLog>,
    pub eval_audit_row: Fp,
    pub open_audit_row: DotProductProofLog,
    pub eval_audit_col: Fp,
    pub open_audit_col: DotProductProofLog,
}

// mle of the identity at p
fn id_eval(p: &[Fp]) -> Fp {
    let mut acc = Fp::zero();
    for pj in p {
        acc = acc.double() + pj;
    }
    acc
}

fn hash(gamma: Fp, tau: Fp, a: Fp, v: Fp, ts: Fp) -> Fp {
    a * gamma * gamma + v * gamma + ts - tau
}

pub fn prove<R: RngCore>(
    t: &mut Transcript,
    key: &SparkKey,
    rx: &[Fp],
    ry: &[Fp],
    w: [Fp; 3],
    rng: &mut R,
) -> SparkProof {
    let gens = &key.gens;
    let d = &key.dense;
    let eq_rx = eq_table(rx);
    let eq_ry = eq_table(ry);
    let erx: Vec<Fp> = d.row_idx.iter().map(|i| eq_rx[*i]).collect();
    let ery: Vec<Fp> = d.col_idx.iter().map(|i| eq_ry[*i]).collect();
    let sp = tracing::info_span!("spark/commit_e").entered();
    let comm_erx = pcs::commit(gens, &erx);
    let comm_ery = pcs::commit(gens, &ery);
    t.append(b"spark/erx", &comm_erx);
    t.append(b"spark/ery", &comm_ery);

    drop(sp);
    // sum-check over val'(k)*E_rx(k)*E_ry(k)
    let sp = tracing::info_span!("spark/sumcheck").entered();
    let mut val: Vec<Fp> =
        (0..erx.len()).map(|k| w[0] * d.polys[VAL][k] + w[1] * d.polys[VAL + 1][k] + w[2] * d.polys[VAL + 2][k]).collect();
    let (mut a, mut b) = (erx.clone(), ery.clone());
    let mut sumcheck = Vec::with_capacity(key.log_nnz);
    let mut rk = Vec::with_capacity(key.log_nnz);
    for _ in 0..key.log_nnz {
        let h = val.len() / 2;
        let mut e = [Fp::zero(); 4];
        for i in 0..h {
            let (mut v0, dv) = (val[i], val[i + h] - val[i]);
            let (mut a0, da) = (a[i], a[i + h] - a[i]);
            let (mut b0, db) = (b[i], b[i + h] - b[i]);
            for slot in e.iter_mut() {
                *slot += v0 * a0 * b0;
                v0 += dv;
                a0 += da;
                b0 += db;
            }
        }
        t.append(b"spark/sc", &e.to_vec());
        let r: Fp = t.challenge_scalar(b"spark/r");
        fold(&mut val, r);
        fold(&mut a, r);
        fold(&mut b, r);
        sumcheck.push(e);
        rk.push(r);
    }
    let polys_k: [(&DenseComm, &Vec<Fp>); 5] = [
        (&key.comms[VAL], &d.polys[VAL]),
        (&key.comms[VAL + 1], &d.polys[VAL + 1]),
        (&key.comms[VAL + 2], &d.polys[VAL + 2]),
        (&comm_erx, &erx),
        (&comm_ery, &ery),
    ];
    drop(sp);
    let sp = tracing::info_span!("spark/open_k").entered();
    let evals_k: Vec<Fp> = polys_k.iter().map(|(_, p)| mle_eval(p, &rk)).collect();
    t.append(b"spark/evals_k", &evals_k);
    let open_k = polys_k.iter().map(|(c, p)| pcs::open(t, gens, c, p, &rk, rng).1).collect();

    drop(sp);
    // memory checking
    let sp = tracing::info_span!("spark/grand_products").entered();
    let gamma: Fp = t.challenge_scalar(b"spark/gamma");
    let tau: Fp = t.challenge_scalar(b"spark/tau");
    let h = |a: Fp, v: Fp, ts: Fp| hash(gamma, tau, a, v, ts);
    let p = &d.polys;
    let nnz = erx.len();
    let rs_row: Vec<Fp> = (0..nnz).map(|k| h(p[ROW][k], erx[k], p[READ_ROW][k])).collect();
    let ws_row: Vec<Fp> = (0..nnz).map(|k| h(p[ROW][k], erx[k], p[READ_ROW][k] + Fp::one())).collect();
    let rs_col: Vec<Fp> = (0..nnz).map(|k| h(p[COL][k], ery[k], p[READ_COL][k])).collect();
    let ws_col: Vec<Fp> = (0..nnz).map(|k| h(p[COL][k], ery[k], p[READ_COL][k] + Fp::one())).collect();
    let (gp_nnz, pt_nnz, _) = product::prove(t, &[rs_row, ws_row, rs_col, ws_col]);
    let init_row: Vec<Fp> = (0..eq_rx.len()).map(|i| h(to_fp(i), eq_rx[i], Fp::zero())).collect();
    let aud_row: Vec<Fp> = (0..eq_rx.len()).map(|i| h(to_fp(i), eq_rx[i], p[AUDIT_ROW][i])).collect();
    let (gp_rows, pt_rows, _) = product::prove(t, &[init_row, aud_row]);
    let init_col: Vec<Fp> = (0..eq_ry.len()).map(|i| h(to_fp(i), eq_ry[i], Fp::zero())).collect();
    let aud_col: Vec<Fp> = (0..eq_ry.len()).map(|i| h(to_fp(i), eq_ry[i], p[AUDIT_COL][i])).collect();
    let (gp_cols, pt_cols, _) = product::prove(t, &[init_col, aud_col]);

    drop(sp);
    let _sp = tracing::info_span!("spark/open_leaves").entered();
    let polys_nnz: [(&DenseComm, &Vec<Fp>); 6] = [
        (&key.comms[ROW], &p[ROW]),
        (&key.comms[COL], &p[COL]),
        (&comm_erx, &erx),
        (&comm_ery, &ery),
        (&key.comms[READ_ROW], &p[READ_ROW]),
        (&key.comms[READ_COL], &p[READ_COL]),
    ];
    let evals_nnz: Vec<Fp> = polys_nnz.iter().map(|(_, q)| mle_eval(q, &pt_nnz)).collect();
    t.append(b"spark/evals_nnz", &evals_nnz);
    let open_nnz = polys_nnz.iter().map(|(c, q)| pcs::open(t, gens, c, q, &pt_nnz, rng).1).collect();
    let eval_audit_row = mle_eval(&p[AUDIT_ROW], &pt_rows);
    t.append(b"spark/audit_row", &eval_audit_row);
    let (_, open_audit_row) = pcs::open(t, gens, &key.comms[AUDIT_ROW], &p[AUDIT_ROW], &pt_rows, rng);
    let eval_audit_col = mle_eval(&p[AUDIT_COL], &pt_cols);
    t.append(b"spark/audit_col", &eval_audit_col);
    let (_, open_audit_col) = pcs::open(t, gens, &key.comms[AUDIT_COL], &p[AUDIT_COL], &pt_cols, rng);

    SparkProof {
        comm_erx,
        comm_ery,
        sumcheck,
        evals_k,
        open_k,
        gp_nnz,
        gp_rows,
        gp_cols,
        evals_nnz,
        open_nnz,
        eval_audit_row,
        open_audit_row,
        eval_audit_col,
        open_audit_col,
    }
}

// check the claimed M(r_x, r_y) against the computation commitment
pub fn verify(t: &mut Transcript, key: &SparkKey, rx: &[Fp], ry: &[Fp], w: [Fp; 3], claimed: Fp, pf: &SparkProof) -> bool {
    let gens = &key.gens;
    if rx.len() != key.log_rows
        || ry.len() != key.log_cols
        || pf.sumcheck.len() != key.log_nnz
        || pf.evals_k.len() != 5
        || pf.open_k.len() != 5
        || pf.evals_nnz.len() != 6
        || pf.open_nnz.len() != 6
        || pf.comm_erx.num_vars as usize != key.log_nnz
        || pf.comm_ery.num_vars as usize != key.log_nnz
    {
        return false;
    }
    t.append(b"spark/erx", &pf.comm_erx);
    t.append(b"spark/ery", &pf.comm_ery);

    // sum-check
    let mut e = claimed;
    let mut rk = Vec::with_capacity(key.log_nnz);
    for g in &pf.sumcheck {
        if g[0] + g[1] != e {
            return false;
        }
        t.append(b"spark/sc", &g.to_vec());
        let r: Fp = t.challenge_scalar(b"spark/r");
        e = eval_cubic(g, r);
        rk.push(r);
    }
    let ek = &pf.evals_k;
    if e != (w[0] * ek[0] + w[1] * ek[1] + w[2] * ek[2]) * ek[3] * ek[4] {
        return false;
    }
    t.append(b"spark/evals_k", ek);
    let comms_k = [&key.comms[VAL], &key.comms[VAL + 1], &key.comms[VAL + 2], &pf.comm_erx, &pf.comm_ery];
    for i in 0..5 {
        if !pcs::verify(t, gens, comms_k[i], &rk, ek[i], &pf.open_k[i]) {
            return false;
        }
    }

    // memory checking
    let gamma: Fp = t.challenge_scalar(b"spark/gamma");
    let tau: Fp = t.challenge_scalar(b"spark/tau");
    let h = |a: Fp, v: Fp, ts: Fp| hash(gamma, tau, a, v, ts);
    let Some((pt_nnz, cl_nnz)) = product::verify(t, &pf.gp_nnz, 4, key.log_nnz) else { return false };
    let Some((pt_rows, cl_rows)) = product::verify(t, &pf.gp_rows, 2, key.log_rows) else { return false };
    let Some((pt_cols, cl_cols)) = product::verify(t, &pf.gp_cols, 2, key.log_cols) else { return false };
    // multiset check for each memory
    let (pn, pr, pc) = (&pf.gp_nnz.products, &pf.gp_rows.products, &pf.gp_cols.products);
    if pr[0] * pn[1] != pn[0] * pr[1] || pc[0] * pn[3] != pn[2] * pc[1] {
        return false;
    }
    // leaf claims of the nnz-sized circuits
    let en = &pf.evals_nnz;
    t.append(b"spark/evals_nnz", en);
    let comms_nnz = [&key.comms[ROW], &key.comms[COL], &pf.comm_erx, &pf.comm_ery, &key.comms[READ_ROW], &key.comms[READ_COL]];
    for i in 0..6 {
        if !pcs::verify(t, gens, comms_nnz[i], &pt_nnz, en[i], &pf.open_nnz[i]) {
            return false;
        }
    }
    let (row, col, erx, ery, rd_row, rd_col) = (en[0], en[1], en[2], en[3], en[4], en[5]);
    if cl_nnz[0] != h(row, erx, rd_row)
        || cl_nnz[1] != h(row, erx, rd_row + Fp::one())
        || cl_nnz[2] != h(col, ery, rd_col)
        || cl_nnz[3] != h(col, ery, rd_col + Fp::one())
    {
        return false;
    }
    // init and audit leaves are evaluated by the verifier
    t.append(b"spark/audit_row", &pf.eval_audit_row);
    if !pcs::verify(t, gens, &key.comms[AUDIT_ROW], &pt_rows, pf.eval_audit_row, &pf.open_audit_row) {
        return false;
    }
    t.append(b"spark/audit_col", &pf.eval_audit_col);
    if !pcs::verify(t, gens, &key.comms[AUDIT_COL], &pt_cols, pf.eval_audit_col, &pf.open_audit_col) {
        return false;
    }
    let (id_r, mem_r) = (id_eval(&pt_rows), eq_eval(rx, &pt_rows));
    let (id_c, mem_c) = (id_eval(&pt_cols), eq_eval(ry, &pt_cols));
    cl_rows[0] == h(id_r, mem_r, Fp::zero())
        && cl_rows[1] == h(id_r, mem_r, pf.eval_audit_row)
        && cl_cols[0] == h(id_c, mem_c, Fp::zero())
        && cl_cols[1] == h(id_c, mem_c, pf.eval_audit_col)
}
