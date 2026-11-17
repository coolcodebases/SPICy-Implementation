// R_pair (pair setup, once per pair): T_j and T'_j from the decoded pairs and the token points
// decoding inputs are not committed rows: the receiver derives the 4B block commitments from the registered rows and its pk_R, and the circuit evaluates them by horner in z_j^S
// witness rows: (d_{c,b}) c-major, z^S, x_V, y_V, x_V', y_V'; public inputs T_j, T'_j

use ark_ec::{AffineRepr, CurveGroup};
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use super::gadgets::{alloc_input_point, alloc_row, complete_add, enforce_proj_equals_affine, horner_gadget, swu_gadget, AffineVar};
use super::r_tok::{col, PointCom};
use super::CommittedRelation;
use crate::curve::coords;
use crate::encoding::elligator_squared::decode_pair;
use crate::pedersen::derived::horner;
use crate::oracle::domain;
use crate::params::CycGens;
use crate::pedersen::verify_opening;
use crate::types::{Fp, G0Affine, GcycAffine};

#[derive(Clone, Debug)]
pub struct PairStatement {
    // block commitments C_{c,b} at c*B + b
    pub blocks: Vec<GcycAffine>,
    // Z_S, commitment to (z_j^S)_j
    pub zs: GcycAffine,
    pub c_v: PointCom,
    pub c_v2: PointCom,
    pub t: Vec<G0Affine>,
    pub t2: Vec<G0Affine>,
}

impl PairStatement {
    // B, blocks per decoding input
    pub fn b(&self) -> usize {
        self.blocks.len() / 4
    }
}

#[derive(Clone, Debug)]
pub struct PairWitness {
    // openings of the blocks, same order
    pub blocks: Vec<Vec<Fp>>,
    pub block_blinds: Vec<Fp>,
    pub zs: Vec<Fp>,
    pub zs_blind: Fp,
    pub v: Vec<(Fp, Fp)>,
    pub v2: Vec<(Fp, Fp)>,
    pub r_v: (Fp, Fp),
    pub r_v2: (Fp, Fp),
}

impl PairWitness {
    // (u_j, v_j, u'_j, v'_j) of slot j, by horner in z_j^S
    pub fn dec(&self, j: usize) -> [Fp; 4] {
        let b = self.blocks.len() / 4;
        [0, 1, 2, 3].map(|c| horner(&(0..b).map(|i| self.blocks[c * b + i][j]).collect::<Vec<_>>(), self.zs[j]))
    }
}

pub struct PairCircuit {
    pub m: usize,
    pub b: usize,
    pub width: usize,
    pub t_coords: Vec<((Fp, Fp), (Fp, Fp))>,
    pub wit: Option<PairWitness>,
}

// rows: 4B blocks, z^S, x_V, y_V, x_V', y_V'
fn row_openings(wit: &PairWitness) -> Vec<(Vec<Fp>, Fp)> {
    let mut out: Vec<(Vec<Fp>, Fp)> = wit.blocks.iter().cloned().zip(wit.block_blinds.iter().copied()).collect();
    out.push((wit.zs.clone(), wit.zs_blind));
    out.extend([
        (col(&wit.v, false), wit.r_v.0),
        (col(&wit.v, true), wit.r_v.1),
        (col(&wit.v2, false), wit.r_v2.0),
        (col(&wit.v2, true), wit.r_v2.1),
    ]);
    out
}

// one slot: its column of every row plus inputs T_j, T'_j
fn slot(cs: ConstraintSystemRef<Fp>, b: usize, e: &[FpVar<Fp>], t_j: &(AffineVar, AffineVar)) -> Result<(), SynthesisError> {
    let zs = &e[4 * b];
    let dec = (0..4).map(|c| horner_gadget(cs.clone(), &e[c * b..(c + 1) * b], zs, None)).collect::<Result<Vec<_>, _>>()?;
    let v_j = AffineVar { x: e[4 * b + 1].clone(), y: e[4 * b + 2].clone() };
    let v2_j = AffineVar { x: e[4 * b + 3].clone(), y: e[4 * b + 4].clone() };
    pair_slot(cs, [&dec[0], &dec[1], &dec[2], &dec[3]], &v_j, &v2_j, t_j)
}

impl ConstraintSynthesizer<Fp> for PairCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fp>) -> Result<(), SynthesisError> {
        let _circuit = super::gadgets::scope!("R_pair");
        let m = self.m;
        let n_rows = 4 * self.b + 5;
        let open = self.wit.as_ref().map(row_openings);
        let mut rows = Vec::with_capacity(n_rows);
        for r in 0..n_rows {
            rows.push(alloc_row(cs.clone(), open.as_ref().map(|o| o[r].0.as_slice()), m, self.width)?);
        }
        let mut t_pub = Vec::with_capacity(m);
        for (t, t2) in &self.t_coords {
            t_pub.push((alloc_input_point(cs.clone(), *t)?, alloc_input_point(cs.clone(), *t2)?));
        }
        for (j, t_j) in t_pub.iter().enumerate() {
            let e: Vec<FpVar<Fp>> = rows.iter().map(|r| r[j].clone()).collect();
            slot(cs.clone(), self.b, &e, t_j)?;
        }
        Ok(())
    }
}

// T_j = phi(u) + phi(v) + V_j and T'_j = phi(u') + phi(v') + V'_j
pub fn pair_slot(
    cs: ConstraintSystemRef<Fp>,
    dec: [&FpVar<Fp>; 4],
    v_j: &AffineVar,
    v2_j: &AffineVar,
    t_j: &(AffineVar, AffineVar),
) -> Result<(), SynthesisError> {
    let _element = super::gadgets::scope!("element");
    let [u, v, u2, v2] = dec;
    let pu = swu_gadget(cs.clone(), u)?.point.to_projective();
    let pv = swu_gadget(cs.clone(), v)?.point.to_projective();
    let t = complete_add(&complete_add(&pu, &pv)?, &v_j.to_projective())?;
    enforce_proj_equals_affine(&t, &t_j.0)?;
    let pu2 = swu_gadget(cs.clone(), u2)?.point.to_projective();
    let pv2 = swu_gadget(cs, v2)?.point.to_projective();
    let t2 = complete_add(&complete_add(&pu2, &pv2)?, &v2_j.to_projective())?;
    enforce_proj_equals_affine(&t2, &t_j.1)
}

// native pair_slot
pub fn pair_slot_native(dec: [Fp; 4], v: (Fp, Fp), v2: (Fp, Fp), t: &G0Affine, t2: &G0Affine) -> bool {
    let [u, vv, u2, vv2] = dec;
    let tt = (decode_pair(u, vv) + crate::curve::from_coords(v)).into_affine();
    let tt2 = (decode_pair(u2, vv2) + crate::curve::from_coords(v2)).into_affine();
    !tt.is_zero() && !tt2.is_zero() && tt == *t && tt2 == *t2
}

pub struct RPair;

impl CommittedRelation for RPair {
    type Statement = PairStatement;
    type Witness = PairWitness;
    type Circuit = PairCircuit;
    const DOMAIN: &'static [u8] = domain::PAIR;
    const NAME: &'static str = "R_pair";

    fn m(stmt: &PairStatement) -> usize {
        stmt.t.len()
    }

    fn shape_key(stmt: &PairStatement) -> Vec<usize> {
        vec![stmt.t.len(), stmt.blocks.len()]
    }

    fn circuit(stmt: &PairStatement, wit: Option<&PairWitness>, width: usize) -> PairCircuit {
        let t_coords = stmt
            .t
            .iter()
            .zip(&stmt.t2)
            .map(|(a, b)| (coords(a).unwrap_or_default(), coords(b).unwrap_or_default()))
            .collect();
        PairCircuit { m: stmt.t.len(), b: stmt.b(), width, t_coords, wit: wit.cloned() }
    }

    fn external_rows(stmt: &PairStatement) -> Vec<GcycAffine> {
        let mut out = stmt.blocks.clone();
        out.push(stmt.zs);
        out.extend([stmt.c_v.0, stmt.c_v.1, stmt.c_v2.0, stmt.c_v2.1]);
        out
    }

    fn external_openings(wit: &PairWitness) -> Vec<(Vec<Fp>, Fp)> {
        row_openings(wit)
    }

    fn public_inputs(stmt: &PairStatement) -> Option<Vec<Fp>> {
        if stmt.t.len() != stmt.t2.len() || stmt.blocks.is_empty() || stmt.blocks.len() % 4 != 0 {
            return None;
        }
        let mut out = Vec::with_capacity(4 * stmt.t.len());
        for (a, b) in stmt.t.iter().zip(&stmt.t2) {
            let (x, y) = coords(a)?;
            let (x2, y2) = coords(b)?;
            out.extend([x, y, x2, y2]);
        }
        Some(out)
    }

    fn slot_layout<'a>(stmt: &'a PairStatement, _wit: Option<&'a PairWitness>, width: usize) -> Option<super::SlotLayout<'a>> {
        let t: Vec<((Fp, Fp), (Fp, Fp))> =
            stmt.t.iter().zip(&stmt.t2).map(|(a, b)| (coords(a).unwrap_or_default(), coords(b).unwrap_or_default())).collect();
        let b = stmt.b();
        let n_rows = 4 * b + 5;
        Some(super::SlotLayout {
            rows: n_rows,
            width,
            slots: t.len(),
            inputs_per_slot: 4,
            entries: Box::new(move |j| (0..n_rows).map(|r| (r, j)).collect()),
            gadget: Box::new(move |cs, j, e| {
                let t_j = (alloc_input_point(cs.clone(), t[j].0)?, alloc_input_point(cs.clone(), t[j].1)?);
                slot(cs, b, e, &t_j)
            }),
        })
    }

    fn check_relation(gens: &CycGens, stmt: &PairStatement, wit: &PairWitness) -> bool {
        let m = stmt.t.len();
        if stmt.t2.len() != m || wit.v.len() != m || wit.v2.len() != m || wit.zs.len() != m {
            return false;
        }
        if stmt.blocks.is_empty() || stmt.blocks.len() % 4 != 0 || wit.blocks.len() != stmt.blocks.len() || wit.block_blinds.len() != stmt.blocks.len() {
            return false;
        }
        if wit.blocks.iter().any(|r| r.len() != m) {
            return false;
        }
        let rows = Self::external_rows(stmt);
        let openings = rows.iter().zip(row_openings(wit)).all(|(c, (v, r))| verify_opening(gens, c, &v, r));
        openings && (0..m).all(|j| pair_slot_native(wit.dec(j), wit.v[j], wit.v2[j], &stmt.t[j], &stmt.t2[j]))
    }
}
