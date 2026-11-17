// R_tok (pair setup, precomputable): the token points U_j, V_j, V'_j from one scalar beta_j
// a point vector is committed as two Coms (x and y coords); beta_j is decomposed once for all three mults
// witness rows: x_V, y_V, x_V', y_V'; public inputs coords(U_j)

use ark_ec::AffineRepr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_ff::{Field as _, Zero as _};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use super::gadgets::{alloc_input_point, alloc_row, enforce_proj_equals_affine, windowed_fixed_base_mul3, AffineVar, WindowTable};
use super::CommittedRelation;
use crate::curve::{coords, scalar_bits_be};
use crate::oracle::domain;
use crate::params::{h0, h0_prime, CycGens};
use crate::pedersen::verify_opening;
use crate::types::{Fp, Fq0, G0Affine, GcycAffine, N0};

// (Com of x coords, Com of y coords)
pub type PointCom = (GcycAffine, GcycAffine);

#[derive(Clone, Debug)]
pub struct TokStatement {
    pub c_v: PointCom,
    pub c_v2: PointCom,
    pub u: Vec<G0Affine>,
}

#[derive(Clone, Debug)]
pub struct TokWitness {
    pub beta: Vec<Fq0>,
    pub v: Vec<(Fp, Fp)>,
    pub v2: Vec<(Fp, Fp)>,
    // blinds of C_V (x, y)
    pub r_v: (Fp, Fp),
    // blinds of C_V' (x, y)
    pub r_v2: (Fp, Fp),
}

pub struct TokCircuit {
    pub m: usize,
    pub width: usize,
    pub u_coords: Vec<(Fp, Fp)>,
    pub wit: Option<TokWitness>,
}

// x coords (y = false) or y coords
pub fn col(v: &[(Fp, Fp)], y: bool) -> Vec<Fp> {
    v.iter().map(|p| if y { p.1 } else { p.0 }).collect()
}

impl ConstraintSynthesizer<Fp> for TokCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fp>) -> Result<(), SynthesisError> {
        let _circuit = super::gadgets::scope!("R_tok");
        let m = self.m;
        let w = self.wit.as_ref();
        let mut rows = Vec::with_capacity(4);
        for (pts, y) in [(0, false), (0, true), (1, false), (1, true)] {
            let vals = w.map(|w| col(if pts == 0 { &w.v } else { &w.v2 }, y));
            rows.push(alloc_row(cs.clone(), vals.as_deref(), m, self.width)?);
        }
        let mut u_pub = Vec::with_capacity(m);
        for p in &self.u_coords {
            u_pub.push(alloc_input_point(cs.clone(), *p)?);
        }
        for (j, u_j) in u_pub.iter().enumerate() {
            let v_j = AffineVar { x: rows[0][j].clone(), y: rows[1][j].clone() };
            let v2_j = AffineVar { x: rows[2][j].clone(), y: rows[3][j].clone() };
            tok_slot(cs.clone(), w.map(|w| &w.beta[j]), u_j, &v_j, &v2_j)?;
        }
        Ok(())
    }
}

// one slot: U_j = beta_j*G0, V_j = beta_j*H0, V'_j = beta_j*H0'
pub fn tok_slot(
    cs: ConstraintSystemRef<Fp>,
    beta: Option<&Fq0>,
    u_j: &AffineVar,
    v_j: &AffineVar,
    v2_j: &AffineVar,
) -> Result<(), SynthesisError> {
    let _element = super::gadgets::scope!("element");
    let bits_native = beta.map(scalar_bits_be);
    // little-endian bits of beta_j
    let bits_le = (0..N0)
        .map(|i| {
            Boolean::new_witness(cs.clone(), || {
                bits_native.as_ref().map(|b| b[N0 - 1 - i]).ok_or(SynthesisError::AssignmentMissing)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let t = token_tables();
    let [u, v, v2] = windowed_fixed_base_mul3(cs, &bits_le, [&t[0], &t[1], &t[2]])?;
    enforce_proj_equals_affine(&u, u_j)?;
    enforce_proj_equals_affine(&v, v_j)?;
    enforce_proj_equals_affine(&v2, v2_j)
}

// window tables of G0, H0, H0', built once
pub fn token_tables() -> &'static [WindowTable; 3] {
    static T: std::sync::OnceLock<[WindowTable; 3]> = std::sync::OnceLock::new();
    T.get_or_init(|| [G0Affine::generator(), h0(), h0_prime()].map(|b| WindowTable::new(&b)))
}

// native tok_slot
pub fn tok_slot_native(beta: &Fq0, u: &G0Affine, v: (Fp, Fp), v2: (Fp, Fp)) -> bool {
    use ark_ec::CurveGroup;
    let m = |b: G0Affine| coords(&(b * beta).into_affine());
    m(G0Affine::generator()) == coords(u) && coords(u).is_some() && m(h0()) == Some(v) && m(h0_prime()) == Some(v2)
}

pub struct RTok;

impl CommittedRelation for RTok {
    type Statement = TokStatement;
    type Witness = TokWitness;
    type Circuit = TokCircuit;
    const DOMAIN: &'static [u8] = domain::TOK;
    const NAME: &'static str = "R_tok";

    fn m(stmt: &TokStatement) -> usize {
        stmt.u.len()
    }

    fn shape_key(stmt: &TokStatement) -> Vec<usize> {
        vec![stmt.u.len()]
    }

    fn circuit(stmt: &TokStatement, wit: Option<&TokWitness>, width: usize) -> TokCircuit {
        let u_coords = stmt.u.iter().map(|p| coords(p).unwrap_or_default()).collect();
        TokCircuit { m: stmt.u.len(), width, u_coords, wit: wit.cloned() }
    }

    fn external_rows(stmt: &TokStatement) -> Vec<GcycAffine> {
        vec![stmt.c_v.0, stmt.c_v.1, stmt.c_v2.0, stmt.c_v2.1]
    }

    fn external_openings(wit: &TokWitness) -> Vec<(Vec<Fp>, Fp)> {
        vec![
            (col(&wit.v, false), wit.r_v.0),
            (col(&wit.v, true), wit.r_v.1),
            (col(&wit.v2, false), wit.r_v2.0),
            (col(&wit.v2, true), wit.r_v2.1),
        ]
    }

    fn public_inputs(stmt: &TokStatement) -> Option<Vec<Fp>> {
        let mut out = Vec::with_capacity(2 * stmt.u.len());
        for p in &stmt.u {
            let (x, y) = coords(p)?;
            out.push(x);
            out.push(y);
        }
        Some(out)
    }

    // slot j reads column j of rows 0-3 and has U_j as input
    fn slot_layout<'a>(stmt: &'a TokStatement, wit: Option<&'a TokWitness>, width: usize) -> Option<super::SlotLayout<'a>> {
        let u: Vec<(Fp, Fp)> = stmt.u.iter().map(|p| coords(p).unwrap_or_default()).collect();
        Some(super::SlotLayout {
            rows: 4,
            width,
            slots: u.len(),
            inputs_per_slot: 2,
            entries: Box::new(|j| (0..4).map(|r| (r, j)).collect()),
            gadget: Box::new(move |cs, j, e| {
                let v_j = AffineVar { x: e[0].clone(), y: e[1].clone() };
                let v2_j = AffineVar { x: e[2].clone(), y: e[3].clone() };
                let u_j = alloc_input_point(cs.clone(), u[j])?;
                let beta = match wit {
                    Some(w) => Some(w.beta.get(j).ok_or(SynthesisError::AssignmentMissing)?),
                    None => None,
                };
                tok_slot(cs, beta, &u_j, &v_j, &v2_j)
            }),
        })
    }

    // native values, same as the synthesis
    fn values(stmt: &TokStatement, wit: &TokWitness, width: usize) -> Result<super::Values, SynthesisError> {
        tok_values_native(stmt, wit, width)
    }

    fn check_relation(gens: &CycGens, stmt: &TokStatement, wit: &TokWitness) -> bool {
        let m = stmt.u.len();
        if wit.beta.len() != m || wit.v.len() != m || wit.v2.len() != m {
            return false;
        }
        let openings = verify_opening(gens, &stmt.c_v.0, &col(&wit.v, false), wit.r_v.0)
            && verify_opening(gens, &stmt.c_v.1, &col(&wit.v, true), wit.r_v.1)
            && verify_opening(gens, &stmt.c_v2.0, &col(&wit.v2, false), wit.r_v2.0)
            && verify_opening(gens, &stmt.c_v2.1, &col(&wit.v2, true), wit.r_v2.1);
        openings && (0..m).all(|j| tok_slot_native(&wit.beta[j], &stmt.u[j], wit.v[j], wit.v2[j]))
    }
}

// native witness generation

// witnesses of the two complete adds per base in window 84, replayed through arkworks in circuit order
fn tok_tail(acc: &[(Fp, Fp); 3], t84: &[(Fp, Fp); 3]) -> Result<Vec<Fp>, SynthesisError> {
    use super::gadgets::complete_add;
    let cs = super::prove_cs();
    let mut seeds = Vec::with_capacity(3);
    for c in 0..3 {
        let a = AffineVar { x: FpVar::new_witness(cs.clone(), || Ok(acc[c].0))?, y: FpVar::new_witness(cs.clone(), || Ok(acc[c].1))? };
        let t = AffineVar { x: FpVar::new_witness(cs.clone(), || Ok(t84[c].0))?, y: FpVar::new_witness(cs.clone(), || Ok(t84[c].1))? };
        seeds.push((a, t));
    }
    let tables = token_tables();
    for (c, (a, t)) in seeds.iter().enumerate() {
        let sum = complete_add(&a.to_projective(), &t.to_projective())?;
        let off = AffineVar::constant(tables[c].neg_offset).to_projective();
        let _ = complete_add(&sum, &off)?;
    }
    Ok(super::take_values(&cs)?.witness[12..].to_vec())
}

// witness count of tok_tail
fn tok_tail_len() -> usize {
    static L: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *L.get_or_init(|| tok_tail(&[(Fp::from(1u64), Fp::from(2u64)); 3], &[(Fp::from(3u64), Fp::from(5u64)); 3]).map(|v| v.len()).expect("tail synthesis"))
}

// table lookup value, computed like the circuit's lc
#[inline]
fn lookup(coeff: &[Fp; 8], mons: &[Fp; 8]) -> Fp {
    let mut v = coeff[0];
    for k in 1..8 {
        if !mons[k].is_zero() && !coeff[k].is_zero() {
            v += coeff[k] * mons[k];
        }
    }
    v
}

// native R_tok values in the slot layout: the four rows, then per slot the bits, window monomials, incomplete adds of windows 1..=83 and the window 84 tail
// chunked with one batch inversion per window
pub fn tok_values_native(stmt: &TokStatement, wit: &TokWitness, width: usize) -> Result<super::Values, SynthesisError> {
    use super::gadgets::{LAST_INCOMPLETE, WINDOWS};
    use ark_ff::Zero;
    let m = stmt.u.len();
    if wit.beta.len() != m || wit.v.len() != m || wit.v2.len() != m || m > width {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut witness = Vec::new();
    for (vals, _) in RTok::external_openings(wit) {
        witness.extend_from_slice(&vals);
        witness.resize(witness.len() + width - vals.len(), Fp::zero());
    }
    let tables = token_tables();
    let tail_len = tok_tail_len();
    let per = N0 + 4 * WINDOWS + 9 * LAST_INCOMPLETE + tail_len;
    const CHUNK: usize = 32;
    let chunks = crate::par::map_range(m.div_ceil(CHUNK), |k| -> Result<Vec<Fp>, SynthesisError> {
        let js: Vec<usize> = (k * CHUNK..((k + 1) * CHUNK).min(m)).collect();
        let n = js.len();
        let mut out = vec![Fp::zero(); n * per];
        let bits: Vec<Vec<bool>> = js.iter().map(|&j| { let mut b = scalar_bits_be(&wit.beta[j]); b.reverse(); b }).collect();
        for (q, b) in bits.iter().enumerate() {
            for (i, bi) in b.iter().enumerate() {
                out[q * per + i] = Fp::from(*bi as u64);
            }
        }
        let mut acc = vec![[(Fp::zero(), Fp::zero()); 3]; n];
        let mut t84 = vec![[(Fp::zero(), Fp::zero()); 3]; n];
        let mut den = vec![Fp::zero(); 3 * n];
        let mut pts = vec![[(Fp::zero(), Fp::zero()); 3]; n];
        let mut pos = N0;
        for w in 0..WINDOWS {
            for (q, b) in bits.iter().enumerate() {
                let (b0, b1, b2) = (Fp::from(b[3 * w] as u64), Fp::from(b[3 * w + 1] as u64), Fp::from(b[3 * w + 2] as u64));
                let (b01, b02, b12) = (b0 * b1, b0 * b2, b1 * b2);
                let b012 = b01 * b2;
                let o = q * per + pos;
                out[o] = b01;
                out[o + 1] = b02;
                out[o + 2] = b12;
                out[o + 3] = b012;
                let mons = [Fp::from(1u64), b0, b1, b01, b2, b02, b12, b012];
                for (pt, tab) in pts[q].iter_mut().zip(tables.iter()) {
                    *pt = (lookup(&tab.coeff[w][0], &mons), lookup(&tab.coeff[w][1], &mons));
                }
            }
            pos += 4;
            if w == 0 {
                acc.copy_from_slice(&pts);
            } else if w <= LAST_INCOMPLETE {
                for q in 0..n {
                    for c in 0..3 {
                        den[3 * q + c] = pts[q][c].0 - acc[q][c].0;
                    }
                }
                // zero denominator gives slope 0, as in incomplete_add_alloc
                crate::batch_affine::batch_invert_serial(&mut den);
                for q in 0..n {
                    for c in 0..3 {
                        let ((x1, y1), (x2, y2)) = (acc[q][c], pts[q][c]);
                        let s = (y2 - y1) * den[3 * q + c];
                        let x3 = s.square() - x1 - x2;
                        let y3 = s * (x1 - x3) - y1;
                        let o = q * per + pos + 3 * c;
                        out[o] = s;
                        out[o + 1] = x3;
                        out[o + 2] = y3;
                        acc[q][c] = (x3, y3);
                    }
                }
                pos += 9;
            } else {
                t84.copy_from_slice(&pts);
            }
        }
        debug_assert_eq!(pos + tail_len, per);
        for q in 0..n {
            let tail = tok_tail(&acc[q], &t84[q])?;
            out[q * per + pos..(q + 1) * per].copy_from_slice(&tail);
        }
        Ok(out)
    });
    for c in chunks {
        let mut c = c?;
        witness.extend_from_slice(&c);
        zeroize::Zeroize::zeroize(&mut c);
    }
    let mut instance = vec![Fp::from(1u64)];
    instance.extend(RTok::public_inputs(stmt).ok_or(SynthesisError::AssignmentMissing)?);
    Ok(super::Values { instance, witness })
}

