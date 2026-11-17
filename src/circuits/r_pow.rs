// R_pow (registration) in paterson-stockmeyer form
// powers z_j^k for k up to S, and g(z_j) by horner in z_j^S over blocks of S coeffs
// no public inputs

use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use super::gadgets::{alloc_row, horner_gadget, linear};
use super::CommittedRelation;
use crate::oracle::domain;
use crate::params::CycGens;
use crate::pedersen::verify_opening;
use crate::types::{Fp, GcycAffine};

#[derive(Clone, Debug)]
pub struct PowStatement {
    pub m: usize,
    // n_g, length of the public mask g = params::mask(n_g)
    pub n_g: usize,
    // rows[k-1] = Z_k for k <= S, rows[S] = Z_g
    pub rows: Vec<GcycAffine>,
}

impl PowStatement {
    // baby step S (0 if fewer than 3 rows)
    pub fn s(&self) -> usize {
        self.rows.len().saturating_sub(1)
    }
}

#[derive(Clone, Debug)]
pub struct PowWitness {
    // powers[k-1][j] = z_j^k for k <= S, powers[S][j] = g(z_j)
    pub powers: Vec<Vec<Fp>>,
    // blinds[k-1] = r~_k, blinds[S] = r~_g
    pub blinds: Vec<Fp>,
}

pub struct PowCircuit {
    pub m: usize,
    pub n_g: usize,
    pub n_rows: usize,
    pub width: usize,
    pub powers: Option<Vec<Vec<Fp>>>,
}

// one slot over its entries (z^1, ..., z^S, g(z))
fn pow_slot(cs: ConstraintSystemRef<Fp>, mask: &[Fp], e: &[FpVar<Fp>]) -> Result<(), SynthesisError> {
    let s = e.len() - 1;
    if s < 2 {
        return Err(SynthesisError::Unsatisfiable);
    }
    for k in 1..s {
        e[k - 1].mul_equals(&e[0], &e[k])?;
    }
    let blocks = mask.len().div_ceil(s).max(1);
    let gb = (0..blocks)
        .map(|b| {
            let c = |k: usize| mask.get(b * s + k).copied().unwrap_or_default();
            let terms: Vec<(Fp, &FpVar<Fp>)> = (1..s).map(|k| (c(k), &e[k - 1])).collect();
            linear(cs.clone(), c(0), &terms)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let _ = horner_gadget(cs, &gb, &e[s - 1], Some(&e[s]))?;
    Ok(())
}

impl ConstraintSynthesizer<Fp> for PowCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fp>) -> Result<(), SynthesisError> {
        let _circuit = super::gadgets::scope!("R_pow");
        let mut rows = Vec::with_capacity(self.n_rows);
        for k in 0..self.n_rows {
            let vals = self.powers.as_ref().map(|p| p[k].as_slice());
            rows.push(alloc_row(cs.clone(), vals, self.m, self.width)?);
        }
        let mask = crate::params::mask(self.n_g);
        // slot by slot, in the order of RPow::slot_layout
        for j in 0..self.m {
            let e: Vec<FpVar<Fp>> = rows.iter().map(|r| r[j].clone()).collect();
            pow_slot(cs.clone(), &mask, &e)?;
        }
        Ok(())
    }
}

pub struct RPow;

impl CommittedRelation for RPow {
    type Statement = PowStatement;
    type Witness = PowWitness;
    type Circuit = PowCircuit;
    const DOMAIN: &'static [u8] = domain::POW;
    const NAME: &'static str = "R_pow";

    fn m(stmt: &PowStatement) -> usize {
        stmt.m
    }

    fn shape_key(stmt: &PowStatement) -> Vec<usize> {
        vec![stmt.m, stmt.n_g, stmt.rows.len()]
    }

    // rows exactly M wide (rounded to a power of two)
    fn fixed_width(stmt: &PowStatement) -> Option<usize> {
        Some(stmt.m)
    }

    fn circuit(stmt: &PowStatement, wit: Option<&PowWitness>, width: usize) -> PowCircuit {
        PowCircuit { m: stmt.m, n_g: stmt.n_g, n_rows: stmt.rows.len(), width, powers: wit.map(|w| w.powers.clone()) }
    }

    fn external_rows(stmt: &PowStatement) -> Vec<GcycAffine> {
        stmt.rows.clone()
    }

    fn external_openings(wit: &PowWitness) -> Vec<(Vec<Fp>, Fp)> {
        wit.powers.iter().cloned().zip(wit.blinds.iter().copied()).collect()
    }

    fn public_inputs(_stmt: &PowStatement) -> Option<Vec<Fp>> {
        Some(vec![])
    }

    // slot j reads column j of every row, no public inputs
    fn slot_layout<'a>(stmt: &'a PowStatement, _wit: Option<&'a PowWitness>, width: usize) -> Option<super::SlotLayout<'a>> {
        let n_rows = stmt.rows.len();
        let mask = crate::params::mask(stmt.n_g);
        Some(super::SlotLayout {
            rows: n_rows,
            width,
            slots: stmt.m,
            inputs_per_slot: 0,
            entries: Box::new(move |j| (0..n_rows).map(|k| (k, j)).collect()),
            gadget: Box::new(move |cs, _j, e| pow_slot(cs, &mask, e)),
        })
    }

    // native values, same as the synthesis
    fn values(stmt: &PowStatement, wit: &PowWitness, width: usize) -> Result<super::Values, SynthesisError> {
        pow_values_native(stmt, wit, width)
    }

    fn check_relation(gens: &CycGens, stmt: &PowStatement, wit: &PowWitness) -> bool {
        let n = stmt.rows.len();
        if wit.powers.len() != n || wit.blinds.len() != n || n == 0 {
            return false;
        }
        if wit.powers.iter().any(|r| r.len() != stmt.m) {
            return false;
        }
        let openings = (0..n).all(|k| verify_opening(gens, &stmt.rows[k], &wit.powers[k], wit.blinds[k]));
        if n < 3 {
            return false;
        }
        let s = n - 1;
        let mask = crate::params::mask(stmt.n_g);
        let products = (1..s).all(|k| (0..stmt.m).all(|j| wit.powers[k][j] == wit.powers[k - 1][j] * wit.powers[0][j]));
        let masked = (0..stmt.m).all(|j| wit.powers[s][j] == crate::field::poly::eval(&mask, wit.powers[0][j]));
        openings && products && masked
    }
}

// native R_pow values in the slot layout: the rows, then per slot the horner intermediates
pub fn pow_values_native(stmt: &PowStatement, wit: &PowWitness, width: usize) -> Result<super::Values, SynthesisError> {
    use ark_ff::Zero;
    let (m, n_rows) = (stmt.m, stmt.rows.len());
    if n_rows < 3 || wit.powers.len() != n_rows || wit.powers.iter().any(|r| r.len() != m) || m > width {
        return Err(SynthesisError::Unsatisfiable);
    }
    let s = n_rows - 1;
    let mask = crate::params::mask(stmt.n_g);
    let blocks = mask.len().div_ceil(s).max(1);
    let own = blocks.saturating_sub(2);
    let mut witness = Vec::with_capacity(n_rows * width + m * own);
    for row in &wit.powers {
        witness.extend_from_slice(row);
        witness.resize(witness.len() + width - row.len(), Fp::zero());
    }
    let c = |b: usize, k: usize| mask.get(b * s + k).copied().unwrap_or_default();
    let block = |b: usize, j: usize| -> Fp {
        let mut v = c(b, 0);
        for k in 1..s {
            let ck = c(b, k);
            if !ck.is_zero() {
                v += ck * wit.powers[k - 1][j];
            }
        }
        v
    };
    let per_slot = crate::par::map_range(m, |j| {
        let x = wit.powers[s - 1][j];
        let mut out = Vec::with_capacity(own);
        if blocks >= 2 {
            let mut acc = block(blocks - 1, j);
            for b in (1..blocks - 1).rev() {
                acc = acc * x + block(b, j);
                out.push(acc);
            }
        }
        out
    });
    for mut w in per_slot {
        witness.extend_from_slice(&w);
        zeroize::Zeroize::zeroize(&mut w);
    }
    Ok(super::Values { instance: vec![Fp::from(1u64)], witness })
}

