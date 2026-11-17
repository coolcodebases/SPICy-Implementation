// relations R_pow, R_tok and R_pair as arkworks r1cs circuits
// the bracketed Com conjuncts are not constraints: the commitments are the pre-committed rows

pub mod gadgets;
pub mod r_pair;
pub mod r_pow;
pub mod r_tok;

use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError, SynthesisMode};

use crate::params::CycGens;
use crate::snark::r1cs::R1cs;
use crate::types::{Fp, GcycAffine};

// relation over F_p whose witness starts with rows pre-committed in G_cyc
pub trait CommittedRelation {
    type Statement;
    type Witness;
    type Circuit: ConstraintSynthesizer<Fp>;
    // domain tag of H_t
    const DOMAIN: &'static [u8];
    const NAME: &'static str;

    // M, entries per row
    fn m(stmt: &Self::Statement) -> usize;
    // everything the shape depends on; equal keys must give identical matrices
    fn shape_key(stmt: &Self::Statement) -> Vec<usize>;
    // fixed row width, overrides snark::choose_width
    fn fixed_width(_stmt: &Self::Statement) -> Option<usize> {
        None
    }
    // wit = None builds the shape only
    fn circuit(stmt: &Self::Statement, wit: Option<&Self::Witness>, width: usize) -> Self::Circuit;
    // commitments to the first witness rows, in order
    fn external_rows(stmt: &Self::Statement) -> Vec<GcycAffine>;
    // (values, blind) per row
    fn external_openings(wit: &Self::Witness) -> Vec<(Vec<Fp>, Fp)>;
    // public inputs in allocation order, None if the statement is malformed
    fn public_inputs(stmt: &Self::Statement) -> Option<Vec<Fp>>;
    // native check of the whole relation, Com conjuncts included
    fn check_relation(gens: &CycGens, stmt: &Self::Statement, wit: &Self::Witness) -> bool;
    // rows + public inputs + identical slots, if the circuit has that form (R_tok, R_pair)
    // used to build matrices from one slot and for parallel witness gen
    fn slot_layout<'a>(
        _stmt: &'a Self::Statement,
        _wit: Option<&'a Self::Witness>,
        _width: usize,
    ) -> Option<SlotLayout<'a>> {
        None
    }
    // assignment values, slot by slot when there is a slot layout
    fn values(stmt: &Self::Statement, wit: &Self::Witness, width: usize) -> Result<Values, SynthesisError> {
        match Self::slot_layout(stmt, Some(wit), width) {
            Some(l) => l.values(&Self::external_openings(wit), Self::public_inputs(stmt)),
            None => values_only(Self::circuit(stmt, Some(wit), width)),
        }
    }
}

// instance (with the leading 1) and witness
#[derive(Clone, Debug)]
pub struct Values {
    pub instance: Vec<Fp>,
    pub witness: Vec<Fp>,
}

pub(crate) fn prove_cs() -> ConstraintSystemRef<Fp> {
    let cs = ConstraintSystem::<Fp>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    // values only: no constraints or matrices stored
    cs.set_mode(SynthesisMode::Prove { construct_matrices: false });
    cs
}

pub(crate) fn take_values(cs: &ConstraintSystemRef<Fp>) -> Result<Values, SynthesisError> {
    let b = cs.borrow().ok_or(SynthesisError::MissingCS)?;
    Ok(Values { instance: b.instance_assignment.clone(), witness: b.witness_assignment.clone() })
}

// one synthesis, values only
pub fn values_only<C: ConstraintSynthesizer<Fp>>(circuit: C) -> Result<Values, SynthesisError> {
    let cs = prove_cs();
    circuit.generate_constraints(cs.clone())?;
    take_values(&cs)
}

// gadget of one slot, given its pre-committed entries; allocates its own public inputs and may depend on j only through values so every slot has the same constraints
pub type SlotGadget<'a> =
    Box<dyn Fn(ConstraintSystemRef<Fp>, usize, &[FpVar<Fp>]) -> Result<(), SynthesisError> + Sync + Send + 'a>;

// layout: pre-committed rows, then every slot's public inputs, then the identical slots
pub struct SlotLayout<'a> {
    pub rows: usize,
    pub width: usize,
    pub slots: usize,
    pub inputs_per_slot: usize,
    // (row, column) entries slot j reads, increasing
    pub entries: Box<dyn Fn(usize) -> Vec<(usize, usize)> + Sync + Send + 'a>,
    pub gadget: SlotGadget<'a>,
}

type Matrix = Vec<Vec<(Fp, usize)>>;

// one slot synthesized on its own
struct OneSlot {
    // local column order: 1, slot public inputs, its entries, its own witnesses
    a: Matrix,
    b: Matrix,
    c: Matrix,
    num_inst: usize,
    num_wit: usize,
}

impl SlotLayout<'_> {
    fn checked_entries(&self, j: usize) -> Result<Vec<(usize, usize)>, SynthesisError> {
        let e = (self.entries)(j);
        let idx: Vec<usize> = e.iter().map(|(r, t)| r * self.width + t).collect();
        if e.iter().any(|(r, t)| *r >= self.rows || *t >= self.width) || idx.windows(2).any(|w| w[0] >= w[1]) {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(e)
    }

    fn synthesize_slot(&self, j: usize) -> Result<OneSlot, SynthesisError> {
        let cs = ConstraintSystem::<Fp>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        let n = self.checked_entries(j)?.len();
        let vars = (0..n).map(|_| FpVar::new_witness(cs.clone(), || Ok(Fp::from(0u64)))).collect::<Result<Vec<_>, _>>()?;
        (self.gadget)(cs.clone(), j, &vars)?;
        cs.finalize();
        let m = cs.to_matrices().ok_or(SynthesisError::MissingCS)?;
        if m.num_instance_variables != 1 + self.inputs_per_slot || m.num_witness_variables < n {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(OneSlot { a: m.a, b: m.b, c: m.c, num_inst: m.num_instance_variables, num_wit: m.num_witness_variables })
    }

    // witness count of the whole circuit
    pub fn num_witnesses(&self) -> Result<usize, SynthesisError> {
        let one = self.synthesize_slot(0)?;
        let n = self.checked_entries(0)?.len();
        Ok(self.rows * self.width + self.slots * (one.num_wit - n))
    }

    // full matrices by copying one slot and shifting columns
    pub fn shape(&self) -> Result<R1cs, SynthesisError> {
        use crate::snark::matrix::{Coeffs, Matrix as Csr};
        let one = self.synthesize_slot(0)?;
        let n = self.checked_entries(0)?.len();
        let own = one.num_wit - n;
        let num_inst = 1 + self.slots * self.inputs_per_slot;
        let num_wit = self.rows * self.width + self.slots * own;
        let flat = |mat: &Matrix| -> (Vec<u32>, Vec<usize>, Vec<u32>, Vec<Fp>) {
            let mut t = Coeffs::default();
            let mut ptr = vec![0u32];
            let (mut cols, mut coef) = (Vec::new(), Vec::new());
            for row in mat {
                for (v, i) in row {
                    cols.push(*i);
                    coef.push(t.intern(*v));
                }
                ptr.push(u32::try_from(cols.len()).expect("nnz < 2^32"));
            }
            (ptr, cols, coef, t.into_vals())
        };
        let tmpl = [flat(&one.a), flat(&one.b), flat(&one.c)];
        // slot j's column map (increasing in the local index)
        let per_slot = |j: usize| -> Result<[Vec<u32>; 3], SynthesisError> {
            let entries = self.checked_entries(j)?;
            if entries.len() != n {
                return Err(SynthesisError::Unsatisfiable);
            }
            let map = |idx: usize| -> u32 {
                let g = if idx == 0 {
                    0
                } else if idx < one.num_inst {
                    1 + j * self.inputs_per_slot + (idx - 1)
                } else {
                    let w = idx - one.num_inst;
                    num_inst
                        + if w < n {
                            let (r, t) = entries[w];
                            r * self.width + t
                        } else {
                            self.rows * self.width + j * own + (w - n)
                        }
                };
                u32::try_from(g).expect("index < 2^32")
            };
            Ok([0, 1, 2].map(|m| tmpl[m].1.iter().map(|i| map(*i)).collect()))
        };
        let parts = crate::par::map_range(self.slots, per_slot).into_iter().collect::<Result<Vec<_>, _>>()?;
        let build = |m: usize| -> Csr {
            let (ptr, _, coef, vals) = &tmpl[m];
            let (rows, nnz) = (ptr.len() - 1, coef.len());
            let mut row_ptr = Vec::with_capacity(self.slots * rows + 1);
            let (mut col, mut cf) = (Vec::with_capacity(self.slots * nnz), Vec::with_capacity(self.slots * nnz));
            row_ptr.push(0u32);
            for (j, p) in parts.iter().enumerate() {
                let base = u32::try_from(j * nnz).expect("nnz < 2^32");
                for i in 0..rows {
                    let (s, e) = (ptr[i] as usize, ptr[i + 1] as usize);
                    let (c0, k0) = (col.len(), cf.len());
                    col.extend_from_slice(&p[m][s..e]);
                    cf.extend_from_slice(&coef[s..e]);
                    // rows are stored sorted by column, as arkworks stores them
                    if col[c0..].windows(2).any(|w| w[0] >= w[1]) {
                        let mut pairs: Vec<(u32, u32)> = col[c0..].iter().copied().zip(cf[k0..].iter().copied()).collect();
                        pairs.sort_by_key(|(c, _)| *c);
                        for (q, (c, k)) in pairs.into_iter().enumerate() {
                            col[c0 + q] = c;
                            cf[k0 + q] = k;
                        }
                    }
                    row_ptr.push(base + ptr[i + 1]);
                }
            }
            Csr::from_parts(row_ptr, col, cf, vals.clone())
        };
        let ((a, b), c) = crate::par::join(|| crate::par::join(|| build(0), || build(1)), || build(2));
        Ok(R1cs::new(num_inst, num_wit, a, b, c))
    }

    // zero-padded rows, then each slot's own witnesses, in parallel
    pub fn values(&self, openings: &[(Vec<Fp>, Fp)], public_inputs: Option<Vec<Fp>>) -> Result<Values, SynthesisError> {
        let io = public_inputs.ok_or(SynthesisError::AssignmentMissing)?;
        if openings.len() != self.rows || openings.iter().any(|(v, _)| v.len() > self.width) {
            return Err(SynthesisError::Unsatisfiable);
        }
        let mut witness = Vec::with_capacity(self.rows * self.width);
        for (vals, _) in openings {
            witness.extend_from_slice(vals);
            witness.resize(witness.len() + self.width - vals.len(), Fp::from(0u64));
        }
        let per_slot = crate::par::map_range(self.slots, |j| -> Result<Vec<Fp>, SynthesisError> {
            let cs = prove_cs();
            let entries = self.checked_entries(j)?;
            let vars = entries
                .iter()
                .map(|(r, t)| {
                    let v = openings[*r].0.get(*t).copied().unwrap_or(Fp::from(0u64));
                    FpVar::new_witness(cs.clone(), || Ok(v))
                })
                .collect::<Result<Vec<_>, _>>()?;
            (self.gadget)(cs.clone(), j, &vars)?;
            let v = take_values(&cs)?;
            Ok(v.witness[entries.len()..].to_vec())
        });
        for w in per_slot {
            let mut w = w?;
            witness.extend_from_slice(&w);
            zeroize::Zeroize::zeroize(&mut w);
        }
        let mut instance = Vec::with_capacity(io.len() + 1);
        instance.push(Fp::from(1u64));
        instance.extend(io);
        Ok(Values { instance, witness })
    }
}

pub use gadgets::AffineVar;
