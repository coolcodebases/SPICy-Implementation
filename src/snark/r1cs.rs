// r1cs matrices and assignments from an arkworks circuit
// index i < num_inst is instance var i (0 is the constant 1), num_inst + j is witness var j

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode};

use crate::circuits::{CommittedRelation, Values};
use crate::error::{Result, SpicyError};
use crate::types::Fp;

pub use super::matrix::Matrix;

// transposes caches A^T, B^T, C^T for the spartan prover
#[derive(Clone, Debug)]
pub struct R1cs {
    pub num_cons: usize,
    // instance vars, constant 1 included
    pub num_inst: usize,
    pub num_wit: usize,
    pub a: Matrix,
    pub b: Matrix,
    pub c: Matrix,
    pub transposes: std::sync::OnceLock<std::sync::Arc<[Matrix; 3]>>,
}

// shape only (setup mode)
pub fn shape<C: ConstraintSynthesizer<Fp>>(circuit: C) -> Result<R1cs> {
    let cs = ConstraintSystem::<Fp>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit.generate_constraints(cs.clone())?;
    cs.finalize();
    let m = cs.to_matrices().ok_or_else(|| SpicyError::Synthesis("no matrices".into()))?;
    Ok(R1cs {
        num_cons: m.num_constraints,
        num_inst: m.num_instance_variables,
        num_wit: m.num_witness_variables,
        a: Matrix::from_rows(&m.a),
        b: Matrix::from_rows(&m.b),
        c: Matrix::from_rows(&m.c),
        transposes: Default::default(),
    })
}

// matrices at row width width, copied from one slot when there is a slot layout, else full synthesis
pub fn relation_shape<Rel: CommittedRelation>(stmt: &Rel::Statement, width: usize) -> Result<R1cs> {
    let _span = tracing::info_span!("synthesize_shape", relation = Rel::NAME).entered();
    match Rel::slot_layout(stmt, None, width) {
        Some(l) => Ok(l.shape()?),
        None => shape(Rel::circuit(stmt, None, width)),
    }
}

#[derive(Clone, Debug)]
pub struct Assignment {
    pub r1cs: R1cs,
    // includes the leading 1
    pub instance: Vec<Fp>,
    pub witness: Vec<Fp>,
}

// full synthesis with values, errors if the witness is unsatisfying
pub fn assign<C: ConstraintSynthesizer<Fp>>(circuit: C) -> Result<Assignment> {
    let _span = tracing::info_span!("synthesize_assign").entered();
    let cs = ConstraintSystem::<Fp>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit.generate_constraints(cs.clone())?;
    cs.finalize();
    if !cs.is_satisfied()? {
        let which = cs.which_is_unsatisfied()?.unwrap_or_default();
        return Err(SpicyError::UnsatisfiedWitness(which));
    }
    let m = cs.to_matrices().ok_or_else(|| SpicyError::Synthesis("no matrices".into()))?;
    let b = cs.borrow().ok_or_else(|| SpicyError::Synthesis("cs borrowed".into()))?;
    Ok(Assignment {
        r1cs: R1cs {
            num_cons: m.num_constraints,
            num_inst: m.num_instance_variables,
            num_wit: m.num_witness_variables,
            a: Matrix::from_rows(&m.a),
            b: Matrix::from_rows(&m.b),
            c: Matrix::from_rows(&m.c),
            transposes: Default::default(),
        },
        instance: b.instance_assignment.clone(),
        witness: b.witness_assignment.clone(),
    })
}

// assignment for proving with the cached shape; only the sizes are checked, not satisfiability
pub fn prove_values<Rel: CommittedRelation>(
    stmt: &Rel::Statement,
    wit: &Rel::Witness,
    width: usize,
    shape: &R1cs,
) -> Result<Values> {
    let _span = tracing::info_span!("synthesize_values").entered();
    let v = Rel::values(stmt, wit, width)?;
    if v.instance.len() != shape.num_inst || v.witness.len() != shape.num_wit {
        return Err(SpicyError::Synthesis("assignment does not match the cached shape".into()));
    }
    Ok(v)
}

impl R1cs {
    pub fn new(num_inst: usize, num_wit: usize, a: Matrix, b: Matrix, c: Matrix) -> Self {
        assert!(a.num_rows() == b.num_rows() && b.num_rows() == c.num_rows());
        R1cs { num_cons: a.num_rows(), num_inst, num_wit, a, b, c, transposes: Default::default() }
    }

    // A^T, B^T, C^T, built once
    pub fn transposes(&self) -> &[Matrix; 3] {
        self.transposes.get_or_init(|| {
            let _span = tracing::info_span!("transposes").entered();
            let n = self.num_inst + self.num_wit;
            let [a, b, c] = [&self.a, &self.b, &self.c];
            let ((ta, tb), tc) = crate::par::join(|| crate::par::join(|| a.transpose(n), || b.transpose(n)), || c.transpose(n));
            std::sync::Arc::new([ta, tb, tc])
        })
    }

    fn row_eval(&self, m: &Matrix, i: usize, inst: &[Fp], wit: &[Fp]) -> Fp {
        m.dot_row(i, |k| if k < self.num_inst { inst[k] } else { wit[k - self.num_inst] })
    }

    // Az o Bz = Cz for z = (instance, witness)
    pub fn is_satisfied(&self, inst: &[Fp], wit: &[Fp]) -> bool {
        if inst.len() != self.num_inst || wit.len() != self.num_wit || inst.first() != Some(&Fp::from(1u64)) {
            return false;
        }
        const CHUNK: usize = 1 << 12;
        crate::par::map_range(self.num_cons.div_ceil(CHUNK), |c| {
            (c * CHUNK..((c + 1) * CHUNK).min(self.num_cons)).all(|i| {
                self.row_eval(&self.a, i, inst, wit) * self.row_eval(&self.b, i, inst, wit)
                    == self.row_eval(&self.c, i, inst, wit)
            })
        })
        .into_iter()
        .all(|ok| ok)
    }

    // structural digest for fiat-shamir
    pub fn dims(&self) -> [u64; 3] {
        [self.num_cons as u64, self.num_inst as u64, self.num_wit as u64]
    }
}
