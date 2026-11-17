// maurer's sigma protocol for a linear map f: Z_q0^n -> G0^m with fiat-shamir
// a precommitted first message is consumed by prove_with

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use ark_std::UniformRand;

use crate::transcript::Transcript;
use crate::types::{Fq0, G0Affine, G0Projective};

// one output coordinate: sum_k [w_(idx_k)]base_k
pub type LinearRow = Vec<(usize, G0Affine)>;

#[derive(Clone, Debug)]
pub struct LinearStatement {
    pub n_witness: usize,
    pub rows: Vec<LinearRow>,
    pub image: Vec<G0Affine>,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SigmaProof {
    pub commitment: Vec<G0Affine>,
    pub response: Vec<Fq0>,
}

// precomputed first message (kappa, f(kappa)) for one shape. single use, not Clone
#[derive(Debug)]
pub struct Precommit {
    pub(crate) kappa: Vec<Fq0>,
    pub(crate) commitment: Vec<G0Affine>,
    pub(crate) bases_digest: [u8; 64],
}

impl LinearStatement {
    pub fn apply(&self, w: &[Fq0]) -> Vec<G0Projective> {
        assert_eq!(w.len(), self.n_witness);
        let row_vt = |row: &LinearRow| -> G0Projective {
            if row.len() > 16 {
                let bases: Vec<G0Affine> = row.iter().map(|(_, b)| *b).collect();
                let scalars: Vec<Fq0> = row.iter().map(|(i, _)| w[*i]).collect();
                G0Projective::msm_unchecked(&bases, &scalars)
            } else {
                row.iter().map(|(i, b)| *b * w[*i]).sum()
            }
        };
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            self.rows.par_iter().map(row_vt).collect()
        }
        #[cfg(not(feature = "parallel"))]
        self.rows.iter().map(row_vt).collect()
    }

    // constant-time f(w)
    pub fn apply_ct(&self, w: &[Fq0]) -> Vec<G0Projective> {
        assert_eq!(w.len(), self.n_witness);
        let row_ct = |row: &LinearRow| {
            row.iter().map(|(i, b)| crate::ct::mul(b, &w[*i])).fold(G0Projective::default(), |a, b| a + b)
        };
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            self.rows.par_iter().map(row_ct).collect()
        }
        #[cfg(not(feature = "parallel"))]
        self.rows.iter().map(row_ct).collect()
    }

    fn absorb_bases(&self, t: &mut Transcript) {
        t.append_u64(b"n_witness", self.n_witness as u64);
        t.append_u64(b"n_rows", self.rows.len() as u64);
        for row in &self.rows {
            t.append_u64(b"row_len", row.len() as u64);
            for (i, b) in row {
                t.append_u64(b"idx", *i as u64);
                t.append(b"base", b);
            }
        }
    }

    fn bases_digest(&self) -> [u8; 64] {
        let mut t = Transcript::new(b"SPICy/maurer/bases");
        self.absorb_bases(&mut t);
        t.challenge_bytes(b"digest")
    }

    fn absorb(&self, t: &mut Transcript) {
        self.absorb_bases(t);
        t.append(b"image", &self.image);
    }
}

// offline: sample kappa and compute f(kappa), only the bases of stmt are used
pub fn precommit<R: RngCore>(stmt: &LinearStatement, rng: &mut R) -> Precommit {
    let kappa: Vec<Fq0> = (0..stmt.n_witness).map(|_| Fq0::rand(rng)).collect();
    let commitment = G0Projective::normalize_batch(&stmt.apply(&kappa));
    Precommit { kappa, commitment, bases_digest: stmt.bases_digest() }
}

// online prover part, consumes the precommitment
pub fn prove_with(t: &mut Transcript, stmt: &LinearStatement, w: &[Fq0], pre: Precommit) -> SigmaProof {
    assert_eq!(pre.bases_digest, stmt.bases_digest(), "precommitment was computed for other bases");
    assert_eq!(w.len(), stmt.n_witness);
    stmt.absorb(t);
    t.append(b"commitment", &pre.commitment);
    let e: Fq0 = t.challenge_scalar(b"e");
    let response = pre.kappa.iter().zip(w).map(|(ki, wi)| *ki + e * wi).collect();
    SigmaProof { commitment: pre.commitment.clone(), response }
}

pub fn prove<R: RngCore>(t: &mut Transcript, stmt: &LinearStatement, w: &[Fq0], rng: &mut R) -> SigmaProof {
    let pre = precommit(stmt, rng);
    prove_with(t, stmt, w, pre)
}

// small-exponent batch verification: one msm over all equations with fresh 128-bit weights
pub fn verify(t: &mut Transcript, stmt: &LinearStatement, proof: &SigmaProof) -> bool {
    if proof.commitment.len() != stmt.rows.len()
        || proof.response.len() != stmt.n_witness
        || stmt.image.len() != stmt.rows.len()
    {
        return false;
    }
    stmt.absorb(t);
    t.append(b"commitment", &proof.commitment);
    let e: Fq0 = t.challenge_scalar(b"e");
    let mut rng = rand::thread_rng();
    let mut bases = Vec::new();
    let mut scalars = Vec::new();
    for (i, row) in stmt.rows.iter().enumerate() {
        let mut wb = [0u8; 16];
        rng.fill_bytes(&mut wb);
        let rho = Fq0::from_le_bytes_mod_order(&wb);
        for (k, b) in row {
            bases.push(*b);
            scalars.push(rho * proof.response[*k]);
        }
        bases.push(proof.commitment[i]);
        scalars.push(-rho);
        bases.push(stmt.image[i]);
        scalars.push(-(rho * e));
    }
    G0Projective::msm_unchecked(&bases, &scalars).is_zero()
}

// unbatched verification
pub fn verify_each(t: &mut Transcript, stmt: &LinearStatement, proof: &SigmaProof) -> bool {
    if proof.commitment.len() != stmt.rows.len()
        || proof.response.len() != stmt.n_witness
        || stmt.image.len() != stmt.rows.len()
    {
        return false;
    }
    stmt.absorb(t);
    t.append(b"commitment", &proof.commitment);
    let e: Fq0 = t.challenge_scalar(b"e");
    let lhs = stmt.apply(&proof.response);
    lhs.iter().zip(proof.commitment.iter().zip(&stmt.image)).all(|(l, (a, y))| *l == a.into_group() + *y * e)
}

// honest-verifier simulator
pub fn simulate<R: RngCore>(stmt: &LinearStatement, e: Fq0, rng: &mut R) -> SigmaProof {
    let s: Vec<Fq0> = (0..stmt.n_witness).map(|_| Fq0::rand(rng)).collect();
    let fs = stmt.apply(&s);
    let a: Vec<G0Projective> = fs.iter().zip(&stmt.image).map(|(f, y)| *f - *y * e).collect();
    SigmaProof { commitment: G0Projective::normalize_batch(&a), response: s }
}

