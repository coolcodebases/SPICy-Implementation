// parameters and setup; every generator is hashed to the curve from a fixed tag

use std::sync::OnceLock;

use ark_ec::AffineRepr;
use ark_ff::PrimeField;

use crate::error::{Result, SpicyError};
use crate::oracle::{h_domain, hash_to_curve};
use crate::types::{Fp, G0Affine};

// floor(log2 p)
pub const LOG2_P: f64 = 254.0;

// upper bound on log2 q0
pub const LOG2_Q0: f64 = 255.0;

// default statistical security kappa for n_g
pub const DEFAULT_STAT_BITS: u32 = 128;

// H1 query bound q1
pub const LOG2_Q1: f64 = 107.0;

// sizes fixed at registration
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    // M = |X|, number of slots
    pub m: usize,
    // N = |Y|
    pub n: usize,
    // number of coeffs of the mask g, at least 4(N+1)
    pub n_g: usize,
}

impl Params {
    // n_g at kappa = DEFAULT_STAT_BITS
    pub fn new(m: usize, n: usize) -> Result<Self> {
        Self::with_mask_len(m, n, mask_len(n, m, DEFAULT_STAT_BITS))
    }

    // explicit mask length n_g >= 4(N+1)
    pub fn with_mask_len(m: usize, n: usize, n_g: usize) -> Result<Self> {
        let p = Params { m, n, n_g };
        p.validate()?;
        Ok(p)
    }

    // 4(N+1), number of coeffs of pk_R
    pub fn key_len(&self) -> usize {
        4 * self.poly_len()
    }

    pub fn poly_len(&self) -> usize {
        self.n + 1
    }

    pub fn validate(&self) -> Result<()> {
        if self.m == 0 {
            return Err(SpicyError::Params("M must be ≥ 1".into()));
        }
        if self.n == 0 {
            return Err(SpicyError::Params("N must be ≥ 1".into()));
        }
        if (self.m as u64) >= (1u64 << 32) {
            return Err(SpicyError::Params("M must be < 2^32 (a practical bound on the number of slots)".into()));
        }
        if self.n_g < self.key_len() {
            return Err(SpicyError::Params(format!("n_g = {} must be ≥ 4(N+1) = {}", self.n_g, self.key_len())));
        }
        Ok(())
    }
}

// log2 of the bound eps_ov(q, n'')
pub fn log2_eps_ov(log2_q: f64, n2: usize, n: usize) -> f64 {
    LOG2_Q0 + n2 as f64 * ((6.0f64).log2() + log2_q - LOG2_P) + 4.0 * (n as f64 + 1.0) * LOG2_P
}

// n_g = max(4(N+1), n'') for the smallest n'' with both bounds at most 2^-(kappa+1)
pub fn mask_len(n: usize, m: usize, stat_bits: u32) -> usize {
    let k = stat_bits as f64 + 1.0;
    for n2 in 8usize.. {
        let log_v = k + (2.0 * m as f64 * n2 as f64).log2();
        if (16.0 * n2 as f64).log2() + log_v > LOG2_P {
            break;
        }
        if 1.0 + log2_eps_ov(log_v, n2, n) <= -k {
            return n2.max(4 * (n + 1));
        }
    }
    panic!("no mask length is large enough for N = {n}, M = {m}");
}

// slack n': a corrupted receiver's key makes fewer than n' elements testable
pub fn slack(n: usize, stat_bits: u32) -> usize {
    (1usize..).find(|&n1| log2_eps_ov(LOG2_Q1, n1, n) <= -(stat_bits as f64)).expect("slack exists")
}

// H0 in G0 with unknown dlog
pub fn h0() -> G0Affine {
    static H0: OnceLock<G0Affine> = OnceLock::new();
    *H0.get_or_init(|| hash_to_curve::<ark_pallas::PallasConfig>(b"SPICy/H0"))
}

// W_R = H_G("W", id_R)
pub fn w_r(id_r: &[u8]) -> G0Affine {
    let mut label = b"SPICy/H_G/W/".to_vec();
    label.extend_from_slice(&(id_r.len() as u64).to_le_bytes());
    label.extend_from_slice(id_r);
    hash_to_curve::<ark_pallas::PallasConfig>(&label)
}

// public mask g(X), coeffs hashed from a setup string
pub fn mask(n_g: usize) -> Vec<Fp> {
    (0..n_g)
        .map(|k| Fp::from_le_bytes_mod_order(&h_domain(b"SPICy/mask", &[b"SPICy setup v1", &(k as u64).to_le_bytes()])))
        .collect()
}

// public params of wic
#[derive(Clone, Debug)]
pub struct PublicParams {
    pub params: Params,
    pub g0: G0Affine,
    pub mask: Vec<Fp>,
}

// Setup(1^lambda)
pub fn setup(params: &Params) -> Result<PublicParams> {
    params.validate()?;
    Ok(PublicParams { params: params.clone(), g0: G0Affine::generator(), mask: mask(params.n_g) })
}

