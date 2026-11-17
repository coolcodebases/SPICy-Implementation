// parameters and Setup
// every generator is hashed to the curve from a fixed tag

use std::sync::OnceLock;

use ark_ec::AffineRepr;
use ark_ff::PrimeField;

use crate::error::{Result, SpicyError};
use crate::oracle::{h_domain, hash_to_curve};
use crate::types::{Fp, G0Affine, GcycAffine};

// log2 p, rounded down
pub const LOG2_P: f64 = 254.0;

// upper bound on log2 q0
pub const LOG2_Q0: f64 = 255.0;

// default statistical security kappa for n_g
pub const DEFAULT_STAT_BITS: u32 = 128;

// H1 query bound q1 = 2^107
pub const LOG2_Q1: f64 = 107.0;

// sizes fixed at registration
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Params {
    // M = |X|, number of slots
    pub m: usize,
    // N = |Y|
    pub n: usize,
    // number of coefficients of the mask g
    pub n_g: usize,
    // paterson-stockmeyer step S: the sender commits to z^1..z^S and g(z), higher degrees come from horner in z^S
    pub ps_step: usize,
}

impl Params {
    // n_g for kappa = DEFAULT_STAT_BITS
    pub fn new(m: usize, n: usize) -> Result<Self> {
        Self::with_mask_len(m, n, mask_len(n, m, DEFAULT_STAT_BITS))
    }

    // explicit mask length n_g, at least 4(N+1)
    pub fn with_mask_len(m: usize, n: usize, n_g: usize) -> Result<Self> {
        Self::with_ps_step(m, n, n_g, default_ps_step(n, n_g))
    }

    pub fn with_ps_step(m: usize, n: usize, n_g: usize, ps_step: usize) -> Result<Self> {
        let p = Params { m, n, n_g, ps_step };
        p.validate()?;
        Ok(p)
    }

    // n_blk = ceil((N+1)/S) blocks per polynomial of pk_R
    pub fn key_blocks(&self) -> usize {
        self.poly_len().div_ceil(self.ps_step)
    }

    // ceil(n_g/S) blocks of g
    pub fn mask_blocks(&self) -> usize {
        self.n_g.div_ceil(self.ps_step)
    }

    // 4(N+1) coefficients in pk_R
    pub fn key_len(&self) -> usize {
        4 * self.poly_len()
    }

    pub fn poly_len(&self) -> usize {
        self.n + 1
    }

    // registered rows Z_1..Z_S and Z_g
    pub fn n_rows(&self) -> usize {
        self.ps_step + 1
    }

    pub fn validate(&self) -> Result<()> {
        if self.m == 0 {
            return Err(SpicyError::Params("M must be ≥ 1".into()));
        }
        if self.n == 0 {
            return Err(SpicyError::Params("N must be ≥ 1".into()));
        }
        if self.n_g < self.key_len() {
            return Err(SpicyError::Params(format!("n_g = {} must be ≥ 4(N+1) = {}", self.n_g, self.key_len())));
        }
        if self.ps_step < 2 || self.ps_step > self.n_g {
            return Err(SpicyError::Params(format!("S = {} must be in [2, n_g = {}]", self.ps_step, self.n_g)));
        }
        Ok(())
    }
}

// default paterson-stockmeyer step, balancing registration rows against pair setup blocks
pub fn default_ps_step(n: usize, n_g: usize) -> usize {
    let s = (((n_g + 4 * (n + 1)) as f64) / 2.0).sqrt().ceil() as usize;
    s.clamp(2, n_g.max(2))
}

// log2 eps_ov(q, n'')
pub fn log2_eps_ov(log2_q: f64, n2: usize, n: usize) -> f64 {
    LOG2_Q0 + n2 as f64 * ((6.0f64).log2() + log2_q - LOG2_P) + 4.0 * (n as f64 + 1.0) * LOG2_P
}

// n_g = max(4(N+1), n'') for the smallest n'' with eps_fr at most 2^-(kappa+1), taking the smallest allowed V = 2^(kappa+1) * 2Mn''
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

// generators G^(1..len) and H_cyc
// G^(j) depends only on j, so a longer vector (hyrax row width above M) extends the registration generators
#[derive(Clone, Debug)]
pub struct CycGens {
    pub g: Vec<GcycAffine>,
    pub h: GcycAffine,
}

impl CycGens {
    pub fn derive(len: usize) -> Self {
        let g = crate::par::map_range(len, |j| hash_to_curve::<ark_vesta::VestaConfig>(format!("SPICy/G_cyc/{j}").as_bytes()));
        CycGens { g, h: h_cyc() }
    }
}

pub fn h_cyc() -> GcycAffine {
    hash_to_curve::<ark_vesta::VestaConfig>(b"SPICy/H_cyc")
}

// extra generator for committed scalars inside spartan
pub fn g_cyc_scalar() -> GcycAffine {
    hash_to_curve::<ark_vesta::VestaConfig>(b"SPICy/G_cyc/scalar")
}

pub fn h0() -> G0Affine {
    static H0: OnceLock<G0Affine> = OnceLock::new();
    *H0.get_or_init(|| hash_to_curve::<ark_pallas::PallasConfig>(b"SPICy/H0"))
}

// H0', the second token base
pub fn h0_prime() -> G0Affine {
    static H0P: OnceLock<G0Affine> = OnceLock::new();
    *H0P.get_or_init(|| hash_to_curve::<ark_pallas::PallasConfig>(b"SPICy/H0'"))
}

// blinding base of C_s
pub fn b0() -> G0Affine {
    static B0: OnceLock<G0Affine> = OnceLock::new();
    *B0.get_or_init(|| hash_to_curve::<ark_pallas::PallasConfig>(b"SPICy/B0"))
}

// slot bases (B_(j,1), B_(j,2)) of C_s, 0-based j
pub fn b_slot(j: usize) -> (G0Affine, G0Affine) {
    (
        hash_to_curve::<ark_pallas::PallasConfig>(format!("SPICy/B/{j}/1").as_bytes()),
        hash_to_curve::<ark_pallas::PallasConfig>(format!("SPICy/B/{j}/2").as_bytes()),
    )
}

// W_R = H_G(W, id_R)
pub fn w_r(id_r: &[u8]) -> G0Affine {
    let mut label = b"SPICy/H_G/W/".to_vec();
    label.extend_from_slice(&(id_r.len() as u64).to_le_bytes());
    label.extend_from_slice(id_r);
    hash_to_curve::<ark_pallas::PallasConfig>(&label)
}

// coefficients of the public mask g(X), hashed from a setup string
pub fn mask(n_g: usize) -> Vec<Fp> {
    crate::par::map_range(n_g, |k| Fp::from_le_bytes_mod_order(&h_domain(b"SPICy/mask", &[b"SPICy setup v1", &(k as u64).to_le_bytes()])))
}

// public parameters pp
#[derive(Clone, Debug)]
pub struct PublicParams {
    pub params: Params,
    pub g0: G0Affine,
    pub h0: G0Affine,
    pub h0p: G0Affine,
    pub b0: G0Affine,
    pub b: Vec<(G0Affine, G0Affine)>,
    pub gens: CycGens,
    pub mask: Vec<Fp>,
}

// setup, cached per process
pub fn setup_cached(params: &Params) -> Result<PublicParams> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    static C: OnceLock<Mutex<HashMap<Params, Arc<PublicParams>>>> = OnceLock::new();
    let c = C.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(pp) = c.lock().expect("setup cache poisoned").get(params) {
        return Ok((**pp).clone());
    }
    let pp = Arc::new(setup(params)?);
    c.lock().expect("setup cache poisoned").insert(params.clone(), pp.clone());
    Ok((*pp).clone())
}

// Setup
pub fn setup(params: &Params) -> Result<PublicParams> {
    params.validate()?;
    Ok(PublicParams {
        params: params.clone(),
        g0: G0Affine::generator(),
        h0: h0(),
        h0p: h0_prime(),
        b0: b0(),
        b: crate::par::map_range(params.m, b_slot),
        gens: CycGens::derive(params.m),
        mask: mask(params.n_g),
    })
}

