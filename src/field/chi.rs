// sign function on F_p* that's cheap in r1cs: with p - 1 = 2^32 t and a^t = zeta^chi(a), sgn(a) is the top bit of chi(a)
// to prove sgn(a) = 0 the prover gives 31 bits of i and s with s^(2^32) = a gamma^-i (see sign_hint)

use std::sync::OnceLock;

use ark_ff::{BigInt, BigInteger, FftField, Field, One, PrimeField, Zero};

use crate::types::Fp;

pub const S2: u32 = 32;

pub struct ChiConsts {
    pub t: BigInt<4>,
    pub e: BigInt<4>,
    pub gamma_inv_pow: Vec<Fp>,
    pub gamma: Fp,
    zeta_inv_pow: Vec<Fp>,
}

// x^-1 mod 2^32 for odd x
fn inv_mod_2_32(x: u32) -> u32 {
    let mut y: u32 = 1;
    for _ in 0..5 {
        y = y.wrapping_mul(2u32.wrapping_sub(x.wrapping_mul(y)));
    }
    y
}

// 2^-32 mod t, computed as (1 + k t) / 2^32
fn inv_pow2_mod(t: &BigInt<4>) -> BigInt<4> {
    let t0 = t.0[0] as u32;
    let k = (inv_mod_2_32(t0)).wrapping_neg() as u64;
    let mut n = [0u64; 5];
    let mut carry: u128 = 1;
    for (i, limb) in t.0.iter().enumerate() {
        let v = (*limb as u128) * (k as u128) + carry;
        n[i] = v as u64;
        carry = v >> 64;
    }
    n[4] = carry as u64;
    assert_eq!(n[0] as u32, 0, "1 + k·t ≡ 0 mod 2^32");
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = (n[i] >> 32) | (n[i + 1] << 32);
    }
    BigInt(out)
}

pub fn consts() -> &'static ChiConsts {
    static C: OnceLock<ChiConsts> = OnceLock::new();
    C.get_or_init(|| {
        assert_eq!(Fp::TWO_ADICITY, S2);
        let t = Fp::TRACE;
        let zeta = Fp::TWO_ADIC_ROOT_OF_UNITY;
        let t_inv = inv_mod_2_32(t.0[0] as u32);
        let gamma = zeta.pow([t_inv as u64]);
        let gi = gamma.inverse().unwrap();
        let zi = zeta.inverse().unwrap();
        let mut gamma_inv_pow = Vec::with_capacity(31);
        let mut zeta_inv_pow = Vec::with_capacity(32);
        let (mut g, mut z) = (gi, zi);
        for _ in 0..32 {
            gamma_inv_pow.push(g);
            zeta_inv_pow.push(z);
            g.square_in_place();
            z.square_in_place();
        }
        gamma_inv_pow.truncate(31);
        ChiConsts { t, e: inv_pow2_mod(&t), gamma_inv_pow, gamma, zeta_inv_pow }
    })
}

// chi(a) for a != 0 by pohlig-hellman, reference version
pub fn chi(a: Fp) -> u32 {
    let c = consts();
    let r = a.pow(c.t);
    let mut i: u32 = 0;
    let mut cur = r;
    for k in 0..S2 {
        // the 2^(31-k)-th power of cur is +-1 and gives bit k
        let mut v = cur;
        for _ in 0..(S2 - 1 - k) {
            v.square_in_place();
        }
        let bit = v != Fp::one();
        let sel = if bit { c.zeta_inv_pow[k as usize] } else { Fp::one() };
        cur *= sel;
        i |= (bit as u32) << k;
    }
    debug_assert_eq!(cur, Fp::one());
    i
}

// top bit of chi(a); sgn(0) = false
pub fn sgn(a: Fp) -> bool {
    if a.is_zero() {
        return false;
    }
    chi(a) >> 31 == 1
}

// prover hint (i, s) for sgn(a) = 0; None if a = 0 or sgn(a) = 1
pub fn sign_hint(a: Fp) -> Option<(u32, Fp)> {
    if a.is_zero() {
        return None;
    }
    let i = chi_fast(a);
    if i >> 31 == 1 {
        return None;
    }
    let c = consts();
    let gi: Fp = (0..31).filter(|k| (i >> k) & 1 == 1).map(|k| c.gamma_inv_pow[k]).product();
    let s = pow_window(a * gi, &c.e);
    Some((i, s))
}

// faster chi and sqrt, variable time
// dlog in mu_(2^32) uses four 8-bit table lookups; one exponentiation gives both a square root and its chi

pub struct FastTables {
    // (first limb of g^d, d) for g = zeta^(2^24), sorted
    look: Vec<(u64, u8)>,
    gpow: Vec<Fp>,
    // zinv[k][d] = zeta^(-d * 2^(8k))
    zinv: Vec<Vec<Fp>>,
    e_half: BigInt<4>,
}

pub fn fast() -> &'static FastTables {
    static F: OnceLock<FastTables> = OnceLock::new();
    F.get_or_init(|| {
        let c = consts();
        let zeta = Fp::TWO_ADIC_ROOT_OF_UNITY;
        let g = zeta.pow([1u64 << 24]);
        let mut gpow = Vec::with_capacity(256);
        let mut x = Fp::one();
        for _ in 0..256 {
            gpow.push(x);
            x *= g;
        }
        assert_eq!(x, Fp::one(), "g has order 2^8");
        let mut look: Vec<(u64, u8)> = gpow.iter().enumerate().map(|(d, v)| (v.0 .0[0], d as u8)).collect();
        look.sort_unstable();
        let zi = zeta.inverse().unwrap();
        let zinv = (0..4)
            .map(|k| {
                let step = zi.pow([1u64 << (8 * k)]);
                let mut v = Vec::with_capacity(256);
                let mut y = Fp::one();
                for _ in 0..256 {
                    v.push(y);
                    y *= step;
                }
                v
            })
            .collect();
        let mut e_half = c.t;
        e_half.div2();
        FastTables { look, gpow, zinv, e_half }
    })
}

fn dlog8(f: &FastTables, v: Fp) -> u32 {
    let l = v.0 .0[0];
    let start = f.look.partition_point(|(x, _)| *x < l);
    for (x, d) in &f.look[start..] {
        if *x != l {
            break;
        }
        if f.gpow[*d as usize] == v {
            return *d as u32;
        }
    }
    panic!("dlog8: argument not in μ_(2^8)");
}

// i with r = zeta^i, for r in mu_(2^32)
pub fn dlog(r: Fp) -> u32 {
    let f = fast();
    let mut i = 0u32;
    let mut cur = r;
    for k in 0..4u32 {
        let mut v = cur;
        for _ in 0..(24 - 8 * k) {
            v.square_in_place();
        }
        let d = dlog8(f, v);
        i |= d << (8 * k);
        if d != 0 {
            cur *= f.zinv[k as usize][d as usize];
        }
    }
    debug_assert_eq!(cur, Fp::one());
    i
}

pub fn zeta_pow_neg(k: u32) -> Fp {
    let f = fast();
    let mut out = Fp::one();
    for j in 0..4 {
        let d = ((k >> (8 * j)) & 0xff) as usize;
        if d != 0 {
            out *= f.zinv[j][d];
        }
    }
    out
}

// a^e with a 4-bit window
pub fn pow_window(a: Fp, e: &BigInt<4>) -> Fp {
    let mut tab = [Fp::one(); 16];
    for i in 1..16 {
        tab[i] = tab[i - 1] * a;
    }
    let mut out = Fp::one();
    let mut started = false;
    for limb in e.0.iter().rev() {
        for nib in (0..16).rev() {
            let d = ((limb >> (4 * nib)) & 0xf) as usize;
            if started {
                for _ in 0..4 {
                    out.square_in_place();
                }
            }
            if d != 0 {
                out *= tab[d];
                started = true;
            }
        }
    }
    out
}

// chi with the table dlog
pub fn chi_fast(a: Fp) -> u32 {
    dlog(pow_window(a, &consts().t))
}

pub fn sgn_fast(a: Fp) -> bool {
    !a.is_zero() && chi_fast(a) >> 31 == 1
}

// a square root y of a together with chi(y), or None if a isn't a square
pub fn sqrt_chi(a: Fp) -> Option<(Fp, u32)> {
    if a.is_zero() {
        return Some((Fp::zero(), 0));
    }
    let b = pow_window(a, &fast().e_half);
    let i = dlog(b.square() * a);
    if i & 1 == 1 {
        return None;
    }
    Some((a * b * zeta_pow_neg(i / 2), i / 2))
}

