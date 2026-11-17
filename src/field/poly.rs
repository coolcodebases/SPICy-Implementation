// univariate polys: interpolation for KGen_R, horner, and small dense arithmetic for swu root finding
// coeffs are low to high

use ark_ff::{BigInteger, Field, PrimeField};

use crate::error::{Result, SpicyError};

// horner
pub fn eval<F: Field>(coeffs: &[F], x: F) -> F {
    coeffs.iter().rev().fold(F::zero(), |acc, c| acc * x + c)
}

// lagrange interpolation, errors on repeated x
pub fn lagrange_interpolate<F: PrimeField>(points: &[(F, F)]) -> Result<Vec<F>> {
    let t = points.len();
    if t == 0 {
        return Ok(vec![]);
    }
    for i in 0..t {
        for j in (i + 1)..t {
            if points[i].0 == points[j].0 {
                return Err(SpicyError::Input("repeated abscissa in interpolation".into()));
            }
        }
    }
    let mut master = vec![F::one()];
    for (xi, _) in points {
        master = mul(&master, &[-*xi, F::one()]);
    }
    let mut out = vec![F::zero(); t];
    for (i, (xi, yi)) in points.iter().enumerate() {
        // master / (X - x_i) by synthetic division
        let mut q = vec![F::zero(); t];
        let mut carry = F::zero();
        for k in (0..t).rev() {
            carry = master[k + 1] + carry * xi;
            q[k] = carry;
        }
        let denom = eval(&q, *xi);
        let scale = *yi * denom.inverse().expect("distinct abscissae");
        for k in 0..t {
            out[k] += q[k] * scale;
        }
        let _ = i;
    }
    Ok(out)
}

// from this many points on, interpolate uses the subproduct tree
pub const FAST_INTERPOLATION_MIN: usize = 384;

// lagrange for few points, subproduct tree from FAST_INTERPOLATION_MIN on; errors on repeated x
pub fn interpolate<F: PrimeField>(points: &[(F, F)]) -> Result<Vec<F>> {
    if points.len() < FAST_INTERPOLATION_MIN {
        return lagrange_interpolate(points);
    }
    let mut xs: Vec<_> = points.iter().map(|p| p.0.into_bigint()).collect();
    xs.sort_unstable();
    if xs.windows(2).any(|w| w[0] == w[1]) {
        return Err(SpicyError::Input("repeated abscissa in interpolation".into()));
    }
    Ok(super::subproduct::interpolate(points))
}

pub fn trim<F: Field>(mut a: Vec<F>) -> Vec<F> {
    while a.last().is_some_and(|c| c.is_zero()) {
        a.pop();
    }
    a
}

pub fn mul<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
    if a.is_empty() || b.is_empty() {
        return vec![];
    }
    let mut r = vec![F::zero(); a.len() + b.len() - 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            r[i + j] += *x * y;
        }
    }
    r
}

pub fn sub<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
    let n = a.len().max(b.len());
    let mut r = vec![F::zero(); n];
    for (i, x) in a.iter().enumerate() {
        r[i] += x;
    }
    for (i, y) in b.iter().enumerate() {
        r[i] -= y;
    }
    trim(r)
}

pub fn rem<F: Field>(a: &[F], m: &[F]) -> Vec<F> {
    let m = trim(m.to_vec());
    assert!(!m.is_empty(), "division by zero polynomial");
    let mut r = trim(a.to_vec());
    let lead_inv = m.last().unwrap().inverse().unwrap();
    while r.len() >= m.len() {
        let shift = r.len() - m.len();
        let coef = *r.last().unwrap() * lead_inv;
        for (i, mc) in m.iter().enumerate() {
            r[shift + i] -= coef * mc;
        }
        r = trim(r);
    }
    r
}

// monic gcd
pub fn gcd<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
    let mut x = trim(a.to_vec());
    let mut y = trim(b.to_vec());
    while !y.is_empty() {
        let r = rem(&x, &y);
        x = y;
        y = r;
    }
    monic(x)
}

pub fn monic<F: Field>(a: Vec<F>) -> Vec<F> {
    let a = trim(a);
    match a.last() {
        None => a,
        Some(l) => {
            let li = l.inverse().unwrap();
            a.into_iter().map(|c| c * li).collect()
        }
    }
}

// base^e mod m, e as little-endian limbs
pub fn pow_mod<F: Field>(base: &[F], e: &[u64], m: &[F]) -> Vec<F> {
    let mut result = vec![F::one()];
    let base = rem(base, m);
    for limb in e.iter().rev() {
        for bit in (0..64).rev() {
            result = rem(&mul(&result, &result), m);
            if (limb >> bit) & 1 == 1 {
                result = rem(&mul(&result, &base), m);
            }
        }
    }
    result
}

// distinct roots of a nonzero poly, sorted, via gcd(f, X^p - X) and deterministic cantor-zassenhaus splitting
pub fn roots<F: PrimeField>(f: &[F]) -> Vec<F> {
    let f = monic(f.to_vec());
    if f.len() <= 1 {
        return vec![];
    }
    let x = vec![F::zero(), F::one()];
    let xp = pow_mod(&x, F::MODULUS.as_ref(), &f);
    let split = gcd(&f, &sub(&xp, &x));
    let mut out = vec![];
    split_roots(&split, &mut out);
    out.sort_by_key(|r| r.into_bigint());
    out.dedup();
    out
}

fn split_roots<F: PrimeField>(h: &[F], out: &mut Vec<F>) {
    let h = monic(h.to_vec());
    match h.len() {
        0 | 1 => {}
        2 => out.push(-h[0]),
        _ => {
            let half: Vec<u64> = {
                let mut e = F::MODULUS;
                e.sub_with_borrow(&F::BigInt::from(1u64));
                e.div2();
                e.as_ref().to_vec()
            };
            for delta in 1u64.. {
                let base = vec![F::from(delta), F::one()];
                let pw = pow_mod(&base, &half, &h);
                let g = gcd(&h, &sub(&pw, &[F::one()]));
                if g.len() > 1 && g.len() < h.len() {
                    let (q, r) = div(&h, &g);
                    debug_assert!(r.is_empty());
                    split_roots(&g, out);
                    split_roots(&q, out);
                    return;
                }
                if delta > 512 {
                    // repeated factor
                    return;
                }
            }
        }
    }
}

pub fn div<F: Field>(a: &[F], m: &[F]) -> (Vec<F>, Vec<F>) {
    let m = trim(m.to_vec());
    let mut r = trim(a.to_vec());
    if r.len() < m.len() {
        return (vec![], r);
    }
    let mut q = vec![F::zero(); r.len() - m.len() + 1];
    let lead_inv = m.last().unwrap().inverse().unwrap();
    while r.len() >= m.len() {
        let shift = r.len() - m.len();
        let coef = *r.last().unwrap() * lead_inv;
        q[shift] = coef;
        for (i, mc) in m.iter().enumerate() {
            r[shift + i] -= coef * mc;
        }
        r = trim(r);
    }
    (trim(q), r)
}

