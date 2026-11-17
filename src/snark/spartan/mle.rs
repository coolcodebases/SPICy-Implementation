// multilinear extensions over F_p, the first variable selects the upper half

use ark_ff::Zero;
use ark_ff::{Field, One};

use crate::types::Fp;

// eq(r, x) for all x in {0,1}^k, index sum x_i 2^(k-1-i)
pub fn eq_table(r: &[Fp]) -> Vec<Fp> {
    let mut t = vec![Fp::one()];
    for ri in r {
        let mut next = vec![Fp::zero(); t.len() * 2];
        let body = |(v, out): (&Fp, &mut [Fp])| {
            let hi = *v * ri;
            out[0] = *v - hi;
            out[1] = hi;
        };
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            t.par_iter().zip(next.par_chunks_mut(2)).with_min_len(1 << 12).for_each(body);
        }
        #[cfg(not(feature = "parallel"))]
        t.iter().zip(next.chunks_mut(2)).for_each(body);
        t = next;
    }
    t
}

// eq(a, b) at two points
pub fn eq_eval(a: &[Fp], b: &[Fp]) -> Fp {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b)
        .map(|(x, y)| *x * y + (Fp::one() - x) * (Fp::one() - y))
        .product()
}

// v~(r) for |v| <= 2^|r|, missing entries are 0
pub fn mle_eval(v: &[Fp], r: &[Fp]) -> Fp {
    let t = eq_table(r);
    assert!(v.len() <= t.len());
    v.iter().zip(&t).map(|(a, b)| *a * b).sum()
}

// bind the first variable to r
pub fn fold(v: &mut Vec<Fp>, r: Fp) {
    let half = v.len() / 2;
    let (lo, hi) = v.split_at_mut(half);
    let body = |(l, h): (&mut Fp, &Fp)| *l += r * (*h - *l);
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        lo.par_iter_mut().zip(hi.par_iter()).with_min_len(1 << 12).for_each(body);
    }
    #[cfg(not(feature = "parallel"))]
    lo.iter_mut().zip(hi.iter()).for_each(body);
    v.truncate(half);
}

// parallel sum of f(i) over i < n, f returns a fixed-size array
pub fn sum_arrays<const K: usize>(n: usize, f: impl Fn(usize) -> [Fp; K] + Sync + Send) -> [Fp; K] {
    let add = |mut a: [Fp; K], b: [Fp; K]| {
        for k in 0..K {
            a[k] += b[k];
        }
        a
    };
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        (0..n).into_par_iter().with_min_len(1 << 12).fold(|| [Fp::zero(); K], |acc, i| add(acc, f(i))).reduce(|| [Fp::zero(); K], add)
    }
    #[cfg(not(feature = "parallel"))]
    (0..n).fold([Fp::zero(); K], |acc, i| add(acc, f(i)))
}

pub fn log2(n: usize) -> usize {
    assert!(n.is_power_of_two());
    n.trailing_zeros() as usize
}

pub fn powers(r: Fp, n: usize) -> Vec<Fp> {
    let mut out = Vec::with_capacity(n);
    let mut acc = Fp::one();
    for _ in 0..n {
        out.push(acc);
        acc *= r;
    }
    out
}

pub fn inner(a: &[Fp], b: &[Fp]) -> Fp {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(x, y)| *x * y).sum()
}

#[allow(dead_code)]
pub fn square(x: Fp) -> Fp {
    x.square()
}

