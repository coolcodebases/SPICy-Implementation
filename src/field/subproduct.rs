// interpolation by the subproduct tree
// fft multiplication and newton-inversion division, schoolbook on small nodes

use ark_ff::{FftField, Field, PrimeField};
use ark_poly::univariate::DensePolynomial;
use ark_poly::DenseUVPolynomial;

use super::poly::{eval, mul as mul_naive, trim};

const LEAF: usize = 32;
const FFT_MIN: usize = 128;
const PAR_MIN: usize = 512;

pub fn mul<F: FftField>(a: &[F], b: &[F]) -> Vec<F> {
    if a.is_empty() || b.is_empty() {
        return vec![];
    }
    if a.len().min(b.len()) < 16 || a.len() + b.len() < FFT_MIN {
        return mul_naive(a, b);
    }
    let pa = DensePolynomial::from_coefficients_slice(a);
    let pb = DensePolynomial::from_coefficients_slice(b);
    (&pa * &pb).coeffs
}

// 1/a mod X^k by newton iteration, needs a[0] != 0
fn inv_series<F: FftField>(a: &[F], k: usize) -> Vec<F> {
    let mut b = vec![a[0].inverse().expect("a(0) ≠ 0")];
    let mut prec = 1;
    while prec < k {
        prec = (2 * prec).min(k);
        let mut ab = mul(&a[..a.len().min(prec)], &b);
        ab.truncate(prec);
        for c in ab.iter_mut() {
            *c = -*c;
        }
        if ab.is_empty() {
            ab.push(F::zero());
        }
        ab[0] += F::from(2u64);
        let mut nb = mul(&b, &ab);
        nb.truncate(prec);
        b = nb;
    }
    b.resize(k, F::zero());
    b
}

// a mod m, deg m at least 1
pub fn rem<F: FftField>(a: &[F], m: &[F]) -> Vec<F> {
    let a = trim(a.to_vec());
    let m = trim(m.to_vec());
    if a.len() < m.len() {
        return a;
    }
    let (n, dm) = (a.len() - 1, m.len() - 1);
    if n - dm < 32 || dm < 16 {
        return super::poly::rem(&a, &m);
    }
    // quotient from the reversed polynomials
    let k = n - dm + 1;
    let ra: Vec<F> = a.iter().rev().take(k).copied().collect();
    let rm: Vec<F> = m.iter().rev().copied().collect();
    let mut rq = mul(&ra, &inv_series(&rm, k));
    rq.truncate(k);
    rq.resize(k, F::zero());
    let q: Vec<F> = rq.into_iter().rev().collect();
    let qm = mul(&q, &m);
    let mut r: Vec<F> = a[..dm].to_vec();
    for (ri, qi) in r.iter_mut().zip(&qm) {
        *ri -= qi;
    }
    trim(r)
}

fn derivative<F: Field>(a: &[F]) -> Vec<F> {
    a.iter().enumerate().skip(1).map(|(i, c)| *c * F::from(i as u64)).collect()
}

struct Node<F> {
    // product over i in [lo, hi) of (X - x_i)
    m: Vec<F>,
    lo: usize,
    hi: usize,
    kids: Option<Box<(Node<F>, Node<F>)>>,
}

fn build<F: FftField>(xs: &[F], lo: usize, hi: usize) -> Node<F> {
    if hi - lo <= LEAF {
        let mut m = vec![F::one()];
        for x in &xs[lo..hi] {
            m = mul_naive(&m, &[-*x, F::one()]);
        }
        return Node { m, lo, hi, kids: None };
    }
    let mid = (lo + hi) / 2;
    let (l, r) = if hi - lo >= PAR_MIN {
        crate::par::join(|| build(xs, lo, mid), || build(xs, mid, hi))
    } else {
        (build(xs, lo, mid), build(xs, mid, hi))
    };
    let m = mul(&l.m, &r.m);
    Node { m, lo, hi, kids: Some(Box::new((l, r))) }
}

// f(x_i) for i in the node, deg f < deg node.m
fn eval_down<F: FftField>(node: &Node<F>, f: &[F], xs: &[F], out: &mut [F]) {
    match &node.kids {
        None => {
            for (o, x) in out.iter_mut().zip(&xs[node.lo..node.hi]) {
                *o = eval(f, *x);
            }
        }
        Some(kids) => {
            let (l, r) = (&kids.0, &kids.1);
            let (ol, or) = out.split_at_mut(l.hi - l.lo);
            if node.hi - node.lo >= PAR_MIN {
                crate::par::join(
                    || eval_down(l, &rem(f, &l.m), xs, ol),
                    || eval_down(r, &rem(f, &r.m), xs, or),
                );
            } else {
                eval_down(l, &rem(f, &l.m), xs, ol);
                eval_down(r, &rem(f, &r.m), xs, or);
            }
        }
    }
}

// sum over the node of c_i M_node(X)/(X - x_i)
fn combine<F: FftField>(node: &Node<F>, c: &[F], xs: &[F]) -> Vec<F> {
    match &node.kids {
        None => {
            let t = node.hi - node.lo;
            let mut out = vec![F::zero(); t];
            for (ci, xi) in c[node.lo..node.hi].iter().zip(&xs[node.lo..node.hi]) {
                let mut carry = F::zero();
                for k in (0..t).rev() {
                    carry = node.m[k + 1] + carry * xi;
                    out[k] += carry * ci;
                }
            }
            out
        }
        Some(kids) => {
            let (l, r) = (&kids.0, &kids.1);
            let (pl, pr) = if node.hi - node.lo >= PAR_MIN {
                crate::par::join(|| mul(&combine(l, c, xs), &r.m), || mul(&combine(r, c, xs), &l.m))
            } else {
                (mul(&combine(l, c, xs), &r.m), mul(&combine(r, c, xs), &l.m))
            };
            let mut out = vec![F::zero(); pl.len().max(pr.len())];
            for (o, v) in out.iter_mut().zip(&pl) {
                *o += v;
            }
            for (o, v) in out.iter_mut().zip(&pr) {
                *o += v;
            }
            out
        }
    }
}

// interpolant of degree < t; caller checks that the x are distinct
pub fn interpolate<F: PrimeField>(points: &[(F, F)]) -> Vec<F> {
    let t = points.len();
    let xs: Vec<F> = points.iter().map(|p| p.0).collect();
    let tree = build(&xs, 0, t);
    let dm = derivative(&tree.m);
    let mut denoms = vec![F::zero(); t];
    eval_down(&tree, &dm, &xs, &mut denoms);
    ark_ff::batch_inversion(&mut denoms);
    let c: Vec<F> = points.iter().zip(&denoms).map(|((_, y), d)| *y * d).collect();
    let mut out = combine(&tree, &c, &xs);
    out.resize(t, F::zero());
    out
}

