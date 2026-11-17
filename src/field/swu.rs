// simplified swu map phi: F_p -> E and its inverse
// pallas has a = 0, so phi runs on the 3-isogenous curve E' and maps over by the isogeny
// constants from pasta_curves
// the root is picked with sgn(y u~) = 0 (u~ = u, or 1 if u = 0), not with rfc 9380 sgn0
// phi^-1: candidates from quadratics in t = Z u^2, checked forward, sorted

use std::sync::OnceLock;

use ark_ec::AffineRepr;
use ark_ff::{BigInt, Field, One, PrimeField, Zero};

use crate::ct;
use crate::field::poly;
use crate::types::{Fp, G0Affine};

// d of SamplePreimage; fibres have at most 5 elements
pub const D_MAX: usize = 6;

pub struct SwuConsts {
    pub a: Fp,
    pub b: Fp,
    pub z: Fp,
    // c1 = -B'/A'
    pub c1: Fp,
    // exceptional abscissa B'/(Z A')
    pub c_exc: Fp,
    // isogeny: x numerator k0..k3, denominator k4, k5; y numerator k6..k9, denominator k10..k12
    pub k: [Fp; 13],
}

fn fp(limbs: [u64; 4]) -> Fp {
    Fp::from_bigint(BigInt::new(limbs)).expect("canonical constant")
}

pub fn consts() -> &'static SwuConsts {
    static C: OnceLock<SwuConsts> = OnceLock::new();
    C.get_or_init(|| {
        let a = fp([0x92bb4b0b657a014b, 0xb74134581a27a59f, 0x49be2d7258370742, 0x18354a2eb0ea8c9c]);
        let b = Fp::from(1265u64);
        let z = -Fp::from(13u64);
        let k = [
            fp([0x775f6034aaaaaaab, 0x4081775473d8375b, 0xe38e38e38e38e38e, 0x0e38e38e38e38e38]),
            fp([0x8cf863b02814fb76, 0x0f93b82ee4b99495, 0x267c7ffa51cf412a, 0x3509afd51872d88e]),
            fp([0x0eb64faef37ea4f7, 0x380af066cfeb6d69, 0x98c7d7ac3d98fd13, 0x17329b9ec5253753]),
            fp([0xeebec06955555580, 0x8102eea8e7b06eb6, 0xc71c71c71c71c71c, 0x1c71c71c71c71c71]),
            fp([0xc47f2ab668bcd71f, 0x9c434ac1c96b6980, 0x5a607fcce0494a79, 0x1d572e7ddc099cff]),
            fp([0x2aa3af1eae5b6604, 0xb4abf9fb9a1fc81c, 0x1d13bf2a7f22b105, 0x325669becaecd5d1]),
            fp([0x5ad985b5e38e38e4, 0x7642b01ad461bad2, 0x4bda12f684bda12f, 0x1a12f684bda12f68]),
            fp([0xc67c31d8140a7dbb, 0x07c9dc17725cca4a, 0x133e3ffd28e7a095, 0x1a84d7ea8c396c47]),
            fp([0x02e2be87d225b234, 0x1765e924f7459378, 0x303216cce1db9ff1, 0x3fb98ff0d2ddcadd]),
            fp([0x93e53ab371c71c4f, 0x0ac03e8e134eb3e4, 0x7b425ed097b425ed, 0x025ed097b425ed09]),
            fp([0x5a28279b1d1b42ae, 0x5941a3a4a97aa1b3, 0x0790bfb3506defb6, 0x0c02c5bcca0e6b7f]),
            fp([0x4d90ab820b12320a, 0xd976bbfabbc5661d, 0x573b3d7f7d681310, 0x17033d3c60c68173]),
            fp([0x992d30ecfffffde5, 0x224698fc094cf91b, 0x0000000000000000, 0x4000000000000000]),
        ];
        let c1 = -b * a.inverse().unwrap();
        let c_exc = b * (z * a).inverse().unwrap();
        SwuConsts { a, b, z, c1, c_exc, k }
    })
}

pub fn f_iso(x: Fp) -> Fp {
    let c = consts();
    x * x * x + c.a * x + c.b
}

pub fn f_e(x: Fp) -> Fp {
    x * x * x + Fp::from(5u64)
}

// sgn0 of rfc 9380
pub fn parity(x: Fp) -> bool {
    x.into_bigint().0[0] & 1 == 1
}

// intermediate values of phi(u); swu_gadget takes its hints from here
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwuTrace {
    pub u: Fp,
    pub t: Fp,
    pub w: Fp,
    // 1/w, or 0 when w = 0
    pub w_inv: Fp,
    pub w_is_zero: bool,
    pub x1: Fp,
    pub x2: Fp,
    // branch bit: x = x1 iff f(x1) is a square
    pub b: bool,
    pub x_iso: Fp,
    pub y_iso: Fp,
    pub x: Fp,
    pub y: Fp,
}

// constant-time phi' on E'
pub fn swu_iso_trace(u: Fp) -> SwuTrace {
    let c = consts();
    let t = c.z * u.square();
    let w = t.square() + t;
    let w_inv = ct::inv0(&w);
    let w_zero = ct::eq(&w, &Fp::zero());
    let x1 = ct::select(w_zero, &c.c_exc, &(c.c1 * (Fp::one() + w_inv)));
    let x2 = t * x1;
    let b = ct::is_square(&f_iso(x1));
    let x_iso = ct::select(b, &x1, &x2);
    let (root, ok) = ct::sqrt(&f_iso(x_iso));
    assert_eq!(ok, 1, "exactly one branch is a square");
    let flip = sign_flip(u, root);
    let y_iso = ct::select(flip, &(-root), &root);
    let (x, y) = iso_map(x_iso, y_iso);
    SwuTrace { u, t, w, w_inv, w_is_zero: w_zero == 1, x1, x2, b: b == 1, x_iso, y_iso, x, y }
}

// whether the root gets negated
pub fn sign_flip(u: Fp, root: Fp) -> ct::Choice {
    let ut = ct::select(ct::eq(&u, &Fp::zero()), &Fp::one(), &u);
    crate::field::chi::sgn(root * ut) as ct::Choice
}

pub fn iso_map(x: Fp, y: Fp) -> (Fp, Fp) {
    let k = &consts().k;
    let x2 = x.square();
    let x3 = x2 * x;
    let nx = k[0] * x3 + k[1] * x2 + k[2] * x + k[3];
    let dx = x2 + k[4] * x + k[5];
    let ny = k[6] * x3 + k[7] * x2 + k[8] * x + k[9];
    let dy = x3 + k[10] * x2 + k[11] * x + k[12];
    // one inversion for both denominators
    let inv = ct::inv0(&(dx * dy));
    (nx * dy * inv, y * ny * dx * inv)
}

// variable-time iso_map
fn iso_map_vt(x: Fp, y: Fp) -> (Fp, Fp) {
    let k = &consts().k;
    let x2 = x.square();
    let x3 = x2 * x;
    let nx = k[0] * x3 + k[1] * x2 + k[2] * x + k[3];
    let dx = x2 + k[4] * x + k[5];
    let ny = k[6] * x3 + k[7] * x2 + k[8] * x + k[9];
    let dy = x3 + k[10] * x2 + k[11] * x + k[12];
    let inv = (dx * dy).inverse().expect("dx, dy vanish only at non-rational kernel abscissae");
    (nx * dy * inv, y * ny * dx * inv)
}

pub fn phi(u: Fp) -> G0Affine {
    let tr = swu_iso_trace(u);
    G0Affine::new_unchecked(tr.x, tr.y)
}

// variable-time phi, used by the receiver's SamplePreimage
pub fn phi_vt(u: Fp) -> G0Affine {
    let (x, y) = swu_iso_vt(u);
    let (x, y) = iso_map_vt(x, y);
    G0Affine::new_unchecked(x, y)
}

// variable-time phi', for phi^-1 and phi_vt
pub fn swu_iso_vt(u: Fp) -> (Fp, Fp) {
    let c = consts();
    let t = c.z * u.square();
    let w = t.square() + t;
    let x1 = match w.inverse() {
        Some(wi) => c.c1 * (Fp::one() + wi),
        None => c.c_exc,
    };
    // f(x1) = 0 takes branch 2, as in swu_iso_trace
    let f1 = f_iso(x1);
    let (x, root, chi_root) = match if f1.is_zero() { None } else { crate::field::chi::sqrt_chi(f1) } {
        Some((r, cr)) => (x1, r, cr),
        None => {
            let x2 = t * x1;
            let (r, cr) = crate::field::chi::sqrt_chi(f_iso(x2)).expect("exactly one branch is a square");
            (x2, r, cr)
        }
    };
    // sign rule
    let chi_u = if u.is_zero() { 0 } else { crate::field::chi::chi_fast(u) };
    let flip = root.is_zero() || (chi_root.wrapping_add(chi_u) >> 31) == 1;
    let y = if flip && !root.is_zero() { -root } else { root };
    (x, y)
}

// phi' with the rfc 9380 sign rule, to cross-check against pasta_curves
pub fn swu_iso_rfc(u: Fp) -> (Fp, Fp) {
    let (x, y) = swu_iso_vt(u);
    (x, if parity(y) != parity(u) { -y } else { y })
}

// phi with the rfc 9380 sign rule
pub fn phi_rfc(u: Fp) -> G0Affine {
    let (x, y) = swu_iso_rfc(u);
    let (x, y) = iso_map(x, y);
    G0Affine::new_unchecked(x, y)
}

// distinct roots of c2 X^2 + c1 X + c0, c2 != 0
fn quadratic_roots(c0: Fp, c1: Fp, c2: Fp) -> Vec<Fp> {
    let disc = c1.square() - (c2 * c0).double().double();
    let Some((r, _)) = crate::field::chi::sqrt_chi(disc) else { return vec![] };
    let inv = (c2.double()).inverse().expect("c2 ≠ 0");
    let (a, b) = ((-c1 + r) * inv, (-c1 - r) * inv);
    if a == b {
        vec![a]
    } else {
        vec![a, b]
    }
}

// a^2 mod (X^3 + m2 X^2 + m1 X + m0)
fn sqrmod3(a: &[Fp; 3], m: &[Fp; 3]) -> [Fp; 3] {
    let (a0, a1, a2) = (a[0], a[1], a[2]);
    let p0 = a0.square();
    let p1 = (a0 * a1).double();
    let p2 = (a0 * a2).double() + a1.square();
    let p3 = (a1 * a2).double();
    let p4 = a2.square();
    let (mut q2, mut q1, q0) = (p2 - p4 * m[1], p1 - p4 * m[0], p0);
    let q3 = p3 - p4 * m[2];
    q2 -= q3 * m[2];
    q1 -= q3 * m[1];
    [q0 - q3 * m[0], q1, q2]
}

// a X mod (X^3 + m2 X^2 + m1 X + m0)
fn mulxmod3(a: &[Fp; 3], m: &[Fp; 3]) -> [Fp; 3] {
    let c = a[2];
    [-(c * m[0]), a[0] - c * m[1], a[1] - c * m[2]]
}

// distinct roots of a cubic via gcd(f, X^p - X); three rational roots fall back to poly::roots
fn cubic_roots(c: [Fp; 4]) -> Vec<Fp> {
    let inv = c[3].inverse().expect("cubic");
    let m = [c[0] * inv, c[1] * inv, c[2] * inv];
    let mut acc = [Fp::one(), Fp::zero(), Fp::zero()];
    for limb in Fp::MODULUS.0.iter().rev() {
        for bit in (0..64).rev() {
            acc = sqrmod3(&acc, &m);
            if (limb >> bit) & 1 == 1 {
                acc = mulxmod3(&acc, &m);
            }
        }
    }
    let r = [acc[0], acc[1] - Fp::one(), acc[2]];
    let f = [m[0], m[1], m[2], Fp::one()];
    let g = poly::monic(poly::gcd(&f, &poly::trim(r.to_vec())));
    let mut out = match g.len() {
        2 => vec![-g[0]],
        3 => quadratic_roots(g[0], g[1], g[2]),
        4 => poly::roots(&g),
        _ => vec![],
    };
    out.sort_by_key(|r| r.into_bigint());
    out
}

// the isogeny preimage of P (there is exactly one)
pub fn iso_map_inverse(p: &G0Affine) -> Vec<(Fp, Fp)> {
    let Some((x, y)) = p.xy().map(|(x, y)| (*x, *y)) else { return vec![] };
    let k = &consts().k;
    // abscissae on E' that map to x
    let cubic = [k[3] - x * k[5], k[2] - x * k[4], k[1] - x, k[0]];
    let mut out = vec![];
    for xp in cubic_roots(cubic) {
        let x2 = xp.square();
        let x3 = x2 * xp;
        let dx = x2 + k[4] * xp + k[5];
        let ny = k[6] * x3 + k[7] * x2 + k[8] * xp + k[9];
        let dy = x3 + k[10] * x2 + k[11] * xp + k[12];
        if dx.is_zero() || ny.is_zero() {
            continue;
        }
        let yp = y * dy * ny.inverse().unwrap();
        if yp.square() == f_iso(xp) {
            let (ix, iy) = (
                (k[0] * x3 + k[1] * x2 + k[2] * xp + k[3]) * dx.inverse().unwrap(),
                yp * ny * dy.inverse().unwrap(),
            );
            if (ix, iy) == (x, y) {
                out.push((xp, yp));
            }
        }
    }
    out
}

// all u with phi'(u) = (x, y), increasing
pub fn swu_iso_inverse(x: Fp, y: Fp) -> Vec<Fp> {
    swu_iso_inverse_with(x, y, swu_iso_vt)
}

// all u with forward(u) = (x, y), for phi' under either sign rule
fn swu_iso_inverse_with(x: Fp, y: Fp, forward: fn(Fp) -> (Fp, Fp)) -> Vec<Fp> {
    let c = consts();
    let mut ts: Vec<Fp> = vec![Fp::zero(), -Fp::one()];  // t^2 + t = 0
    // branch 1: solve t^2 + t = w
    let inv_w = -c.a * x * c.b.inverse().unwrap() - Fp::one();
    if let Some(w) = inv_w.inverse() {
        ts.extend(quadratic_roots(-w, Fp::one(), Fp::one()));
    }
    // branch 2: x = t x1
    ts.extend(quadratic_roots(c.c1 - x, c.c1 - x, c.c1));
    let z_inv = c.z.inverse().unwrap();
    let mut us = vec![];
    for t in ts {
        if let Some((r, _)) = crate::field::chi::sqrt_chi(t * z_inv) {
            // one evaluation decides both r and -r
            let (fx, fy) = forward(r);
            if fx == x {
                if fy == y {
                    us.push(r);
                } else if fy == -y && !r.is_zero() {
                    us.push(-r);
                }
            }
        }
    }
    us.sort_by_key(|u| u.into_bigint());
    us.dedup();
    us
}

// phi^-1(P), increasing
pub fn phi_inverse(p: &G0Affine) -> Vec<Fp> {
    let mut us: Vec<Fp> = iso_map_inverse(p)
        .into_iter()
        .flat_map(|(xp, yp)| swu_iso_inverse(xp, yp))
        .collect();
    us.sort_by_key(|u| u.into_bigint());
    us.dedup();
    us
}

