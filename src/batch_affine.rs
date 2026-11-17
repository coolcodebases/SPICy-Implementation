// batched affine adds on a = 0 curves (one shared inversion per batch) and fixed-base mult of one base by many scalars
// exceptional cases handled exactly, variable time

use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{Field, PrimeField, Zero};

// add pts[i] to targets[idx[i]] for all i; indices must be distinct
pub fn batch_add<P: SWCurveConfig>(targets: &mut [Affine<P>], idx: &[usize], pts: &[Affine<P>]) {
    assert!(P::COEFF_A.is_zero(), "doubling formula assumes a = 0");
    debug_assert_eq!(idx.len(), pts.len());
    let mut den: Vec<P::BaseField> = Vec::with_capacity(idx.len());
    for (&i, p) in idx.iter().zip(pts) {
        let q = &targets[i];
        den.push(if q.infinity || p.infinity {
            P::BaseField::zero()
        } else if q.x != p.x {
            p.x - q.x
        } else if q.y == p.y {
            q.y.double()
        } else {
            P::BaseField::zero()
        });
    }
    // serial, callers already run this inside parallel loops
    batch_invert_serial(&mut den);
    for ((&i, p), inv) in idx.iter().zip(pts).zip(den) {
        let q = &mut targets[i];
        if p.infinity {
            continue;
        }
        if q.infinity {
            *q = *p;
            continue;
        }
        if q.x == p.x && q.y != p.y {
            *q = Affine::identity();
            continue;
        }
        let num = if q.x != p.x { p.y - q.y } else { q.x.square() * P::BaseField::from(3u64) };
        let l = num * inv;
        let x3 = l.square() - q.x - p.x;
        let y3 = l * (q.x - x3) - q.y;
        *q = Affine::new_unchecked(x3, y3);
    }
}

// c-bit window digits of the scalars, shared by every base
pub struct ScalarDigits {
    c: usize,
    windows: usize,
    n: usize,
    // d[i*windows + w] is digit w of scalar i
    d: Vec<u16>,
}

impl ScalarDigits {
    pub fn new<F: PrimeField>(scalars: &[F]) -> Self {
        let bits = F::MODULUS_BIT_SIZE as usize;
        let n = scalars.len();
        // pick c minimising table construction plus accumulation cost
        let c = (2..=12usize)
            .min_by_key(|c| {
                let w = bits.div_ceil(*c);
                22 * ((1usize << c) - 1) * w + 13 * n.max(1) * w
            })
            .unwrap();
        let windows = bits.div_ceil(c);
        let mut d = Vec::with_capacity(n * windows);
        for k in scalars {
            let b = k.into_bigint();
            let limbs = b.as_ref();
            for w in 0..windows {
                let (bit, limb) = (w * c % 64, w * c / 64);
                let mut x = limbs[limb] >> bit;
                if bit + c > 64 && limb + 1 < limbs.len() {
                    x |= limbs[limb + 1] << (64 - bit);
                }
                d.push((x & ((1u64 << c) - 1)) as u16);
            }
        }
        ScalarDigits { c, windows, n, d }
    }
}

// [k_i]B for all i from a window table, adding [d * 2^(cw)]B to every accumulator per window
pub fn fixed_base_many_with<P: SWCurveConfig>(base: &Affine<P>, sd: &ScalarDigits) -> Vec<Affine<P>> {
    let (c, windows) = (sd.c, sd.windows);
    let per = (1usize << c) - 1;
    // table[w*(2^c - 1) + d - 1] = [d * 2^(cw)]B
    let mut proj: Vec<Projective<P>> = Vec::with_capacity(windows * per);
    let mut g = base.into_group();
    for _ in 0..windows {
        let mut acc = g;
        for _ in 0..per {
            proj.push(acc);
            acc += g;
        }
        g = acc;  // [2^c]g
    }
    let table = normalize_serial(&proj);
    let mut acc = vec![Affine::<P>::identity(); sd.n];
    let (mut idx, mut pts) = (Vec::with_capacity(sd.n), Vec::with_capacity(sd.n));
    for w in 0..windows {
        idx.clear();
        pts.clear();
        for i in 0..sd.n {
            let d = sd.d[i * windows + w] as usize;
            if d != 0 {
                idx.push(i);
                pts.push(table[w * per + d - 1]);
            }
        }
        batch_add(&mut acc, &idx, &pts);
    }
    acc
}

pub fn fixed_base_many<P: SWCurveConfig>(base: &Affine<P>, scalars: &[P::ScalarField]) -> Vec<Affine<P>> {
    fixed_base_many_with(base, &ScalarDigits::new(scalars))
}

// signed c-bit digits, |d| at most 2^(c-1), stored window-major
pub struct SignedDigits {
    c: usize,
    windows: usize,
    n: usize,
    d: Vec<i16>,
}

impl SignedDigits {
    pub fn new<F: PrimeField>(scalars: &[F]) -> Self {
        let bits = F::MODULUS_BIT_SIZE as usize;
        let n = scalars.len().max(1);
        // pick c minimising table construction plus accumulation cost
        let c = (2..=13usize).min_by_key(|c| (bits + 1).div_ceil(*c) * (11 * (1usize << (c - 1)) + 13 * n / 2)).unwrap();
        Self::with_width(scalars, c)
    }

    pub fn with_width<F: PrimeField>(scalars: &[F], c: usize) -> Self {
        assert!((2..=15).contains(&c));
        let bits = F::MODULUS_BIT_SIZE as usize;
        // one more bit than the scalar for the final carry
        let windows = (bits + 1).div_ceil(c);
        let n = scalars.len();
        let half = 1i64 << (c - 1);
        let mut d = vec![0i16; windows * n];
        for (i, k) in scalars.iter().enumerate() {
            let b = k.into_bigint();
            let limbs = b.as_ref();
            let mut carry = 0i64;
            for w in 0..windows {
                let (bit, limb) = (w * c % 64, w * c / 64);
                let mut x = if limb < limbs.len() { limbs[limb] >> bit } else { 0 };
                if bit + c > 64 && limb + 1 < limbs.len() {
                    x |= limbs[limb + 1] << (64 - bit);
                }
                let mut v = (x & ((1u64 << c) - 1)) as i64 + carry;
                carry = 0;
                if v > half {
                    v -= 1 << c;
                    carry = 1;
                }
                d[w * n + i] = v as i16;
            }
            debug_assert_eq!(carry, 0, "the extra bit absorbs the last carry");
        }
        SignedDigits { c, windows, n, d }
    }
}

// serial montgomery batch inversion, zeros stay zero
pub fn batch_invert_serial<F: Field>(v: &mut [F]) {
    let mut pre = Vec::with_capacity(v.len());
    let mut acc = F::one();
    for x in v.iter() {
        pre.push(acc);
        if !x.is_zero() {
            acc *= x;
        }
    }
    let mut inv = acc.inverse().expect("product of non-zero elements");
    for (x, p) in v.iter_mut().zip(pre).rev() {
        if !x.is_zero() {
            let xi = inv * p;
            inv *= *x;
            *x = xi;
        }
    }
}

// batch normalisation with one serial inversion
pub fn normalize_serial<P: SWCurveConfig>(v: &[Projective<P>]) -> Vec<Affine<P>> {
    let mut zs: Vec<P::BaseField> = v.iter().map(|p| p.z).collect();
    batch_invert_serial(&mut zs);
    v.iter()
        .zip(zs)
        .map(|(p, zi)| {
            if p.z.is_zero() {
                Affine::identity()
            } else {
                let zi2 = zi.square();
                Affine::new_unchecked(p.x * zi2, p.y * zi2 * zi)
            }
        })
        .collect()
}

// batch inversion with a reusable buffer; every entry must be nonzero
fn batch_invert_into<F: Field>(v: &mut [F], scratch: &mut Vec<F>) {
    scratch.clear();
    let mut acc = F::one();
    for x in v.iter() {
        scratch.push(acc);
        acc *= x;
    }
    let mut inv = acc.inverse().expect("non-zero denominators");
    for (x, pre) in v.iter_mut().zip(scratch.iter()).rev() {
        let xi = inv * pre;
        inv *= *x;
        *x = xi;
    }
}

// [k_i]B with signed window digits, one shared inversion per window
// exceptional adds (acc is O or +-the added point) take a separate exact path
pub fn fixed_base_many_signed<P: SWCurveConfig>(base: &Affine<P>, sd: &SignedDigits) -> Vec<Affine<P>> {
    let (c, windows, n) = (sd.c, sd.windows, sd.n);
    let h = 1usize << (c - 1);
    let mut bw: Vec<Projective<P>> = Vec::with_capacity(windows);
    let mut g = base.into_group();
    for _ in 0..windows {
        bw.push(g);
        for _ in 0..c {
            g.double_in_place();
        }
    }
    let bw = normalize_serial(&bw);
    // T[w][d-1] = [d]bw[w], built by repeated batch_add
    let mut table = vec![Affine::<P>::identity(); windows * h];
    let mut col = bw.clone();
    let all: Vec<usize> = (0..windows).collect();
    for d in 0..h {
        for w in 0..windows {
            table[w * h + d] = col[w];
        }
        if d + 1 < h {
            batch_add(&mut col, &all, &bw);
        }
    }
    let pick = |w: usize, d: i16| -> Affine<P> {
        let t = table[w * h + d.unsigned_abs() as usize - 1];
        if d < 0 { -t } else { t }
    };
    let mut acc = vec![Affine::<P>::identity(); n];
    let (mut idx, mut sel, mut den, mut scratch, mut special) =
        (Vec::with_capacity(n), Vec::with_capacity(n), Vec::with_capacity(n), Vec::with_capacity(n), Vec::new());
    for w in 0..windows {
        let dig = &sd.d[w * n..(w + 1) * n];
        idx.clear();
        sel.clear();
        den.clear();
        special.clear();
        for (i, &d) in dig.iter().enumerate() {
            if d == 0 {
                continue;
            }
            let (q, p) = (&acc[i], pick(w, d));
            if q.infinity || q.x == p.x {
                special.push(i);
            } else {
                idx.push(i);
                den.push(p.x - q.x);
                sel.push((p.x, p.y));
            }
        }
        if !den.is_empty() {
            batch_invert_into(&mut den, &mut scratch);
        }
        for ((&i, inv), (px, py)) in idx.iter().zip(&den).zip(&sel) {
            let q = &mut acc[i];
            let l = (*py - q.y) * inv;
            let x3 = l.square() - q.x - px;
            let y3 = l * (q.x - x3) - q.y;
            q.x = x3;
            q.y = y3;
        }
        for &i in &special {
            acc[i] = (acc[i].into_group() + pick(w, dig[i])).into_affine();
        }
    }
    acc
}

