// r1cs gadgets over F_p for R_tok and R_pair, points of E in affine coords

use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::curve::coords;
use crate::field::swu::consts;
use crate::types::{Fp, G0Affine};

type R<T> = Result<T, SynthesisError>;

// named constraint scope so which_is_unsatisfied prints paths like R_pair/element/swu/sign
macro_rules! scope {
    ($name:expr) => {
        tracing::info_span!(target: "r1cs", $name).entered()
    };
}
pub(crate) use scope;

// point of E in projective coords, for the complete formulas
pub type ProjVar = ProjectiveVar<ark_pallas::PallasConfig, FpVar<Fp>>;

#[derive(Clone, Debug)]
pub struct AffineVar {
    pub x: FpVar<Fp>,
    pub y: FpVar<Fp>,
}

impl AffineVar {
    pub fn constant(p: (Fp, Fp)) -> Self {
        AffineVar { x: FpVar::constant(p.0), y: FpVar::constant(p.1) }
    }

    pub fn value(&self) -> R<(Fp, Fp)> {
        Ok((self.x.value()?, self.y.value()?))
    }

    pub fn enforce_equal(&self, other: &AffineVar) -> R<()> {
        self.x.enforce_equal(&other.x)?;
        self.y.enforce_equal(&other.y)
    }

    pub fn to_projective(&self) -> ProjVar {
        ProjVar::new(self.x.clone(), self.y.clone(), FpVar::one())
    }
}

// complete renes-costello-batina addition
pub fn complete_add(p: &ProjVar, q: &ProjVar) -> R<ProjVar> {
    let _s = scope!("complete_add");
    Ok(p + q)
}

// projective p equals affine a, also rejects the identity
pub fn enforce_proj_equals_affine(p: &ProjVar, a: &AffineVar) -> R<()> {
    let _s = scope!("proj_eq_affine");
    a.x.mul_equals(&p.z, &p.x)?;
    a.y.mul_equals(&p.z, &p.y)
}

pub fn enforce_nonzero(a: &FpVar<Fp>) -> R<()> {
    let _s = scope!("nonzero");
    a.inverse().map(|_| ())
}

// returns z = [a == 0] and the inverse hint inv
// when a = 0 inv is free, only use it multiplied by 1 - z
pub fn is_zero(cs: ConstraintSystemRef<Fp>, a: &FpVar<Fp>) -> R<(Boolean<Fp>, FpVar<Fp>)> {
    let _s = scope!("is_zero");
    let z = Boolean::new_witness(cs.clone(), || Ok(a.value()?.is_zero()))?;
    let inv = FpVar::new_witness(cs, || Ok(a.value()?.inverse().unwrap_or(Fp::zero())))?;
    let zf = FpVar::from(z.clone());
    a.mul_equals(&inv, &(FpVar::one() - &zf))?;
    a.mul_equals(&zf, &FpVar::zero())?;
    Ok((z, inv))
}

// p = 2^t + delta, returns (t, delta, k) with k the bit length of delta (126 for pallas)
fn modulus_split() -> (usize, <Fp as PrimeField>::BigInt, usize) {
    let p = Fp::MODULUS;
    let t = Fp::MODULUS_BIT_SIZE as usize - 1;
    let mut delta = p;
    let mut top = <Fp as PrimeField>::BigInt::from(1u64);
    top.muln(t as u32);
    let borrow = delta.sub_with_borrow(&top);
    assert!(!borrow, "p ≥ 2^t");
    let k = delta.num_bits() as usize;
    assert!(k < t, "p = 2^t + δ with δ < 2^(t−1)");
    (t, delta, k)
}

// canonical little-endian bits of a: 255 bools whose value N equals a and N < p
// int_of gives the integer the prover decomposes
pub fn canonical_bits_le_with(
    cs: ConstraintSystemRef<Fp>,
    a: &FpVar<Fp>,
    int_of: impl Fn(Fp) -> <Fp as PrimeField>::BigInt + Copy,
) -> R<Vec<Boolean<Fp>>> {
    let (t, delta, k) = modulus_split();
    let n = t + 1;
    let bits = (0..n)
        .map(|i| Boolean::new_witness(cs.clone(), || Ok(int_of(a.value()?).get_bit(i))))
        .collect::<R<Vec<_>>>()?;
    let mut pow2 = Fp::one();
    let mut packed = FpVar::<Fp>::zero();
    for bit in &bits {
        packed += FpVar::from(bit.clone()) * pow2;
        pow2.double_in_place();
    }
    packed.enforce_equal(a)?;
    let _c = scope!("canonical");
    let top = FpVar::from(bits[t].clone());
    let mut hi = FpVar::<Fp>::zero();
    let mut pow2 = Fp::one();
    for bit in &bits[k..t] {
        hi += FpVar::from(bit.clone()) * pow2;
        pow2.double_in_place();
    }
    top.mul_equals(&hi, &FpVar::zero())?;
    let two_k = Fp::from(2u64).pow([k as u64]);
    let offset = two_k - Fp::from_bigint(delta).expect("δ < p");
    let mut lo = FpVar::<Fp>::zero();
    let mut pow2 = Fp::one();
    for bit in &bits[..k] {
        lo += FpVar::from(bit.clone()) * pow2;
        pow2.double_in_place();
    }
    let shifted_bit = |i: usize| -> R<bool> {
        let nint = int_of(a.value()?);
        let mut lo_int = <Fp as PrimeField>::BigInt::from(0u64);
        for j in (0..k).rev() {
            lo_int.mul2();
            if nint.get_bit(j) {
                lo_int.add_with_carry(&<Fp as PrimeField>::BigInt::from(1u64));
            }
        }
        if nint.get_bit(t) {
            let mut two_k_int = <Fp as PrimeField>::BigInt::from(1u64);
            two_k_int.muln(k as u32);
            lo_int.add_with_carry(&two_k_int);
            lo_int.sub_with_borrow(&delta);
        }
        Ok(lo_int.get_bit(i))
    };
    let c_bits = (0..k).map(|i| Boolean::new_witness(cs.clone(), || shifted_bit(i))).collect::<R<Vec<_>>>()?;
    let mut c_packed = FpVar::<Fp>::zero();
    let mut pow2 = Fp::one();
    for bit in &c_bits {
        c_packed += FpVar::from(bit.clone()) * pow2;
        pow2.double_in_place();
    }
    c_packed.enforce_equal(&(lo + top * offset))?;
    Ok(bits)
}

// canonical bits with the honest representative in [0, p)
pub fn canonical_bits_le(cs: ConstraintSystemRef<Fp>, a: &FpVar<Fp>) -> R<Vec<Boolean<Fp>>> {
    canonical_bits_le_with(cs, a, |v| v.into_bigint())
}

// incomplete affine addition with slope and result allocated as witnesses
pub fn incomplete_add_alloc(cs: ConstraintSystemRef<Fp>, p1: &AffineVar, p2: &AffineVar) -> R<AffineVar> {
    let _s = scope!("incomplete_add");
    let val = || -> R<(Fp, Fp, Fp)> {
        let (x1, y1, x2, y2) = (p1.x.value()?, p1.y.value()?, p2.x.value()?, p2.y.value()?);
        let s = (y2 - y1) * (x2 - x1).inverse().unwrap_or(Fp::zero());
        let x3 = s.square() - x1 - x2;
        Ok((s, x3, s * (x1 - x3) - y1))
    };
    let v = val();
    let s = FpVar::new_witness(cs.clone(), || v.map(|t| t.0))?;
    let x3 = FpVar::new_witness(cs.clone(), || v.map(|t| t.1))?;
    let y3 = FpVar::new_witness(cs, || v.map(|t| t.2))?;
    s.mul_equals(&(&p2.x - &p1.x), &(&p2.y - &p1.y))?;
    s.mul_equals(&s, &(&x3 + &p1.x + &p2.x))?;
    s.mul_equals(&(&p1.x - &x3), &(&y3 + &p1.y))?;
    Ok(AffineVar { x: x3, y: y3 })
}

// 3-bit windows of a 255-bit scalar
pub const WINDOWS: usize = 85;
// windows 1..=83 use the incomplete formula
pub const LAST_INCOMPLETE: usize = 83;

// constants for the windowed fixed-base mult by P
// for window w and k < 8 the table holds (k + 2)*8^w*P as multilinear coeffs in the window bits
// neg_offset cancels the shift by 2*8^w in every window
// window 84 and the offset use complete adds
#[derive(Clone, Debug)]
pub struct WindowTable {
    pub coeff: Vec<[[Fp; 8]; 2]>,
    pub neg_offset: (Fp, Fp),
}

impl WindowTable {
    pub fn new(base: &G0Affine) -> Self {
        use ark_ec::{AffineRepr, CurveGroup, Group};
        let mut pw = base.into_group();
        let mut pts = Vec::with_capacity(WINDOWS * 8);
        for _ in 0..WINDOWS {
            let mut e = pw.double();
            for _ in 0..8 {
                pts.push(e);
                e += pw;
            }
            for _ in 0..3 {
                pw.double_in_place();
            }
        }
        // sequential: a OnceLock initialiser reached from rayon workers must not wait on rayon
        let pts: Vec<G0Affine> = pts.iter().map(|p| p.into_affine()).collect();
        let coeff = pts
            .chunks_exact(8)
            .map(|w| {
                let f: Vec<(Fp, Fp)> = w.iter().map(|p| coords(p).expect("(k+2)·8^w·P ≠ O")).collect();
                [0, 1].map(|c| {
                    // mobius transform over subsets of {b0, b1, b2}
                    let mut a: [Fp; 8] = core::array::from_fn(|k| if c == 0 { f[k].0 } else { f[k].1 });
                    for bit in 0..3 {
                        for sset in 0..8 {
                            if sset & (1 << bit) != 0 {
                                a[sset] -= a[sset ^ (1 << bit)];
                            }
                        }
                    }
                    a
                })
            })
            .collect();
        let mut off = crate::types::Fq0::from(0u64);
        let mut e = crate::types::Fq0::from(2u64);
        for _ in 0..WINDOWS {
            off += e;
            e *= crate::types::Fq0::from(8u64);
        }
        let neg_offset = coords(&(-(*base * off)).into_affine()).expect("offset ≠ O");
        WindowTable { coeff, neg_offset }
    }
}

// sum c_i*v_i as a single lc
pub fn linear_combination(cs: ConstraintSystemRef<Fp>, vars: &[FpVar<Fp>], coeffs: &[Fp]) -> R<FpVar<Fp>> {
    use ark_r1cs_std::fields::fp::AllocatedFp;
    use ark_relations::r1cs::{LinearCombination, Variable};
    let mut lc = LinearCombination::<Fp>::zero();
    let mut constant = Fp::zero();
    let mut value = Some(Fp::zero());
    for (v, k) in vars.iter().zip(coeffs) {
        if k.is_zero() {
            continue;
        }
        match v {
            FpVar::Constant(c) => constant += *c * k,
            FpVar::Var(a) => {
                lc += (*k, a.variable);
                value = value.and_then(|x| a.value().ok().map(|y| x + y * k));
            }
        }
    }
    if lc.0.is_empty() {
        return Ok(FpVar::Constant(constant));
    }
    if !constant.is_zero() {
        lc += (constant, Variable::One);
    }
    let value = value.map(|x| x + constant);
    let var = cs.new_lc(lc)?;
    let value = if cs.is_in_setup_mode() { None } else { value };
    Ok(FpVar::Var(AllocatedFp::new(value, var, cs)))
}

// beta*P_c for three fixed bases at once with 3-bit windows
pub fn windowed_fixed_base_mul3(
    cs: ConstraintSystemRef<Fp>,
    bits_le: &[Boolean<Fp>],
    tables: [&WindowTable; 3],
) -> R<[ProjVar; 3]> {
    let _s = scope!("windowed_fixed_base_mul");
    assert_eq!(bits_le.len(), 3 * WINDOWS);
    let lookup = |mons: &[FpVar<Fp>; 8], c: &[Fp; 8]| -> R<FpVar<Fp>> { linear_combination(cs.clone(), mons, c) };
    let mut acc: [Option<AffineVar>; 3] = [None, None, None];
    let mut out: [Option<ProjVar>; 3] = [None, None, None];
    for w in 0..WINDOWS {
        let b: [FpVar<Fp>; 3] = core::array::from_fn(|i| FpVar::from(bits_le[3 * w + i].clone()));
        let b01 = &b[0] * &b[1];
        let b02 = &b[0] * &b[2];
        let b12 = &b[1] * &b[2];
        let b012 = &b01 * &b[2];
        let mons = [FpVar::one(), b[0].clone(), b[1].clone(), b01, b[2].clone(), b02, b12, b012];
        for c in 0..3 {
            let t = AffineVar { x: lookup(&mons, &tables[c].coeff[w][0])?, y: lookup(&mons, &tables[c].coeff[w][1])? };
            match w {
                0 => acc[c] = Some(t),
                w if w <= LAST_INCOMPLETE => acc[c] = Some(incomplete_add_alloc(cs.clone(), acc[c].as_ref().unwrap(), &t)?),
                _ => {
                    let sum = complete_add(&acc[c].as_ref().unwrap().to_projective(), &t.to_projective())?;
                    let off = AffineVar::constant(tables[c].neg_offset).to_projective();
                    out[c] = Some(complete_add(&sum, &off)?);
                }
            }
        }
    }
    Ok(out.map(|o| o.expect("WINDOWS > LAST_INCOMPLETE + 0")))
}

// phi'(u) on E' and phi(u) on E
pub struct SwuVars {
    pub iso_point: AffineVar,
    pub point: AffineVar,
}

// phi(u) = iso(phi'(u))
// prover gives 1/(t^2 + t), branch bit b and root y
pub fn swu_gadget(cs: ConstraintSystemRef<Fp>, u: &FpVar<Fp>) -> R<SwuVars> {
    swu_gadget_with_hints(cs, u, SwuTamper::default())
}

// dishonest hints, constraints unchanged
#[derive(Clone, Copy, Debug, Default)]
pub struct SwuTamper {
    pub flip_branch: bool,
    // propose -y instead of the root with sgn(y*u~) = 0
    pub flip_sign: bool,
}

// swu_gadget with possibly dishonest hints
pub fn swu_gadget_with_hints(cs: ConstraintSystemRef<Fp>, u: &FpVar<Fp>, tamper: SwuTamper) -> R<SwuVars> {
    let _s = scope!("swu");
    let c = consts();
    let g = scope!("x1_x2");
    let t = u.square()? * c.z;
    // x1 and x2 with the exceptional case
    let w = t.square()? + &t;
    let (w_zero, w_inv) = is_zero(cs.clone(), &w)?;
    let wz = FpVar::from(w_zero.clone());
    let wz_inv = &wz * &w_inv;
    let x1 = (&w_inv + Fp::one()) * c.c1 + &wz * (c.c_exc - c.c1) - &wz_inv * c.c1;
    let x2 = &t * &x1;
    drop(g);
    // branch bit
    let g = scope!("branch");
    let b = Boolean::new_witness(cs.clone(), || {
        let x1v = x1.value()?;
        Ok(crate::field::swu::f_iso(x1v).legendre().is_qr() ^ tamper.flip_branch)
    })?;
    let x = b.select(&x1, &x2)?;
    drop(g);
    // root y with the sign fix
    let g = scope!("on_curve");
    let xx = x.square()?;
    let xxx = &xx * &x;
    let y = FpVar::new_witness(cs.clone(), || {
        let xv = x.value()?;
        let mut yv = crate::field::swu::f_iso(xv).sqrt().ok_or(SynthesisError::Unsatisfiable)?;
        if crate::field::swu::sign_flip(u.value()?, yv) == 1 {
            yv = -yv;
        }
        Ok(if tamper.flip_sign { -yv } else { yv })
    })?;
    y.square()?.enforce_equal(&(&xxx + &x * c.a + c.b))?;
    drop(g);
    // the exceptional case forces b = 1
    let g = scope!("exc_forces_b1");
    FpVar::from(w_zero).mul_equals(&(FpVar::one() - FpVar::from(b.clone())), &FpVar::zero())?;
    drop(g);
    // sign check on y*u~ with u~ = u + e
    let g = scope!("sign");
    let ut = u + &wz;
    let a = &y * &ut;
    enforce_sign_zero(cs.clone(), &a)?;
    let iso_point = AffineVar { x: x.clone(), y: y.clone() };
    drop(g);
    // isogeny E' -> E
    let _g = scope!("isogeny");
    let k = &c.k;
    let nx = &xxx * k[0] + &xx * k[1] + &x * k[2] + k[3];
    let dx = &xx + &x * k[4] + k[5];
    let ny = &xxx * k[6] + &xx * k[7] + &x * k[8] + k[9];
    let dy = &xxx + &xx * k[10] + &x * k[11] + k[12];
    enforce_nonzero(&dx)?;
    enforce_nonzero(&dy)?;
    let px = FpVar::new_witness(cs.clone(), || Ok(nx.value()? * dx.value()?.inverse().unwrap_or(Fp::zero())))?;
    px.mul_equals(&dx, &nx)?;
    let y_ny = &y * &ny;
    let py = FpVar::new_witness(cs, || Ok(y_ny.value()? * dy.value()?.inverse().unwrap_or(Fp::zero())))?;
    py.mul_equals(&dy, &y_ny)?;
    Ok(SwuVars { iso_point, point: AffineVar { x: px, y: py } })
}

// enforce sgn(a) = 0, prover gives 31 bits of i and s
// a = 0 always passes, so callers need a != 0
pub fn enforce_sign_zero(cs: ConstraintSystemRef<Fp>, a: &FpVar<Fp>) -> R<()> {
    let c = crate::field::chi::consts();
    let hint = a.value().ok().map(|v| crate::field::chi::sign_hint(v).unwrap_or((0, Fp::zero())));
    let bits = (0..31)
        .map(|k| Boolean::new_witness(cs.clone(), || hint.map(|(i, _)| (i >> k) & 1 == 1).ok_or(SynthesisError::AssignmentMissing)))
        .collect::<R<Vec<_>>>()?;
    let factor = |k: usize| FpVar::from(bits[k].clone()) * (c.gamma_inv_pow[k] - Fp::one()) + Fp::one();
    let mut g = factor(0);
    for k in 1..31 {
        g = &g * &factor(k);
    }
    let s = FpVar::new_witness(cs, || hint.map(|(_, s)| s).ok_or(SynthesisError::AssignmentMissing))?;
    let mut p = s;
    for _ in 0..32 {
        p = p.square()?;
    }
    a.mul_equals(&g, &p)
}

// one pre-committed hyrax row of width witnesses, the first m carry values
// padding columns are unconstrained
// call before any other witness so row r is at [r*width, (r+1)*width)
pub fn alloc_row(
    cs: ConstraintSystemRef<Fp>,
    values: Option<&[Fp]>,
    m: usize,
    width: usize,
) -> R<Vec<FpVar<Fp>>> {
    assert!(m <= width);
    let _s = scope!("row");
    let mut out = Vec::with_capacity(m);
    for j in 0..width {
        let v = FpVar::new_witness(cs.clone(), || {
            if j < m {
                values.map(|v| v[j]).ok_or(SynthesisError::AssignmentMissing)
            } else {
                Ok(Fp::zero())
            }
        })?;
        if j < m {
            out.push(v);
        }
    }
    Ok(out)
}

// point as two public inputs
pub fn alloc_input_point(cs: ConstraintSystemRef<Fp>, p: (Fp, Fp)) -> R<AffineVar> {
    Ok(AffineVar {
        x: FpVar::new_input(cs.clone(), || Ok(p.0))?,
        y: FpVar::new_input(cs, || Ok(p.1))?,
    })
}

// c0 + sum c_i*v_i as one lc variable, no constraint
pub fn linear(cs: ConstraintSystemRef<Fp>, c0: Fp, terms: &[(Fp, &FpVar<Fp>)]) -> R<FpVar<Fp>> {
    use ark_r1cs_std::fields::fp::AllocatedFp;
    use ark_relations::r1cs::{LinearCombination, Variable};
    let mut constant = c0;
    let mut lc = LinearCombination::<Fp>::zero();
    let mut val = Some(Fp::zero());
    for (c, v) in terms {
        if c.is_zero() {
            continue;
        }
        match v {
            FpVar::Constant(k) => constant += *c * k,
            FpVar::Var(a) => {
                lc += (*c, a.variable);
                val = val.and_then(|x| a.value().ok().map(|y| x + *c * y));
            }
        }
    }
    if !constant.is_zero() {
        lc += (constant, Variable::One);
    }
    let val = val.map(|x| x + constant);
    if cs.is_none() {
        return Ok(FpVar::Constant(val.unwrap_or(constant)));
    }
    let var = cs.new_lc(lc)?;
    Ok(FpVar::Var(AllocatedFp::new(val, var, cs)))
}

// horner evaluation of the blocks at x from the top block down; the last output is target if given
pub fn horner_gadget(cs: ConstraintSystemRef<Fp>, blocks: &[FpVar<Fp>], x: &FpVar<Fp>, target: Option<&FpVar<Fp>>) -> R<FpVar<Fp>> {
    let n = blocks.len();
    assert!(n >= 1);
    let mut acc = blocks[n - 1].clone();
    for b in (0..n - 1).rev() {
        let next = match (b, target) {
            (0, Some(t)) => t.clone(),
            _ => FpVar::new_witness(cs.clone(), || Ok(acc.value()? * x.value()? + blocks[b].value()?))?,
        };
        acc.mul_equals(x, &(&next - &blocks[b]))?;
        acc = next;
    }
    if let (1, Some(t)) = (n, target) {
        acc.enforce_equal(t)?;
        acc = t.clone();
    }
    Ok(acc)
}
