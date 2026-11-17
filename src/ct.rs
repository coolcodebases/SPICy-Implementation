// constant-time helpers: branch-free select, fermat inversion, tonelli-shanks, montgomery ladder

use std::marker::PhantomData;

use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{BigInt, BigInteger, FftField, Field, Fp, FpConfig, One, PrimeField, Zero};

pub type Choice = u64;

pub type F4<P> = Fp<P, 4>;

#[inline]
pub fn is_zero_u64(x: u64) -> Choice {
    ((x | x.wrapping_neg()) >> 63) ^ 1
}

// a == b without branching
#[inline]
pub fn eq<P: FpConfig<4>>(a: &F4<P>, b: &F4<P>) -> Choice {
    let mut acc = 0u64;
    for i in 0..4 {
        acc |= a.0 .0[i] ^ b.0 .0[i];
    }
    is_zero_u64(acc)
}

// a if c = 1, else b
#[inline]
pub fn select<P: FpConfig<4>>(c: Choice, a: &F4<P>, b: &F4<P>) -> F4<P> {
    let mask = 0u64.wrapping_sub(c);
    let mut l = [0u64; 4];
    for (i, li) in l.iter_mut().enumerate() {
        *li = (a.0 .0[i] & mask) | (b.0 .0[i] & !mask);
    }
    Fp(BigInt(l), PhantomData)
}

#[inline]
pub fn cswap<P: FpConfig<4>>(c: Choice, a: &mut F4<P>, b: &mut F4<P>) {
    let (na, nb) = (select(c, b, a), select(c, a, b));
    *a = na;
    *b = nb;
}

// x^e with a fixed schedule; e is public
pub fn pow_fixed<P: FpConfig<4>>(x: &F4<P>, e: &[u64]) -> F4<P> {
    let mut acc = F4::<P>::one();
    for limb in e.iter().rev() {
        for bit in (0..64).rev() {
            acc.square_in_place();
            let t = acc * x;
            acc = select((limb >> bit) & 1, &t, &acc);
        }
    }
    acc
}

fn modulus_minus<P: FpConfig<4>>(k: u64) -> BigInt<4> {
    let mut m = P::MODULUS;
    m.sub_with_borrow(&BigInt::from(k));
    m
}

// fermat inverse, 0 maps to 0
pub fn inv0<P: FpConfig<4>>(x: &F4<P>) -> F4<P> {
    pow_fixed(x, &modulus_minus::<P>(2).0)
}

// 1 iff x is a nonzero square (euler)
pub fn is_square<P: FpConfig<4>>(x: &F4<P>) -> Choice {
    eq(&pow_fixed(x, &F4::<P>::MODULUS_MINUS_ONE_DIV_TWO.0), &F4::<P>::one())
}

// constant-time tonelli-shanks: (z, 1) with z^2 = x if x is a square, else (_, 0)
pub fn sqrt<P: FpConfig<4>>(x: &F4<P>) -> (F4<P>, Choice) {
    let c1 = F4::<P>::TWO_ADICITY as usize;  // 2^c1 exactly divides p - 1
    let c3 = F4::<P>::TRACE_MINUS_ONE_DIV_TWO;  // (c2 - 1)/2 with c2 = (p - 1)/2^c1
    let c5 = F4::<P>::TWO_ADIC_ROOT_OF_UNITY;  // non-residue^c2
    let mut z = pow_fixed(x, &c3.0);
    let mut t = z.square() * x;
    z *= x;
    let mut b = t;
    let mut c = c5;
    for i in (2..=c1).rev() {
        for _ in 1..=(i - 2) {
            b.square_in_place();
        }
        let e = eq(&b, &F4::<P>::one());
        let zt = z * c;
        z = select(e, &z, &zt);
        c.square_in_place();
        let tt = t * c;
        t = select(e, &t, &tt);
        b = t;
    }
    let ok = eq(&z.square(), x);
    (z, ok)
}

// lsb of the canonical representative; the conversion itself is not constant time
pub fn parity<P: FpConfig<4>>(x: &F4<P>) -> Choice {
    x.into_bigint().0[0] & 1
}

fn cswap_point<C: SWCurveConfig>(c: Choice, a: &mut Projective<C>, b: &mut Projective<C>)
where
    C::BaseField: CtField,
{
    C::BaseField::ct_swap(c, &mut a.x, &mut b.x);
    C::BaseField::ct_swap(c, &mut a.y, &mut b.y);
    C::BaseField::ct_swap(c, &mut a.z, &mut b.z);
}

// field types with a constant-time swap
pub trait CtField: Sized {
    fn ct_swap(c: Choice, a: &mut Self, b: &mut Self);
}

impl<P: FpConfig<4>> CtField for F4<P> {
    fn ct_swap(c: Choice, a: &mut Self, b: &mut Self) {
        cswap(c, a, b)
    }
}

// [k]P by a montgomery ladder on k' = k + 2q
pub fn mul<C: SWCurveConfig>(base: &Affine<C>, k: &C::ScalarField) -> Projective<C>
where
    C::BaseField: CtField,
    C::ScalarField: PrimeField<BigInt = BigInt<4>>,
{
    let q = C::ScalarField::MODULUS;
    debug_assert!(q.0[3] >> 62 == 1, "2^254 < q < 2^255");
    let mut kk = k.into_bigint();
    let c1 = kk.add_with_carry(&q);
    let c2 = kk.add_with_carry(&q);
    debug_assert!(!c1 && !c2 && kk.0[3] >> 63 == 1);
    let mut r0: Projective<C> = base.into_group();
    let mut r1 = r0.double();
    for i in (0..255).rev() {
        let bit = (kk.0[i / 64] >> (i % 64)) & 1;
        cswap_point(bit, &mut r0, &mut r1);
        r1 += r0;
        r0.double_in_place();
        cswap_point(bit, &mut r0, &mut r1);
    }
    r0
}

// sum of [k_i]P_i with the ladder, for secret scalars
pub fn msm<C: SWCurveConfig>(bases: &[Affine<C>], scalars: &[C::ScalarField]) -> Projective<C>
where
    C::BaseField: CtField,
    C::ScalarField: PrimeField<BigInt = BigInt<4>>,
{
    assert_eq!(bases.len(), scalars.len());
    bases.iter().zip(scalars).map(|(b, s)| mul(b, s)).fold(Projective::<C>::zero(), |a, b| a + b)
}

// constant-time fixed-base mult, 4-bit windows: table[w][d] = [d*16^w]B + U with U hashed to the curve, and [k]B = sum_w table[w][k_w] - [64]U
// each lookup reads all 16 entries
#[derive(Clone)]
pub struct FixedBase<C: SWCurveConfig> {
    table: Vec<[Affine<C>; 16]>,
}

impl<C: SWCurveConfig> core::fmt::Debug for FixedBase<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FixedBase { .. }")
    }
}

// offset point U of FixedBase
pub fn offset<C: SWCurveConfig>() -> Affine<C>
where
    C::BaseField: PrimeField,
{
    crate::oracle::hash_to_curve::<C>(b"SPICy/ct/fixed-base-offset")
}

impl<C: SWCurveConfig> FixedBase<C>
where
    C::BaseField: CtField + PrimeField,
    C::ScalarField: PrimeField<BigInt = BigInt<4>>,
{
    pub const WINDOWS: usize = 64;

    // B is public
    pub fn new(base: &Affine<C>) -> Self {
        let u: Projective<C> = offset::<C>().into_group();
        let mut flat: Vec<Projective<C>> = Vec::with_capacity(Self::WINDOWS * 16);
        let mut bw: Projective<C> = base.into_group();  // [16^w]B
        for _ in 0..Self::WINDOWS {
            let mut e = u;
            for _ in 0..16 {
                flat.push(e);
                e += bw;
            }
            for _ in 0..4 {
                bw.double_in_place();
            }
        }
        let flat = Projective::<C>::normalize_batch(&flat);
        let table = flat.chunks_exact(16).map(|c| core::array::from_fn(|d| c[d])).collect();
        FixedBase { table }
    }

    fn lookup(&self, w: usize, digit: u64) -> Affine<C> {
        let mut out = self.table[w][0];
        for (d, entry) in self.table[w].iter().enumerate().skip(1) {
            let c = is_zero_u64(d as u64 ^ digit);
            let mut cand = *entry;
            C::BaseField::ct_swap(c, &mut out.x, &mut cand.x);
            C::BaseField::ct_swap(c, &mut out.y, &mut cand.y);
            let mask = 0u8.wrapping_sub(c as u8);
            out.infinity = ((out.infinity as u8 & !mask) | (entry.infinity as u8 & mask)) != 0;
        }
        out
    }

    // [k]B for a secret k
    pub fn mul(&self, k: &C::ScalarField) -> Projective<C> {
        let kk = k.into_bigint();
        let nib = |w: usize| (kk.0[w / 16] >> (4 * (w % 16))) & 0xf;
        let mut acc: Projective<C> = self.lookup(0, nib(0)).into_group();
        for w in 1..Self::WINDOWS {
            acc += self.lookup(w, nib(w));
        }
        acc - offset_correction::<C>()
    }
}

// [64]U
fn offset_correction<C: SWCurveConfig>() -> Projective<C>
where
    C::BaseField: PrimeField,
{
    let mut u: Projective<C> = offset::<C>().into_group();
    for _ in 0..6 {
        u.double_in_place();
    }
    u
}

