// pi_rep: straight-line extractable PoK of (s1, s2) with pk_S = [s1]G0 + [s2]W_R, label id_S
// two-base sigma protocol + fischlin: R = 16 reps, 16-bit challenges, B = 8 zero bits each

use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};
use zeroize::Zeroize;
use sha2::{Digest, Sha512};

use crate::ct;
use crate::error::{Result as SpicyResult, SpicyError};
use crate::oracle::domain;
use crate::serialize::to_bytes;
use crate::types::{Fq0, G0Affine};

// parallel repetitions
pub const REPS: usize = 16;
// zero bits required of each repetition's hash
pub const ZERO_BITS: u32 = 8;
// challenge bits
pub const CHALLENGE_BITS: u32 = 16;

// R commitments, challenges and responses
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RepProof {
    pub a: Vec<G0Affine>,
    pub c: Vec<u16>,
    pub z1: Vec<Fq0>,
    pub z2: Vec<Fq0>,
}

fn enc_scalar(x: &Fq0) -> [u8; 32] {
    x.into_bigint().to_bytes_le().try_into().expect("32-byte scalar")
}

// sha-512 state with the statement and all commitments absorbed
fn prefix(ctx: &[u8; 64], g0: &G0Affine, w: &G0Affine, pk: &G0Affine, a: &[G0Affine]) -> Sha512 {
    let mut h = Sha512::new();
    h.update((domain::REP.len() as u64).to_le_bytes());
    h.update(domain::REP);
    h.update([REPS as u8, ZERO_BITS as u8, CHALLENGE_BITS as u8]);
    h.update(ctx);
    for p in [g0, w, pk] {
        h.update(to_bytes(p));
    }
    for p in a {
        h.update(to_bytes(p));
    }
    // compress the prefix to one block
    let digest: [u8; 64] = h.finalize().into();
    let mut h = Sha512::new();
    h.update(digest);
    h
}

// does H(prefix, i, c, z1, z2) start with ZERO_BITS zero bits?
fn good(prefix: &Sha512, i: usize, c: u16, z1: &Fq0, z2: &Fq0) -> bool {
    let mut h = prefix.clone();
    h.update((i as u16).to_le_bytes());
    h.update(c.to_le_bytes());
    h.update(enc_scalar(z1));
    h.update(enc_scalar(z2));
    let out = h.finalize();
    leading_zero_bits(&out) >= ZERO_BITS
}

fn leading_zero_bits(out: &[u8]) -> u32 {
    let mut n = 0;
    for b in out {
        if *b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

// hedged nonce (a1, a2) of rep i from witness, statement, context, fresh randomness and i
fn hedged_nonce(ctx: &[u8; 64], w: &G0Affine, pk: &G0Affine, s1: &Fq0, s2: &Fq0, fresh: &[u8; 32], i: usize) -> (Fq0, Fq0) {
    let mut h = Sha512::new();
    h.update((domain::REP_NONCE.len() as u64).to_le_bytes());
    h.update(domain::REP_NONCE);
    h.update(enc_scalar(s1));
    h.update(enc_scalar(s2));
    h.update(ctx);
    h.update(to_bytes(w));
    h.update(to_bytes(pk));
    h.update(fresh);
    h.update((i as u64).to_le_bytes());
    let out = h.finalize();
    (Fq0::from_le_bytes_mod_order(&out[..32]), Fq0::from_le_bytes_mod_order(&out[32..]))
}

// PoK of (s1, s2) with pk = [s1]g0 + [s2]w for context ctx
pub fn prove<R: RngCore + CryptoRng>(
    ctx: &[u8; 64],
    g0: &G0Affine,
    w: &G0Affine,
    pk: &G0Affine,
    s1: &Fq0,
    s2: &Fq0,
    rng: &mut R,
) -> SpicyResult<RepProof> {
    let mut fresh = [0u8; 32];
    rng.fill_bytes(&mut fresh);
    let mut nonces: Vec<(Fq0, Fq0)> = (0..REPS).map(|i| hedged_nonce(ctx, w, pk, s1, s2, &fresh, i)).collect();
    fresh.zeroize();
    let a: Vec<G0Affine> = {
        let pts: Vec<_> = crate::par::map(&nonces, |(a1, a2)| ct::mul(g0, a1) + ct::mul(w, a2));
        ark_pallas::Projective::normalize_batch(&pts)
    };
    let pre = prefix(ctx, g0, w, pk, &a);
    let found: Vec<Option<(u16, Fq0, Fq0)>> = crate::par::map_range(REPS, |i| {
        let (mut z1, mut z2) = nonces[i];
        for c in 0..=u16::MAX {
            if good(&pre, i, c, &z1, &z2) {
                return Some((c, z1, z2));
            }
            z1 += s1;
            z2 += s2;
        }
        None
    });
    for (a1, a2) in nonces.iter_mut() {
        a1.zeroize();
        a2.zeroize();
    }
    let mut proof = RepProof { a, c: Vec::with_capacity(REPS), z1: Vec::with_capacity(REPS), z2: Vec::with_capacity(REPS) };
    for f in found {
        let (c, z1, z2) = f.ok_or(SpicyError::SamplingFailed)?;
        proof.c.push(c);
        proof.z1.push(z1);
        proof.z2.push(z2);
    }
    Ok(proof)
}

// verify pi_rep for (ctx, w, pk)
pub fn verify(ctx: &[u8; 64], g0: &G0Affine, w: &G0Affine, pk: &G0Affine, proof: &RepProof) -> bool {
    if proof.a.len() != REPS || proof.c.len() != REPS || proof.z1.len() != REPS || proof.z2.len() != REPS {
        return false;
    }
    if proof.a.iter().any(|p| !p.is_on_curve()) {
        return false;
    }
    let pre = prefix(ctx, g0, w, pk, &proof.a);
    let ok: Vec<bool> = crate::par::map_range(REPS, |i| {
        let (c, z1, z2) = (proof.c[i], &proof.z1[i], &proof.z2[i]);
        good(&pre, i, c, z1, z2)
            && (*g0 * z1 + *w * z2 - proof.a[i] - *pk * Fq0::from(c as u64)).is_zero()
    });
    ok.into_iter().all(|b| b)
}

