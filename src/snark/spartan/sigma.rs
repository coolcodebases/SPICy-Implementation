// pedersen commitments in G_cyc and the hyrax sigma protocols spartan uses (dot product, equality, product), fiat-shamir

use std::sync::{Arc, OnceLock};

use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use ark_std::UniformRand;

use super::mle::inner;
use crate::params::{g_cyc_scalar, CycGens};
use crate::transcript::Transcript;
use crate::types::{Fp, GcycAffine, GcycProjective};

// vector gens G^(1..n), H (shared with the registration rows) and scalar gen G_s
#[derive(Clone, Debug)]
pub struct Gens {
    pub vec: CycGens,
    pub gs: GcycAffine,
    // lazily built Precomp for vec.g
    pre: Arc<OnceLock<Precomp>>,
}

// precomputed pts[i*K + k] = 2^(c*k)*G^(i), so a commitment is one bucket pass over c-bit digits
// same result as msm_unchecked, variable time in v like the arkworks msm
#[derive(Debug)]
struct Precomp {
    c: usize,
    k: usize,
    pts: Vec<GcycAffine>,
}

// batch normalise with one inversion, no rayon
fn serial_normalize(v: &[GcycProjective]) -> Vec<GcycAffine> {
    use ark_ff::Field;
    let mut zs: Vec<_> = v.iter().map(|p| p.z).collect();
    crate::batch_affine::batch_invert_serial(&mut zs);
    v.iter()
        .zip(zs)
        .map(|(p, zi)| {
            if p.is_zero() {
                GcycAffine::zero()
            } else {
                let zi2 = zi.square();
                GcycAffine::new_unchecked(p.x * zi2, p.y * zi2 * zi)
            }
        })
        .collect()
}

// shorter vectors just use the arkworks msm
const PRECOMP_MIN: usize = 64;

impl Precomp {
    fn new(g: &[GcycAffine]) -> Self {
        let bits = Fp::MODULUS_BIT_SIZE as usize;
        let n = g.len().max(1);
        // window size c with the lowest cost
        let c = (4..=16).min_by_key(|c| n * bits.div_ceil(*c) + (1usize << (c + 1))).unwrap();
        let k = bits.div_ceil(c);
        // sequential: a OnceLock initialiser reached from rayon workers must not wait on rayon
        let per_gen: Vec<Vec<GcycProjective>> = g.iter().map(|gi| {
            let mut cur = gi.into_group();
            (0..k)
                .map(|_| {
                    let out = cur;
                    for _ in 0..c {
                        cur.double_in_place();
                    }
                    out
                })
                .collect()
        }).collect();
        let proj: Vec<GcycProjective> = per_gen.into_iter().flatten().collect();
        Precomp { c, k, pts: serial_normalize(&proj) }
    }

    fn msm(&self, v: &[Fp]) -> GcycProjective {
        let mask = (1u64 << self.c) - 1;
        let nb = (1usize << self.c) - 1;
        let mut acc = AffineBuckets::new(nb);
        for (i, vi) in v.iter().enumerate() {
            if vi.is_zero() {
                continue;
            }
            let b = vi.into_bigint();
            for k in 0..self.k {
                let (bit, limb) = (k * self.c % 64, k * self.c / 64);
                let mut d = b.0[limb] >> bit;
                if bit + self.c > 64 && limb + 1 < 4 {
                    d |= b.0[limb + 1] << (64 - bit);
                }
                let d = (d & mask) as usize;
                if d != 0 {
                    acc.add(d - 1, &self.pts[i * self.k + k]);
                }
            }
        }
        let buckets = acc.finish();
        let (mut run, mut sum) = (GcycProjective::zero(), GcycProjective::zero());
        for bk in buckets.iter().rev() {
            run += bk;
            sum += run;
        }
        sum
    }
}

type Bf = <GcycAffine as AffineRepr>::BaseField;

// bucket accumulation with batched affine adds (montgomery trick)
// at most one pending add per bucket per flush, extra adds go to a projective side accumulator
// P + P and P - P are handled exactly
struct AffineBuckets {
    aff: Vec<GcycAffine>,
    side: Vec<GcycProjective>,
    pending: Vec<(u32, GcycAffine)>,
    mark: Vec<u32>,
    epoch: u32,
}

const BATCH: usize = 256;

impl AffineBuckets {
    fn new(nb: usize) -> Self {
        AffineBuckets {
            aff: vec![GcycAffine::zero(); nb],
            side: vec![GcycProjective::zero(); nb],
            pending: Vec::with_capacity(BATCH),
            mark: vec![0; nb],
            epoch: 1,
        }
    }

    fn add(&mut self, b: usize, p: &GcycAffine) {
        if self.mark[b] == self.epoch {
            self.side[b] += p;
        } else if self.aff[b].is_zero() {
            self.aff[b] = *p;
        } else {
            self.mark[b] = self.epoch;
            self.pending.push((b as u32, *p));
            if self.pending.len() == BATCH {
                self.flush();
            }
        }
    }

    fn flush(&mut self) {
        use ark_ff::Field;
        let mut den: Vec<Bf> = Vec::with_capacity(self.pending.len());
        for (b, p) in &self.pending {
            let q = &self.aff[*b as usize];
            den.push(if q.x != p.x { p.x - q.x } else if q.y == p.y { q.y.double() } else { Bf::zero() });
        }
        // serial: already inside the parallel loop over hyrax rows
        crate::batch_affine::batch_invert_serial(&mut den);
        for ((b, p), inv) in self.pending.iter().zip(den) {
            let q = &mut self.aff[*b as usize];
            if q.x == p.x && q.y != p.y {
                *q = GcycAffine::zero();
                continue;
            }
            let num = if q.x != p.x { p.y - q.y } else { q.x.square() * Bf::from(3u64) };
            let l = num * inv;
            let x3 = l.square() - q.x - p.x;
            let y3 = l * (q.x - x3) - q.y;
            *q = GcycAffine::new_unchecked(x3, y3);
        }
        self.pending.clear();
        self.epoch += 1;
    }

    fn finish(mut self) -> Vec<GcycProjective> {
        self.flush();
        self.side.iter().zip(&self.aff).map(|(s, a)| *s + a).collect()
    }
}

impl Gens {
    pub fn new(n: usize) -> Self {
        Gens { vec: CycGens::derive(n), gs: g_cyc_scalar(), pre: Arc::new(OnceLock::new()) }
    }

    // process-wide cached gens of length n
    pub fn cached(n: usize) -> std::sync::Arc<Gens> {
        use std::collections::HashMap;
        use std::sync::Mutex;
        static C: OnceLock<Mutex<HashMap<usize, Arc<Gens>>>> = OnceLock::new();
        let m = C.get_or_init(|| Mutex::new(HashMap::new()));
        if let Some(g) = m.lock().expect("gens cache").get(&n) {
            return g.clone();
        }
        let g = Arc::new(Gens::new(n));
        m.lock().expect("gens cache").insert(n, g.clone());
        g
    }

    pub fn commit_vec(&self, v: &[Fp], r: Fp) -> GcycProjective {
        assert!(v.len() <= self.vec.g.len());
        let sum = if v.len() < PRECOMP_MIN {
            GcycProjective::msm_unchecked(&self.vec.g[..v.len()], v)
        } else {
            self.pre.get_or_init(|| Precomp::new(&self.vec.g)).msm(v)
        };
        sum + self.vec.h * r
    }

    pub fn commit_scalar(&self, v: Fp, r: Fp) -> GcycProjective {
        self.gs * v + self.vec.h * r
    }
}

// proof of dot product: Cx = Com(x; rx), Cy = Com(y; ry), <a, x> = y

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DotProductProof {
    pub delta: GcycAffine,
    pub beta: GcycAffine,
    pub z: Vec<Fp>,
    pub z_delta: Fp,
    pub z_beta: Fp,
}

impl DotProductProof {
    #[allow(clippy::too_many_arguments)]
    pub fn prove<R: RngCore>(
        t: &mut Transcript,
        gens: &Gens,
        x: &[Fp],
        rx: Fp,
        a: &[Fp],
        ry: Fp,
        cx: &GcycAffine,
        cy: &GcycAffine,
        rng: &mut R,
    ) -> Self {
        let d: Vec<Fp> = (0..x.len()).map(|_| Fp::rand(rng)).collect();
        let (r_delta, r_beta) = (Fp::rand(rng), Fp::rand(rng));
        let delta = gens.commit_vec(&d, r_delta).into_affine();
        let beta = gens.commit_scalar(inner(a, &d), r_beta).into_affine();
        t.append(b"dp/cx", cx);
        t.append(b"dp/cy", cy);
        t.append(b"dp/a", &a.to_vec());
        t.append(b"dp/delta", &delta);
        t.append(b"dp/beta", &beta);
        let c: Fp = t.challenge_scalar(b"dp/c");
        let z = x.iter().zip(&d).map(|(xi, di)| c * xi + di).collect();
        DotProductProof { delta, beta, z, z_delta: c * rx + r_delta, z_beta: c * ry + r_beta }
    }

    pub fn verify(&self, t: &mut Transcript, gens: &Gens, a: &[Fp], cx: &GcycAffine, cy: &GcycAffine) -> bool {
        self.verify_transcript(t, gens, a, cx, cy).is_some_and(|c| self.check(gens, a, cx, cy, c))
    }

    // transcript part of verify, split from check so sumcheck can run the checks in parallel
    pub fn verify_transcript(&self, t: &mut Transcript, gens: &Gens, a: &[Fp], cx: &GcycAffine, cy: &GcycAffine) -> Option<Fp> {
        if self.z.len() != a.len() || a.len() > gens.vec.g.len() {
            return None;
        }
        t.append(b"dp/cx", cx);
        t.append(b"dp/cy", cy);
        t.append(b"dp/a", &a.to_vec());
        t.append(b"dp/delta", &self.delta);
        t.append(b"dp/beta", &self.beta);
        Some(t.challenge_scalar(b"dp/c"))
    }

    // group equations of verify for challenge c
    pub fn check(&self, gens: &Gens, a: &[Fp], cx: &GcycAffine, cy: &GcycAffine, c: Fp) -> bool {
        *cx * c + self.delta == gens.commit_vec(&self.z, self.z_delta)
            && *cy * c + self.beta == gens.commit_scalar(inner(a, &self.z), self.z_beta)
    }
}

// proof of equality: C1 - C2 = (r1 - r2)*H

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct EqualityProof {
    pub alpha: GcycAffine,
    pub z: Fp,
}

impl EqualityProof {
    pub fn prove<R: RngCore>(
        t: &mut Transcript,
        gens: &Gens,
        c1: &GcycAffine,
        r1: Fp,
        c2: &GcycAffine,
        r2: Fp,
        rng: &mut R,
    ) -> Self {
        let k = Fp::rand(rng);
        let alpha = (gens.vec.h * k).into_affine();
        t.append(b"eq/c1", c1);
        t.append(b"eq/c2", c2);
        t.append(b"eq/alpha", &alpha);
        let c: Fp = t.challenge_scalar(b"eq/c");
        EqualityProof { alpha, z: c * (r1 - r2) + k }
    }

    pub fn verify(&self, t: &mut Transcript, gens: &Gens, c1: &GcycAffine, c2: &GcycAffine) -> bool {
        t.append(b"eq/c1", c1);
        t.append(b"eq/c2", c2);
        t.append(b"eq/alpha", &self.alpha);
        let c: Fp = t.challenge_scalar(b"eq/c");
        gens.vec.h * self.z == (GcycProjective::from(*c1) - c2) * c + self.alpha
    }
}

// proof of product: X = Com(x; rx), Y = Com(y; ry), Z = Com(x*y; rz)

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProductProof {
    pub alpha: GcycAffine,
    pub beta: GcycAffine,
    pub delta: GcycAffine,
    pub z: [Fp; 5],
}

impl ProductProof {
    #[allow(clippy::too_many_arguments)]
    pub fn prove<R: RngCore>(
        t: &mut Transcript,
        gens: &Gens,
        (x, rx, cx): (Fp, Fp, &GcycAffine),
        (y, ry, cy): (Fp, Fp, &GcycAffine),
        (rz, cz): (Fp, &GcycAffine),
        rng: &mut R,
    ) -> Self {
        let b: Vec<Fp> = (0..5).map(|_| Fp::rand(rng)).collect();
        let alpha = gens.commit_scalar(b[0], b[1]).into_affine();
        let beta = gens.commit_scalar(b[2], b[3]).into_affine();
        let delta = (*cx * b[2] + gens.vec.h * b[4]).into_affine();
        t.append(b"pp/x", cx);
        t.append(b"pp/y", cy);
        t.append(b"pp/z", cz);
        t.append(b"pp/alpha", &alpha);
        t.append(b"pp/beta", &beta);
        t.append(b"pp/delta", &delta);
        let c: Fp = t.challenge_scalar(b"pp/c");
        let z = [b[0] + c * x, b[1] + c * rx, b[2] + c * y, b[3] + c * ry, b[4] + c * (rz - rx * y)];
        ProductProof { alpha, beta, delta, z }
    }

    pub fn verify(&self, t: &mut Transcript, gens: &Gens, cx: &GcycAffine, cy: &GcycAffine, cz: &GcycAffine) -> bool {
        t.append(b"pp/x", cx);
        t.append(b"pp/y", cy);
        t.append(b"pp/z", cz);
        t.append(b"pp/alpha", &self.alpha);
        t.append(b"pp/beta", &self.beta);
        t.append(b"pp/delta", &self.delta);
        let c: Fp = t.challenge_scalar(b"pp/c");
        let z = &self.z;
        GcycProjective::from(self.alpha) + *cx * c == gens.commit_scalar(z[0], z[1])
            && GcycProjective::from(self.beta) + *cy * c == gens.commit_scalar(z[2], z[3])
            && GcycProjective::from(self.delta) + *cz * c == *cx * z[2] + gens.vec.h * z[4]
    }
}

