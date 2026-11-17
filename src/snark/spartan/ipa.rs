// log-size zk proof of dot product (hyrax with the bulletproofs reduction, like spartan's DotProductProofLog)
// Cx = <x, G> + rx*H, Cy = y*Q + ry*H, public a, <x, a> = y

use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use ark_std::UniformRand;

use super::mle::inner;
use super::sigma::Gens;
use crate::transcript::Transcript;
use crate::types::{Fp, GcycAffine, GcycProjective};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DotProductProofLog {
    pub l_vec: Vec<GcycAffine>,
    pub r_vec: Vec<GcycAffine>,
    pub delta: GcycAffine,
    pub beta: GcycAffine,
    pub z1: Fp,
    pub z2: Fp,
}

fn absorb_statement(t: &mut Transcript, cx: &GcycAffine, cy: &GcycAffine, a: &[Fp]) {
    t.append(b"ipa/cx", cx);
    t.append(b"ipa/cy", cy);
    t.append(b"ipa/a", &a.to_vec());
}

impl DotProductProofLog {
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
        let mut n = x.len();
        assert!(n.is_power_of_two() && a.len() == n && n <= gens.vec.g.len());
        absorb_statement(t, cx, cy, a);
        let (q, h) = (gens.gs, gens.vec.h);
        let mut xs = x.to_vec();
        let mut as_ = a.to_vec();
        let mut gs: Vec<GcycAffine> = gens.vec.g[..n].to_vec();
        let mut blind = rx + ry;
        let (mut l_vec, mut r_vec) = (vec![], vec![]);
        while n > 1 {
            n /= 2;
            let (x_l, x_r) = xs.split_at(n);
            let (a_l, a_r) = as_.split_at(n);
            let (g_l, g_r) = gs.split_at(n);
            let (b_l, b_r) = (Fp::rand(rng), Fp::rand(rng));
            let l = (GcycProjective::msm_unchecked(g_r, x_l) + q * inner(x_l, a_r) + h * b_l).into_affine();
            let r = (GcycProjective::msm_unchecked(g_l, x_r) + q * inner(x_r, a_l) + h * b_r).into_affine();
            t.append(b"ipa/L", &l);
            t.append(b"ipa/R", &r);
            let u: Fp = t.challenge_scalar(b"ipa/u");
            let ui = u.inverse().expect("challenge ≠ 0 w.h.p.");
            let nx: Vec<Fp> = (0..n).map(|i| u * x_l[i] + ui * x_r[i]).collect();
            let na: Vec<Fp> = (0..n).map(|i| ui * a_l[i] + u * a_r[i]).collect();
            let ng: Vec<GcycProjective> = ark_std::cfg_into_iter!(0..n).map(|i| g_l[i] * ui + g_r[i] * u).collect();
            blind += u.square() * b_l + ui.square() * b_r;
            xs = nx;
            as_ = na;
            gs = GcycProjective::normalize_batch(&ng);
            l_vec.push(l);
            r_vec.push(r);
        }
        let (x_hat, a_hat, g_hat) = (xs[0], as_[0], gs[0]);
        let (d, r_delta, r_beta) = (Fp::rand(rng), Fp::rand(rng), Fp::rand(rng));
        let delta = (g_hat * d + h * r_delta).into_affine();
        let beta = (q * d + h * r_beta).into_affine();
        t.append(b"ipa/delta", &delta);
        t.append(b"ipa/beta", &beta);
        let c: Fp = t.challenge_scalar(b"ipa/c");
        DotProductProofLog {
            l_vec,
            r_vec,
            delta,
            beta,
            z1: d + c * x_hat * a_hat,
            z2: a_hat * (c * blind + r_beta) + r_delta,
        }
    }

    pub fn verify(&self, t: &mut Transcript, gens: &Gens, a: &[Fp], cx: &GcycAffine, cy: &GcycAffine) -> bool {
        let n = a.len();
        if !n.is_power_of_two() || n > gens.vec.g.len() {
            return false;
        }
        let lg = n.trailing_zeros() as usize;
        if self.l_vec.len() != lg || self.r_vec.len() != lg {
            return false;
        }
        absorb_statement(t, cx, cy, a);
        let mut us = Vec::with_capacity(lg);
        for j in 0..lg {
            t.append(b"ipa/L", &self.l_vec[j]);
            t.append(b"ipa/R", &self.r_vec[j]);
            us.push(t.challenge_scalar::<Fp>(b"ipa/u"));
        }
        let Some(uis) = us.iter().map(|u| u.inverse()).collect::<Option<Vec<Fp>>>() else {
            return false;
        };
        // folded generator weights s_i
        let s: Vec<Fp> = (0..n)
            .map(|i| (0..lg).map(|j| if (i >> (lg - 1 - j)) & 1 == 1 { us[j] } else { uis[j] }).product())
            .collect();
        let g_hat = GcycProjective::msm_unchecked(&gens.vec.g[..n], &s);
        let a_hat = inner(a, &s);
        let mut scalars: Vec<Fp> = us.iter().map(|u| u.square()).collect();
        scalars.extend(uis.iter().map(|u| u.square()));
        let mut points = self.l_vec.clone();
        points.extend_from_slice(&self.r_vec);
        let gamma_hat = GcycProjective::msm_unchecked(&points, &scalars) + cx + cy;
        t.append(b"ipa/delta", &self.delta);
        t.append(b"ipa/beta", &self.beta);
        let c: Fp = t.challenge_scalar(b"ipa/c");
        (gamma_hat * c + self.beta) * a_hat + self.delta == (g_hat + gens.gs * a_hat) * self.z1 + gens.vec.h * self.z2
    }
}

