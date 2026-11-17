// batched grand products via layered circuits and sum-check, as in spark; not zk (public data)
// each layer is reduced by a degree-3 sum-check, ending at one common leaf point

use ark_ff::{Field, One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::mle::{eq_eval, eq_table, fold};
use crate::transcript::Transcript;
use crate::types::Fp;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct LayerProof {
    // round polys as values at 0, 1, 2, 3
    pub polys: Vec<[Fp; 4]>,
    pub v0: Vec<Fp>,
    pub v1: Vec<Fp>,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct BatchedProductProof {
    pub products: Vec<Fp>,
    pub layers: Vec<LayerProof>,
}

// g(r) for the cubic with g(0..=3) = e
pub fn eval_cubic(e: &[Fp; 4], r: Fp) -> Fp {
    let pts = [Fp::zero(), Fp::one(), Fp::from(2u64), Fp::from(3u64)];
    let mut acc = Fp::zero();
    for i in 0..4 {
        let mut num = Fp::one();
        let mut den = Fp::one();
        for j in 0..4 {
            if i != j {
                num *= r - pts[j];
                den *= pts[i] - pts[j];
            }
        }
        acc += e[i] * num * den.inverse().expect("distinct points");
    }
    acc
}

// prove products of leaves (equal power-of-two lengths), returns (proof, leaf point, leaf claims)
pub fn prove(t: &mut Transcript, leaves: &[Vec<Fp>]) -> (BatchedProductProof, Vec<Fp>, Vec<Fp>) {
    let k = leaves.len();
    let n = leaves[0].len();
    assert!(n.is_power_of_two() && leaves.iter().all(|l| l.len() == n));
    let ell = n.trailing_zeros() as usize;
    // layers[c][j] for j = 0..=l
    let layers: Vec<Vec<Vec<Fp>>> = leaves
        .iter()
        .map(|leaf| {
            let mut ls = vec![leaf.clone()];
            while ls.last().unwrap().len() > 1 {
                let cur = ls.last().unwrap();
                let h = cur.len() / 2;
                ls.push((0..h).map(|i| cur[i] * cur[i + h]).collect());
            }
            ls.reverse();
            ls
        })
        .collect();
    let products: Vec<Fp> = layers.iter().map(|l| l[0][0]).collect();
    t.append(b"gp/products", &products);
    let mut claims = products.clone();
    let mut point: Vec<Fp> = vec![];
    let mut proofs = Vec::with_capacity(ell);
    for j in 1..=ell {
        let rho: Vec<Fp> = t.challenge_scalars(b"gp/rho", k);
        let half = 1usize << (j - 1);
        let mut eq = eq_table(&point);
        let mut lo: Vec<Vec<Fp>> = layers.iter().map(|l| l[j][..half].to_vec()).collect();
        let mut hi: Vec<Vec<Fp>> = layers.iter().map(|l| l[j][half..].to_vec()).collect();
        let mut polys = Vec::with_capacity(j - 1);
        let mut rs = Vec::with_capacity(j - 1);
        for _ in 0..(j - 1) {
            let h = eq.len() / 2;
            let mut e = [Fp::zero(); 4];
            for i in 0..h {
                let (e0, de) = (eq[i], eq[i + h] - eq[i]);
                let mut ex = e0;
                let mut terms: Vec<(Fp, Fp, Fp, Fp)> = (0..k)
                    .map(|c| (lo[c][i], lo[c][i + h] - lo[c][i], hi[c][i], hi[c][i + h] - hi[c][i]))
                    .collect();
                for slot in e.iter_mut() {
                    let s: Fp = terms.iter().zip(&rho).map(|((l, _, hh, _), w)| *w * l * hh).sum();
                    *slot += ex * s;
                    ex += de;
                    for tm in terms.iter_mut() {
                        tm.0 += tm.1;
                        tm.2 += tm.3;
                    }
                }
            }
            t.append(b"gp/poly", &e.to_vec());
            let r: Fp = t.challenge_scalar(b"gp/r");
            fold(&mut eq, r);
            for c in 0..k {
                fold(&mut lo[c], r);
                fold(&mut hi[c], r);
            }
            polys.push(e);
            rs.push(r);
        }
        let v0: Vec<Fp> = lo.iter().map(|l| l[0]).collect();
        let v1: Vec<Fp> = hi.iter().map(|h| h[0]).collect();
        t.append(b"gp/v0", &v0);
        t.append(b"gp/v1", &v1);
        let cc: Fp = t.challenge_scalar(b"gp/c");
        claims = v0.iter().zip(&v1).map(|(a, b)| (Fp::one() - cc) * a + cc * b).collect();
        point = std::iter::once(cc).chain(rs).collect();
        proofs.push(LayerProof { polys, v0, v1 });
    }
    (BatchedProductProof { products, layers: proofs }, point, claims)
}

// returns (common leaf point, leaf claims) to check against the leaves' mles
pub fn verify(t: &mut Transcript, proof: &BatchedProductProof, k: usize, ell: usize) -> Option<(Vec<Fp>, Vec<Fp>)> {
    if proof.products.len() != k || proof.layers.len() != ell {
        return None;
    }
    t.append(b"gp/products", &proof.products);
    let mut claims = proof.products.clone();
    let mut point: Vec<Fp> = vec![];
    for (j, layer) in (1..=ell).zip(&proof.layers) {
        if layer.polys.len() != j - 1 || layer.v0.len() != k || layer.v1.len() != k {
            return None;
        }
        let rho: Vec<Fp> = t.challenge_scalars(b"gp/rho", k);
        let mut e: Fp = rho.iter().zip(&claims).map(|(w, c)| *w * c).sum();
        let mut rs = Vec::with_capacity(j - 1);
        for g in &layer.polys {
            if g[0] + g[1] != e {
                return None;
            }
            t.append(b"gp/poly", &g.to_vec());
            let r: Fp = t.challenge_scalar(b"gp/r");
            e = eval_cubic(g, r);
            rs.push(r);
        }
        let joint: Fp = (0..k).map(|c| rho[c] * layer.v0[c] * layer.v1[c]).sum();
        if e != eq_eval(&point, &rs) * joint {
            return None;
        }
        t.append(b"gp/v0", &layer.v0);
        t.append(b"gp/v1", &layer.v1);
        let cc: Fp = t.challenge_scalar(b"gp/c");
        claims = layer.v0.iter().zip(&layer.v1).map(|(a, b)| (Fp::one() - cc) * a + cc * b).collect();
        point = std::iter::once(cc).chain(rs).collect();
    }
    Some((point, claims))
}

