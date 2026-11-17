// commitments derived from pk_R and the power rows, opening to the decoding inputs (u_j, v_j, u'_j, v'_j)
// receiver computes the commitments, sender the openings
// keys must be normalized to one length

use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::Zero;

use crate::types::{Fp, GcycAffine, GcycProjective};

fn check_key(pk: &[Vec<Fp>]) -> usize {
    assert_eq!(pk.len(), 4, "pk_R is four polynomials");
    let len = pk[0].len();
    assert!(pk.iter().all(|p| p.len() == len), "pk_R polynomials must be normalized to one length");
    len
}

// paterson-stockmeyer form: P_(c+1)(X) = sum_b X^(bS) F_(c,b)(X), B = ceil((N+1)/S) blocks
// C_(c,b) = sum_(k<S) [p_(c,bS+k)]Z_k, minus Z_g for c = 3, b = 0; horner in z_j^S over the blocks gives the decoding inputs
// returned c-major, index c*B + b
fn block_coefficients(pk: &[Vec<Fp>], s: usize, blocks: usize) -> Vec<Vec<Fp>> {
    let mut out = Vec::with_capacity(4 * blocks);
    for p in pk {
        for b in 0..blocks {
            out.push((0..s).map(|k| p.get(b * s + k).copied().unwrap_or_default()).collect());
        }
    }
    out
}

// block commitments C_(c,b) from Z_0 and rows = [Z_1..Z_S, Z_g]; variable time
pub fn block_commitments(z0: GcycAffine, rows: &[GcycAffine], pk: &[Vec<Fp>], s: usize, blocks: usize) -> Vec<GcycAffine> {
    assert_eq!(rows.len(), s + 1, "rows = Z_1..Z_S, Z_g");
    assert!(check_key(pk) <= s * blocks, "pk_R longer than B blocks");
    let base: Vec<GcycAffine> = std::iter::once(z0).chain(rows[..s - 1].iter().copied()).collect();
    let coeffs = block_coefficients(pk, s, blocks);
    let c: Vec<GcycProjective> = crate::par::map_range(coeffs.len(), |i| {
        let p = GcycProjective::msm_unchecked(&base, &coeffs[i]);
        if i == 3 * blocks {
            p - rows[s]
        } else {
            p
        }
    });
    GcycProjective::normalize_batch(&c)
}

// openings of block_commitments from values[k-1] = (z_j^k)_j for k up to S and values[S] = (g(z_j))_j
pub fn block_openings(values: &[Vec<Fp>], blinds: &[Fp], pk: &[Vec<Fp>], s: usize, blocks: usize) -> Vec<(Vec<Fp>, Fp)> {
    assert_eq!(values.len(), s + 1, "rows = Z_1..Z_S, Z_g");
    assert!(check_key(pk) <= s * blocks, "pk_R longer than B blocks");
    let m = values[0].len();
    let coeffs = block_coefficients(pk, s, blocks);
    crate::par::map_range(coeffs.len(), |i| {
        let a = &coeffs[i];
        let mut vals: Vec<Fp> = (0..m).map(|j| a[0] + (1..s).map(|k| a[k] * values[k - 1][j]).sum::<Fp>()).collect();
        let mut r: Fp = (1..s).map(|k| a[k] * blinds[k - 1]).sum();
        if i == 3 * blocks {
            vals.iter_mut().zip(&values[s]).for_each(|(v, g)| *v -= g);
            r -= blinds[s];
        }
        (vals, r)
    })
}

// horner over the blocks, x = z^S
pub fn horner(blocks: &[Fp], x: Fp) -> Fp {
    blocks.iter().rev().fold(Fp::zero(), |acc, d| acc * x + d)
}

// rows with Z_0 prepended
pub fn with_z0(z0: GcycAffine, rows: &[GcycAffine]) -> Vec<GcycAffine> {
    let mut out = Vec::with_capacity(rows.len() + 1);
    out.push(z0);
    out.extend_from_slice(rows);
    out
}

