// sparse r1cs matrices in compressed-row form with interned coefficients
// +-1 entries skip the multiplication; to_rows inverts from_rows

use std::collections::HashMap;

use ark_ff::{One, Zero};

use crate::types::Fp;

// index of 1 in every table
pub const ONE: u32 = 0;
// index of -1 in every table
pub const NEG_ONE: u32 = 1;

// row i has entries col[k], vals[coef[k]] for k in row_ptr[i]..row_ptr[i+1]
#[derive(Clone, Debug)]
pub struct Matrix {
    row_ptr: Vec<u32>,
    col: Vec<u32>,
    coef: Vec<u32>,
    vals: Vec<Fp>,
}

// coefficient interning table, 1 and -1 at ONE and NEG_ONE
#[derive(Clone, Debug)]
pub struct Coeffs {
    vals: Vec<Fp>,
    index: HashMap<Fp, u32>,
}

impl Default for Coeffs {
    fn default() -> Self {
        let vals = vec![Fp::one(), -Fp::one()];
        let index = vals.iter().enumerate().map(|(i, v)| (*v, i as u32)).collect();
        Coeffs { vals, index }
    }
}

impl Coeffs {
    pub fn into_vals(self) -> Vec<Fp> {
        self.vals
    }

    pub fn intern(&mut self, v: Fp) -> u32 {
        if let Some(i) = self.index.get(&v) {
            return *i;
        }
        let i = u32::try_from(self.vals.len()).expect("fewer than 2^32 distinct coefficients");
        self.vals.push(v);
        self.index.insert(v, i);
        i
    }
}

fn u32_of(x: usize) -> u32 {
    u32::try_from(x).expect("matrix index below 2^32")
}

impl Matrix {
    // from arkworks row form, keeps entry order
    pub fn from_rows(rows: &[Vec<(Fp, usize)>]) -> Self {
        let mut t = Coeffs::default();
        let nnz: usize = rows.iter().map(Vec::len).sum();
        let (mut row_ptr, mut col, mut coef) = (Vec::with_capacity(rows.len() + 1), Vec::with_capacity(nnz), Vec::with_capacity(nnz));
        row_ptr.push(0);
        for row in rows {
            for (v, k) in row {
                debug_assert!(!v.is_zero(), "arkworks never stores a zero coefficient");
                col.push(u32_of(*k));
                coef.push(t.intern(*v));
            }
            row_ptr.push(u32_of(col.len()));
        }
        Matrix { row_ptr, col, coef, vals: t.vals }
    }

    // row_ptr starts at 0 and is non-decreasing up to col.len(), every coef index below vals.len()
    pub fn from_parts(row_ptr: Vec<u32>, col: Vec<u32>, coef: Vec<u32>, vals: Vec<Fp>) -> Self {
        assert!(row_ptr.first() == Some(&0) && *row_ptr.last().unwrap() as usize == col.len());
        assert!(row_ptr.windows(2).all(|w| w[0] <= w[1]) && col.len() == coef.len());
        assert!(vals.len() >= 2 && vals[ONE as usize] == Fp::one() && vals[NEG_ONE as usize] == -Fp::one());
        assert!(coef.iter().all(|c| (*c as usize) < vals.len()));
        Matrix { row_ptr, col, coef, vals }
    }

    // back to arkworks row form
    pub fn to_rows(&self) -> Vec<Vec<(Fp, usize)>> {
        (0..self.num_rows()).map(|i| self.row(i).collect()).collect()
    }

    pub fn num_rows(&self) -> usize {
        self.row_ptr.len() - 1
    }

    pub fn nnz(&self) -> usize {
        self.col.len()
    }

    pub fn vals(&self) -> &[Fp] {
        &self.vals
    }

    // row i as (columns, coef indices)
    #[inline]
    pub fn row_raw(&self, i: usize) -> (&[u32], &[u32]) {
        let (s, e) = (self.row_ptr[i] as usize, self.row_ptr[i + 1] as usize);
        (&self.col[s..e], &self.coef[s..e])
    }

    // row i as (coef, column) pairs
    pub fn row(&self, i: usize) -> impl Iterator<Item = (Fp, usize)> + '_ {
        let (c, k) = self.row_raw(i);
        c.iter().zip(k).map(|(c, k)| (self.vals[*k as usize], *c as usize))
    }

    // sum_k coef_k * z(col_k) over row i
    #[inline]
    pub fn dot_row(&self, i: usize, z: impl Fn(usize) -> Fp) -> Fp {
        let (cols, coefs) = self.row_raw(i);
        let mut acc = Fp::zero();
        for (c, k) in cols.iter().zip(coefs) {
            let v = z(*c as usize);
            match *k {
                ONE => acc += v,
                NEG_ONE => acc -= v,
                k => acc += self.vals[k as usize] * v,
            }
        }
        acc
    }

    // transpose with num_cols rows: row y lists (row index, coef) of column y, rows increasing
    pub fn transpose(&self, num_cols: usize) -> Matrix {
        // parallel counting sort: chunk t writes its entries of column y after those of chunks < t, so each column lists its rows in increasing order
        let rows = self.num_rows();
        let t = if self.nnz() < (1 << 16) { 1 } else { crate::par::num_threads().clamp(1, 16) };
        let bounds: Vec<usize> = (0..=t).map(|k| k * rows / t).collect();
        let counts: Vec<Vec<u32>> = crate::par::map_range(t, |k| {
            let mut c = vec![0u32; num_cols];
            let (s, e) = (self.row_ptr[bounds[k]] as usize, self.row_ptr[bounds[k + 1]] as usize);
            for y in &self.col[s..e] {
                c[*y as usize] += 1;
            }
            c
        });
        let mut row_ptr = vec![0u32; num_cols + 1];
        for y in 0..num_cols {
            row_ptr[y + 1] = row_ptr[y] + counts.iter().map(|c| c[y]).sum::<u32>();
        }
        // start offset of (chunk k, column y)
        let mut starts: Vec<Vec<u32>> = Vec::with_capacity(t);
        let mut run = row_ptr[..num_cols].to_vec();
        for c in &counts {
            starts.push(run.clone());
            for y in 0..num_cols {
                run[y] += c[y];
            }
        }
        drop(counts);
        let nnz = self.nnz();
        let (mut col, mut coef) = (vec![0u32; nnz], vec![0u32; nnz]);
        // each (chunk, column) range of the output is written by exactly one chunk
        struct Out(*mut u32, *mut u32);
        unsafe impl Sync for Out {}
        let out = Out(col.as_mut_ptr(), coef.as_mut_ptr());
        let out = &out;
        crate::par::map_range(t, |k| {
            let mut next = starts[k].clone();
            for i in bounds[k]..bounds[k + 1] {
                let (cs, ks) = self.row_raw(i);
                for (c, kk) in cs.iter().zip(ks) {
                    let p = &mut next[*c as usize];
                    debug_assert!((*p as usize) < nnz);
                    // safety: p is in this chunk's own range of column c (disjoint across chunks) and below nnz by construction of row_ptr and starts
                    unsafe {
                        *out.0.add(*p as usize) = u32_of(i);
                        *out.1.add(*p as usize) = *kk;
                    }
                    *p += 1;
                }
            }
        });
        Matrix { row_ptr, col, coef, vals: self.vals.clone() }
    }
}

impl PartialEq for Matrix {
    // same rows in the same order, coef tables may differ
    fn eq(&self, other: &Self) -> bool {
        self.num_rows() == other.num_rows()
            && self.nnz() == other.nnz()
            && (0..self.num_rows()).all(|i| self.row(i).eq(other.row(i)))
    }
}

impl PartialEq<Vec<Vec<(Fp, usize)>>> for Matrix {
    fn eq(&self, other: &Vec<Vec<(Fp, usize)>>) -> bool {
        self.num_rows() == other.len() && (0..self.num_rows()).all(|i| self.row(i).eq(other[i].iter().copied()))
    }
}

