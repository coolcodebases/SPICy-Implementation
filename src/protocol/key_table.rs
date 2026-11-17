// receiver's key table k_(R,i,j), one column per slot sorted by point so a match is a binary search

use ark_ec::AffineRepr;

use crate::types::G0Affine;

// exact identity of a G0 point: x limbs and y parity (2 for the identity)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PointKey([u64; 4], u8);

impl PointKey {
    pub fn of(p: &G0Affine) -> Self {
        if p.is_zero() {
            return PointKey([0; 4], 2);
        }
        PointKey(p.x.0 .0, (p.y.0 .0[0] & 1) as u8)
    }
}

#[derive(Clone, Debug, Default)]
pub struct KeyTable {
    cols: Vec<Vec<(PointKey, u32)>>,
}

impl KeyTable {
    // cols[j] = (i, k_(R,i,j)) for the i that slot j can match
    pub fn from_columns(cols: Vec<Vec<(usize, G0Affine)>>) -> Self {
        let cols = crate::par::map(&cols, |col| {
            let mut v: Vec<(PointKey, u32)> =
                col.iter().map(|(i, p)| (PointKey::of(p), u32::try_from(*i).expect("N < 2^32"))).collect();
            v.sort_unstable();
            v
        });
        KeyTable { cols }
    }

    // from full columns cols[j][i] = k_(R,i,j)
    pub fn from_full_columns(cols: Vec<Vec<G0Affine>>) -> Self {
        let cols = crate::par::map(&cols, |col| {
            let mut v: Vec<(PointKey, u32)> =
                col.iter().enumerate().map(|(i, p)| (PointKey::of(p), u32::try_from(i).expect("N < 2^32"))).collect();
            v.sort_unstable();
            v
        });
        KeyTable { cols }
    }

    pub fn slots(&self) -> usize {
        self.cols.len()
    }

    pub fn pairs(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.cols.iter().enumerate().flat_map(|(j, col)| col.iter().map(move |(_, i)| (*i as usize, j)))
    }

    pub fn entries(&self) -> usize {
        self.cols.iter().map(Vec::len).sum()
    }

    // every i with k_(R,i,j) = k, increasing
    pub fn matches(&self, j: usize, k: &G0Affine) -> Vec<usize> {
        let Some(col) = self.cols.get(j) else { return vec![] };
        let key = PointKey::of(k);
        let start = col.partition_point(|(q, _)| *q < key);
        let mut out: Vec<usize> = col[start..].iter().take_while(|(q, _)| *q == key).map(|(_, i)| *i as usize).collect();
        out.sort_unstable();
        out
    }
}

