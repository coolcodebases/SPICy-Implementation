// data-parallel helpers, rayon when the parallel feature is on
// results don't depend on scheduling; randomised work gets one chacha20 stream per item (map_rng)

use ark_std::rand::RngCore;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroizing;

// (0..n).map(f).collect() in parallel
pub fn map_range<U, F>(n: usize, f: F) -> Vec<U>
where
    U: Send,
    F: Fn(usize) -> U + Sync + Send,
{
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        (0..n).into_par_iter().map(f).collect()
    }
    #[cfg(not(feature = "parallel"))]
    {
        (0..n).map(f).collect()
    }
}

// xs.iter().map(f).collect() in parallel
pub fn map<T, U, F>(xs: &[T], f: F) -> Vec<U>
where
    T: Sync,
    U: Send,
    F: Fn(&T) -> U + Sync + Send,
{
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        xs.par_iter().map(f).collect()
    }
    #[cfg(not(feature = "parallel"))]
    {
        xs.iter().map(f).collect()
    }
}

// (0..n).map(|i| f(i, rng_i)) with one chacha20 stream per item, seeded from rng in index order; seeds are wiped after use
pub fn map_rng<U, R, F>(n: usize, rng: &mut R, f: F) -> Vec<U>
where
    U: Send,
    R: RngCore,
    F: Fn(usize, &mut ChaCha20Rng) -> U + Sync + Send,
{
    let seeds: Vec<Zeroizing<[u8; 32]>> = (0..n)
        .map(|_| {
            let mut s = Zeroizing::new([0u8; 32]);
            rng.fill_bytes(&mut s[..]);
            s
        })
        .collect();
    map_range(n, |i| {
        let mut r = ChaCha20Rng::from_seed(*seeds[i]);
        f(i, &mut r)
    })
}

// (a(), b()) in parallel
pub fn join<A, B, RA, RB>(a: A, b: B) -> (RA, RB)
where
    A: FnOnce() -> RA + Send,
    B: FnOnce() -> RB + Send,
    RA: Send,
    RB: Send,
{
    #[cfg(feature = "parallel")]
    {
        rayon::join(a, b)
    }
    #[cfg(not(feature = "parallel"))]
    {
        (a(), b())
    }
}

