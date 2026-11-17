// fiat-shamir transcript for the oracles H_t, t in {pow, tok, pair, key, bat}
// sha-512 hash chain; challenges take 64 bytes reduced mod the order

use ark_ff::PrimeField;
use sha2::{Digest, Sha512};

#[derive(Clone)]
pub struct Transcript {
    state: [u8; 64],
}

impl Transcript {
    // transcript for H_t with domain label t
    pub fn new(domain: &[u8]) -> Self {
        let mut h = Sha512::new();
        h.update(b"SPICy/transcript/v1");
        h.update((domain.len() as u64).to_le_bytes());
        h.update(domain);
        Transcript { state: h.finalize().into() }
    }

    pub fn append_bytes(&mut self, label: &[u8], bytes: &[u8]) {
        let mut h = Sha512::new();
        h.update(self.state);
        h.update((label.len() as u64).to_le_bytes());
        h.update(label);
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
        self.state = h.finalize().into();
    }

    // 64 pseudo-random bytes, state is ratcheted afterwards
    pub fn challenge_bytes(&mut self, label: &[u8]) -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(self.state);
        h.update(b"challenge");
        h.update((label.len() as u64).to_le_bytes());
        h.update(label);
        let out: [u8; 64] = h.finalize().into();
        self.append_bytes(b"ratchet", &out);
        out
    }

    pub fn challenge_scalar<F: PrimeField>(&mut self, label: &[u8]) -> F {
        F::from_le_bytes_mod_order(&self.challenge_bytes(label))
    }

}
