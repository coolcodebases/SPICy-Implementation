// zeroize secrets on drop (keys, sigma nonces, tokens, set elements, row openings, witnesses, r1cs assignments); all Drop impls live here
// best effort: clones and library buffers can survive

use zeroize::Zeroize;

use crate::bridge::Token;
use crate::circuits::r_pair::PairWitness;
use crate::circuits::r_pow::PowWitness;
use crate::circuits::r_tok::TokWitness;
use crate::oprf::SkR;
use crate::pedersen::power_rows::PowerRowsSecret;
use crate::protocol::registration::{ReceiverSecret, SenderSecret};
use crate::sigma::key_relation::KeyWitness;
use crate::sigma::maurer::Precommit;
use crate::sigma::open_relation::OpenWitness;
use crate::circuits::Values;
use crate::snark::r1cs::Assignment;
use crate::types::Fp;

fn wipe_pairs(v: &mut Vec<(Fp, Fp)>) {
    for p in v.iter_mut() {
        p.0.zeroize();
        p.1.zeroize();
    }
    v.clear();
}

fn wipe_pair(p: &mut (Fp, Fp)) {
    p.0.zeroize();
    p.1.zeroize();
}

impl Drop for SkR {
    fn drop(&mut self) {
        self.rho.zeroize();
    }
}

impl Drop for ReceiverSecret {
    fn drop(&mut self) {
        // sk_r wipes itself
        self.elements.zeroize();
    }
}

impl Drop for PowerRowsSecret {
    fn drop(&mut self) {
        self.powers.zeroize();
        self.blinds.zeroize();
    }
}

impl Drop for SenderSecret {
    fn drop(&mut self) {
        // rows_secret wipes itself
        self.elements.zeroize();
        self.z.zeroize();
    }
}

impl Drop for KeyWitness {
    fn drop(&mut self) {
        for v in [&mut self.a, &mut self.b, &mut self.gamma1, &mut self.gamma2] {
            v.zeroize();
        }
        self.r.zeroize();
    }
}

impl Drop for OpenWitness {
    fn drop(&mut self) {
        self.a.zeroize();
        self.b.zeroize();
        self.r.zeroize();
    }
}

impl Drop for Precommit {
    fn drop(&mut self) {
        self.kappa.zeroize();
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        self.beta.zeroize();
    }
}

impl Drop for PowWitness {
    fn drop(&mut self) {
        self.powers.zeroize();
        self.blinds.zeroize();
    }
}

impl Drop for TokWitness {
    fn drop(&mut self) {
        self.beta.zeroize();
        wipe_pairs(&mut self.v);
        wipe_pairs(&mut self.v2);
        wipe_pair(&mut self.r_v);
        wipe_pair(&mut self.r_v2);
    }
}

impl Drop for PairWitness {
    fn drop(&mut self) {
        for d in self.blocks.iter_mut() {
            d.zeroize();
        }
        self.block_blinds.zeroize();
        self.zs.zeroize();
        self.zs_blind.zeroize();
        wipe_pairs(&mut self.v);
        wipe_pairs(&mut self.v2);
        wipe_pair(&mut self.r_v);
        wipe_pair(&mut self.r_v2);
    }
}

impl Drop for Assignment {
    fn drop(&mut self) {
        self.witness.zeroize();
    }
}

impl Drop for Values {
    fn drop(&mut self) {
        self.witness.zeroize();
    }
}

