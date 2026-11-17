// run config in toml: m, n, optional n_g (at least 4(N+1)), backend, optional seed
// the seed gives a deterministic chacha20 rng, benches and examples only
// unknown keys are rejected so a typo can't silently fall back to a default

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Result, SpicyError};
use crate::params::Params;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    // spartan nizk + hyrax, the verifier evaluates the r1cs matrices itself
    #[default]
    #[serde(alias = "spartan")]
    SpartanNizk,
    // spartan snark with spark + hyrax: sublinear verifier, bigger proofs
    SpartanSnark,
    // reveals the witness, not zero-knowledge. debugging only
    Transparent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub m: usize,
    pub n: usize,
    // mask length n_g, defaults to params::mask_len
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n_g: Option<usize>,
    // paterson-stockmeyer step S, defaults to params::default_ps_step
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ps_step: Option<usize>,
    #[serde(default)]
    pub backend: Backend,
    // fixed rng seed, experiments only
    #[serde(default)]
    pub seed: Option<u64>,
}

impl Config {
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let c: Config = toml::from_str(s).map_err(|e| SpicyError::Params(format!("config: {e}")))?;
        c.params()?;
        Ok(c)
    }

    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string(self).map_err(|e| SpicyError::Params(format!("config: {e}")))
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let s = std::fs::read_to_string(path.as_ref())
            .map_err(|e| SpicyError::Params(format!("reading {}: {e}", path.as_ref().display())))?;
        Self::from_toml_str(&s)
    }

    pub fn params(&self) -> Result<Params> {
        let n_g = self.n_g.unwrap_or_else(|| crate::params::mask_len(self.n, self.m, crate::params::DEFAULT_STAT_BITS));
        let s = self.ps_step.unwrap_or_else(|| crate::params::default_ps_step(self.n, n_g));
        Params::with_ps_step(self.m, self.n, n_g, s)
    }
}

