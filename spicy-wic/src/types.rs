// type aliases for the pasta cycle: G0 = pallas over F_p, G_cyc = vesta with scalar field F_p

// F_p: base field of E, scalar field of G_cyc, and the circuit field
pub type Fp = ark_pallas::Fq;
// Z_q0: scalar field of E and base field of G_cyc
pub type Fq0 = ark_pallas::Fr;

// G0 = E(F_p), pallas
pub type G0Affine = ark_pallas::Affine;
pub type G0Projective = ark_pallas::Projective;

// G_cyc, vesta
pub type GcycAffine = ark_vesta::Affine;

