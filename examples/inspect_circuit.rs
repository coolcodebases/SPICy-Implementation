// looks inside the circuits: gadget costs, witness layout of a small R_pair, and which constraint each of three tampered witnesses breaks
// run: cargo run --release --example inspect_circuit

use ark_ec::AffineRepr;
use ark_ff::{One, Zero};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintLayer, ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, TracingMode};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tracing_subscriber::layer::SubscriberExt;

use spicy::circuits::gadgets::{
    alloc_row, complete_add, is_zero, windowed_fixed_base_mul3, swu_gadget, swu_gadget_with_hints, AffineVar,
    SwuTamper,
};
use spicy::circuits::r_pair::RPair;
use spicy::circuits::CommittedRelation;
use spicy::curve::coords;
use spicy::params::{setup, Params};
use spicy::protocol::pair_setup::build_pair_relations;
use spicy::protocol::registration::{registration_r, registration_s};
use spicy::snark::choose_width;
use spicy::snark::transparent::Transparent;
use spicy::types::{Fp, G0Affine, N0};

// number of constraints f adds to a fresh cs
fn cost(f: impl FnOnce(ConstraintSystemRef<Fp>)) -> usize {
    let cs = ConstraintSystem::<Fp>::new_ref();
    f(cs.clone());
    assert!(cs.is_satisfied().unwrap(), "honest gadget must be satisfied");
    cs.num_constraints()
}

fn point(cs: &ConstraintSystemRef<Fp>, p: &G0Affine) -> AffineVar {
    let (x, y) = coords(p).unwrap();
    AffineVar { x: FpVar::new_witness(cs.clone(), || Ok(x)).unwrap(), y: FpVar::new_witness(cs.clone(), || Ok(y)).unwrap() }
}

fn main() {
    // name failing constraints
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let _guard = tracing::subscriber::set_default(tracing_subscriber::Registry::default().with(layer));

    let g = G0Affine::generator();
    let g2 = (g + g).into();
    println!("== 1. Gadget costs (constraints) ==");
    let rows = [
        ("is_zero(a)", cost(|cs| {
            let a = FpVar::new_witness(cs.clone(), || Ok(Fp::from(7u64))).unwrap();
            let _ = is_zero(cs, &a).unwrap();
        })),
        ("windowed_fixed_base_mul3(β; G0, H0, H0'), 255 bits", cost(|cs| {
            let t = spicy::circuits::r_tok::token_tables();
            let bits: Vec<Boolean<Fp>> =
                (0..N0).map(|i| Boolean::new_witness(cs.clone(), || Ok(i % 3 == 0)).unwrap()).collect();
            let _ = windowed_fixed_base_mul3(cs, &bits, [&t[0], &t[1], &t[2]]).unwrap();
        })),
        ("swu_gadget(u) = ϕ(u)", cost(|cs| {
            let u = FpVar::new_witness(cs.clone(), || Ok(Fp::from(12345u64))).unwrap();
            swu_gadget(cs, &u).unwrap();
        })),
        ("complete_add(P, Q), RCB, Z = 1 inputs", cost(|cs| {
            let (p, q) = (point(&cs, &g), point(&cs, &g2));
            let _ = complete_add(&p.to_projective(), &q.to_projective()).unwrap();
        })),
        ("alloc_row(m = 4, W = 8)", cost(|cs| {
            alloc_row(cs, Some(&[Fp::one(); 4]), 4, 8).unwrap();
        })),
    ];
    for (name, n) in rows {
        println!("  {name:<34} {n:>6}");
    }
    println!("  (Boolean witnesses add 1 constraint each: b·(b − 1) = 0; counted inside the gadget that allocates them.)");

    println!("\n== 2. R_pair for M = 2, N = 1 (n_g = 8, the smallest allowed) ==");
    let pp = setup(&Params::with_mask_len(2, 1, 8).unwrap()).unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let (reg_r, _) = registration_r(&pp, b"R", &[b"y0".to_vec()], &mut rng).unwrap();
    let (_, sender) = registration_s::<Transparent, _>(&pp, b"S", &[b"x0".to_vec(), b"x1".to_vec()], &mut rng).unwrap();
    let rel = build_pair_relations::<Transparent, _>(&pp, &sender, &reg_r, &mut rng).unwrap();
    let (stmt, wit) = (&rel.pair_stmt, &rel.pair_wit);
    let width = choose_width::<RPair>(stmt).unwrap();
    let cs = ConstraintSystem::<Fp>::new_ref();
    RPair::circuit(stmt, Some(wit), width).generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    println!("  Hyrax row width W = {width}");
    println!(
        "  constraints = {}, witness variables = {}, public inputs = {} (instance vector also holds the constant 1)",
        cs.num_constraints(),
        cs.num_witness_variables(),
        cs.num_instance_variables() - 1
    );
    let b = cs.borrow().unwrap();
    println!("  public inputs = coords(T_j), coords(T'_j) per slot:");
    for (i, v) in b.instance_assignment[1..].iter().enumerate() {
        let what = ["x_T", "y_T", "x_T'", "y_T'"][i % 4].to_string() + &format!("_{}", i / 4 + 1);
        println!("    io[{i:>2}] {what:<7} = {}", short(v));
    }
    println!("  pre-committed rows = the first (4B+5)·W witness variables (the 4B block rows d_(c,b) the Receiver derives from pk_R, z^S, then x_V, y_V, x_V', y_V'), M values + zero padding:");
    let nb = stmt.blocks.len();
    let mut names: Vec<String> = (0..nb).map(|i| format!("d{},{}", i / (nb / 4), i % (nb / 4))).collect();
    names.extend(["z^S", "x_V", "y_V", "x_V'", "y_V'"].map(String::from));
    for (r, name) in names.iter().enumerate() {
        let row = &b.witness_assignment[r * width..(r + 1) * width];
        let shown: Vec<String> = row[..2].iter().map(short).collect();
        let zeros = row[2..].iter().all(|x| x.is_zero());
        println!("    row {r:>2} ({name:<5}): [{}, …]  entries 2..{width} all zero: {zeros}", shown.join(", "));
    }
    assert_eq!(b.witness_assignment[0], wit.blocks[0][0]);
    drop(b);
    println!("  satisfied: {}", cs.is_satisfied().unwrap());

    println!("\n== 3. Tampered witnesses and the constraint they break ==");
    // (a) wrong block value moves phi(u), so T_0 doesn't match the public input
    let mut w2 = wit.clone();
    w2.blocks[0][0] += Fp::one();
    let cs = ConstraintSystem::<Fp>::new_ref();
    RPair::circuit(stmt, Some(&w2), width).generate_constraints(cs.clone()).unwrap();
    println!("  (a) u + 1            -> {}", path(&cs.which_is_unsatisfied().unwrap().unwrap_or_default()));
    // (b) wrong sqrt sign in phi
    let cs = ConstraintSystem::<Fp>::new_ref();
    let u = FpVar::new_witness(cs.clone(), || Ok(Fp::from(12345u64))).unwrap();
    swu_gadget_with_hints(cs.clone(), &u, SwuTamper { flip_sign: true, flip_branch: false }).unwrap();
    println!("  (b) −y in ϕ(u)       -> {}", path(&cs.which_is_unsatisfied().unwrap().unwrap_or_default()));
    // (c) wrong branch at u = 0
    let cs = ConstraintSystem::<Fp>::new_ref();
    let u = FpVar::new_witness(cs.clone(), || Ok(Fp::zero())).unwrap();
    swu_gadget_with_hints(cs.clone(), &u, SwuTamper { flip_sign: false, flip_branch: true }).unwrap();
    println!("  (c) b = 0 at u = 0   -> {}", path(&cs.which_is_unsatisfied().unwrap().unwrap_or_default()));
}

fn short(v: &Fp) -> String {
    if v.is_zero() {
        "0".into()
    } else {
        let s = v.to_string();
        format!("{}…", &s[..s.len().min(8)])
    }
}

// shortens the arkworks constraint trace to "R_pair > element > ..."
fn path(trace: &str) -> String {
    let mut names: Vec<&str> = trace
        .lines()
        .filter_map(|l| l.split("spicy::circuits::").nth(1))
        .filter_map(|l| l.split("::").last())
        .collect();
    names.reverse();
    names.join(" > ")
}
