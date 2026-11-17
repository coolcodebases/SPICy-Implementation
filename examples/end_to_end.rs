// full spicy run with sizes and simulated wan times (100 Mbit/s, 80 ms rtt)
// run: cargo run --release --example end_to_end -- --config examples/spicy.toml [--trace]
// or: cargo run --release --example end_to_end -- 8 8 [--ng 36]; --trace times every phase

use std::time::{Duration, Instant};

use rand_chacha::rand_core::{OsRng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tracing_subscriber::layer::SubscriberExt;

use ark_relations::r1cs::{ConstraintLayer, TracingMode};
use spicy::circuits::{r_pair::RPair, r_pow::{PowStatement, RPow}, r_tok::RTok};
use spicy::config::{Backend, Config};
use spicy::params::{setup, slack, DEFAULT_STAT_BITS};
use spicy::protocol::messages::size_of;
use spicy::protocol::pair_setup::build_pair_relations;
use spicy::protocol::*;
use spicy::snark::{cache, spartan::SpartanNizk, spartan::SpartanSnark, transparent::Transparent, ProofSystem};

fn rng_for(cfg: &Config) -> ChaCha20Rng {
    match cfg.seed {
        Some(s) => ChaCha20Rng::seed_from_u64(s),
        None => ChaCha20Rng::from_rng(OsRng).unwrap(),
    }
}

// one-way time of a message at 100 Mbit/s, 80 ms rtt
fn wan(bytes: usize) -> Duration {
    Duration::from_millis(40) + Duration::from_secs_f64(bytes as f64 * 8.0 / 100e6)
}

fn run<B: ProofSystem>(cfg: &Config) {
    let params = cfg.params().expect("parameters");
    let pp = setup(&params).unwrap();
    let mut rng = rng_for(cfg);
    let (m, n) = (cfg.m, cfg.n);
    let x: Vec<Vec<u8>> = (0..m).map(|i| format!("item-{}", 2 * i).into_bytes()).collect();
    let y: Vec<Vec<u8>> = (0..n).map(|i| format!("item-{}", 3 * i).into_bytes()).collect();
    println!(
        "SPICy with M = {m}, N = {n}, pk_R = 4 polynomials of degree ≤ {}, n_g = {}, μ = {} (slack n' = {} at κ = {DEFAULT_STAT_BITS}); backend: {}",
        n,
        params.n_g,
        params.ps_step,
        slack(n, DEFAULT_STAT_BITS),
        B::NAME
    );
    if !B::ZERO_KNOWLEDGE {
        println!("WARNING: this backend is NOT zero-knowledge (debugging only)");
    }

    let t = Instant::now();
    let (reg_r, rsec) = registration_r(&pp, b"receiver", &y, &mut rng).unwrap();
    println!("Registration_R      {:>9.2?}  |pk_R| = {} B (WAN {:.0?})", t.elapsed(), size_of(&reg_r), wan(size_of(&reg_r)));
    let t = Instant::now();
    let (reg_s, ssec) = registration_s::<B, _>(&pp, b"sender", &x, &mut rng).unwrap();
    println!(
        "Registration_S      {:>9.2?}  |msg| = {} B (π_pow {} B, WAN {:.0?})",
        t.elapsed(),
        size_of(&reg_s),
        reg_s.pi_pow.len(),
        wan(size_of(&reg_s))
    );
    let t = Instant::now();
    let verified = verify_registration_s::<B>(&pp, &reg_s).unwrap();
    println!("Verify π_pow        {:>9.2?}", t.elapsed());

    let rel = build_pair_relations::<Transparent, _>(&pp, &ssec, &reg_r, &mut rng).unwrap();
    let pow = cache::shape::<RPow>(&PowStatement { m, n_g: params.n_g, rows: ssec.rows.clone() }).unwrap();
    let tok = cache::shape::<RTok>(&rel.tokens.stmt).unwrap();
    let pair = cache::shape::<RPair>(&rel.pair_stmt).unwrap();
    for (name, c) in [("R_pow", pow), ("R_tok", tok), ("R_pair", pair)] {
        println!(
            "  {name:<6}: {:>8} constraints ({:>6} per slot), {:>8} witnesses, {:>4} public inputs, Hyrax width {}",
            c.r1cs.num_cons,
            c.r1cs.num_cons / m,
            c.r1cs.num_wit,
            c.r1cs.num_inst - 1,
            c.width
        );
    }

    let t = Instant::now();
    let pre = spicy::protocol::pair_setup::precompute_tokens::<B, _>(&pp, &ssec, &mut rng).unwrap();
    let t_pre = t.elapsed();
    println!("PairSetup_S offline {:>9.2?}  (token batch + π_tok, precomputable)", t_pre);
    let t = Instant::now();
    let (msg, mut s_state) = spicy::protocol::pair_setup::pair_setup_s_with::<B, _>(&pp, &ssec, &reg_r, Some(pre), &mut rng).unwrap();
    let t_on = t.elapsed();
    println!(
        "PairSetup_S         {:>9.2?}  (online part {:.2?} after the Receiver registered)  |msg_pair| = {} B (π_tok {} B, π_pair {} B, WAN {:.0?})",
        t_pre + t_on,
        t_on,
        size_of(&msg),
        msg.pi_tok.len(),
        msg.pi_pair.len(),
        wan(size_of(&msg))
    );
    let t = Instant::now();
    let r_state = pair_setup_r::<B>(&pp, &verified, &msg, &rsec).unwrap();
    println!("PairSetup_R         {:>9.2?}  (verify π_tok, π_pair, π_s; {} k_(R,i,j))", t.elapsed(), n * m);
    let t = Instant::now();
    s_state.precompute(1, &mut rng);
    println!("Σ first message     {:>9.2?}  (offline, one per session)", t.elapsed());

    for i in 0..2 {
        let sid = format!("session-{i}").into_bytes();
        let t = Instant::now();
        let im = intersection_s(&sid, &mut s_state, &mut rng);
        let ts = t.elapsed();
        let t = Instant::now();
        let out = intersection_r(&pp, &sid, &r_state, &rsec, &im).unwrap();
        let names: Vec<String> = out.iter().map(|e| String::from_utf8_lossy(e).into_owned()).collect();
        println!(
            "Intersection {}{}  S {:>9.2?} R {:>9.2?}  |msg| = {} B (WAN {:.0?})  INT = {names:?}",
            i,
            if i == 0 { " (precomputed)" } else { " (online)     " },
            ts,
            t.elapsed(),
            size_of(&im),
            wan(size_of(&im))
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let trace = args.iter().any(|a| a == "--trace");
    let cfg = if let Some(i) = args.iter().position(|a| a == "--config") {
        Config::load(args.get(i + 1).expect("--config <path>")).expect("config")
    } else {
        let ng = args.iter().position(|a| a == "--ng").and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok());
        let ps = args.iter().position(|a| a == "--ps").and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok());
        let nums: Vec<usize> = args
            .iter()
            .enumerate()
            .filter(|(i, _)| *i == 0 || (args[i - 1] != "--ng" && args[i - 1] != "--ps"))
            .filter_map(|(_, a)| a.parse().ok())
            .collect();
        let (m, n) = (*nums.first().unwrap_or(&8), *nums.get(1).unwrap_or(&8));
        Config { m, n, n_g: ng, ps_step: ps, backend: Backend::SpartanNizk, seed: Some(2026) }
    };

    let mut layer = ConstraintLayer::default();
    // OnlyConstraints turns off all other spans, so use All when timing
    layer.mode = if trace { TracingMode::All } else { TracingMode::OnlyConstraints };
    let registry = tracing_subscriber::Registry::default().with(layer);
    let _guard = if trace {
        tracing::subscriber::set_default(registry.with(SpanTimer))
    } else {
        tracing::subscriber::set_default(registry)
    };

    match cfg.backend {
        Backend::SpartanNizk => run::<SpartanNizk>(&cfg),
        Backend::SpartanSnark => run::<SpartanSnark>(&cfg),
        Backend::Transparent => run::<Transparent>(&cfg),
    }
}

// prints wall time of every span in this crate
// own layer since tracing-subscriber 0.3 doesn't work with ConstraintLayer
struct SpanTimer;

struct Started(Instant, String);

struct Fields(String);
impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        self.0.push_str(&format!(" {}={:?}", f.name(), v));
    }
    fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
        self.0.push_str(&format!(" {}={}", f.name(), v));
    }
}

impl<S> tracing_subscriber::Layer<S> for SpanTimer
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn new_span(&self, attrs: &tracing::span::Attributes<'_>, id: &tracing::span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        if !attrs.metadata().target().starts_with("spicy") {
            return;
        }
        if let Some(span) = ctx.span(id) {
            let mut f = Fields(String::new());
            attrs.record(&mut f);
            span.extensions_mut().insert(Started(Instant::now(), f.0));
        }
    }

    fn on_close(&self, id: tracing::span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        if let Some(span) = ctx.span(&id) {
            if let Some(Started(t, fields)) = span.extensions().get::<Started>() {
                let label = format!("{}{}", span.name(), fields.replace(" backend=", " | "));
                println!("  [trace] {label:<70} {:>9.2?}", t.elapsed());
            }
        }
    }
}
