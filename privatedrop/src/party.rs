// safe rust layer between the c api and spicy::protocol
// the receiver sends (id_R, pk_R)
// the sender replies with its registration, msg_pair and the intersection message
// every exchange does a fresh pair setup and keeps no pair state
// both sides need the same n_g and refuse sizes that need a longer mask

use std::collections::HashMap;
use std::time::Instant;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;
use rand::RngCore;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroize;

use spicy::encoding::psi_encoding::PkR;
use spicy::error::{AbortReason, SpicyError};
use spicy::oprf::{check_distinct, SkR};
use spicy::params::{default_ps_step, mask_len, setup_cached, w_r, Params, PublicParams, DEFAULT_STAT_BITS};
use spicy::pedersen::power_rows::PowerRowsSecret;
use spicy::protocol::messages::{IntersectionMsg, MsgPair, RegistrationR, RegistrationS};
use spicy::protocol::pair_setup::{pair_setup_s_with, precompute_tokens};
use spicy::protocol::tokens::TokenBundle;
use spicy::protocol::{
    intersection_r, intersection_s, pair_setup_r, registration_r, registration_s, verify_registration_s,
    ReceiverSecret, SenderSecret,
};
use spicy::serialize::{from_bytes, to_bytes};
use spicy::snark::spartan::Spartan;
use spicy::types::{Fp, Fq0, GcycAffine};

// version byte at the start of every wire and secret encoding
pub const WIRE_VERSION: u8 = 3;

// proof backend for pi_pow, pi_tok and pi_pair
pub type Backend = Spartan;

// largest accepted identity, in bytes
pub const MAX_ID_LEN: usize = 1024;

// errors

// error categories exposed over the c api
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ErrorKind {
    InvalidArgument = 1,
    InvalidInput = 2,
    ProtocolAbort = 3,
    Malformed = 4,
    Policy = 5,
    Internal = 6,
    Panic = 7,
}

#[derive(Debug, Clone)]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Error { kind, message: message.into() }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl From<SpicyError> for Error {
    fn from(e: SpicyError) -> Self {
        let kind = match &e {
            SpicyError::Abort(AbortReason::MalformedMessage(_)) => ErrorKind::Malformed,
            SpicyError::Abort(_) => ErrorKind::ProtocolAbort,
            SpicyError::Params(_) | SpicyError::Input(_) => ErrorKind::InvalidInput,
            SpicyError::Serialization(_) => ErrorKind::Malformed,
            SpicyError::SamplingFailed | SpicyError::Synthesis(_) | SpicyError::UnsatisfiedWitness(_) => {
                ErrorKind::Internal
            }
        };
        Error::new(kind, e.to_string())
    }
}

pub type PartyResult<T> = std::result::Result<T, Error>;

// helpers shared with wic.rs

pub(crate) fn malformed(what: &str) -> Error {
    Error::new(ErrorKind::Malformed, format!("malformed {what}"))
}

// decodes a whole buffer, trailing bytes are an error
pub(crate) fn decode<T: CanonicalDeserialize>(bytes: &[u8], what: &str) -> PartyResult<T> {
    from_bytes::<T>(bytes).map_err(|e| Error::new(ErrorKind::Malformed, format!("malformed {what}: {e}")))
}

pub(crate) fn check_version(v: u8, expected: u8, what: &str) -> PartyResult<()> {
    if v != expected {
        return Err(Error::new(ErrorKind::Malformed, format!("{what}: unsupported version {v} (expected {expected})")));
    }
    Ok(())
}

// checks our own id
pub(crate) fn check_id(id: &[u8], what: &str) -> PartyResult<()> {
    if id.is_empty() || id.len() > MAX_ID_LEN {
        return Err(Error::new(ErrorKind::InvalidInput, format!("{what} must be 1..={MAX_ID_LEN} bytes")));
    }
    Ok(())
}

// checks an id received from the peer
pub(crate) fn check_peer_id(id: &[u8], what: &str) -> PartyResult<()> {
    if id.is_empty() || id.len() > MAX_ID_LEN {
        return Err(malformed(what));
    }
    Ok(())
}

// checks that the peer uses our n_g
pub(crate) fn check_same_n_g(peer: &str, peer_n_g: usize, me: &str, n_g: usize) -> PartyResult<()> {
    if peer_n_g != n_g {
        return Err(Error::new(
            ErrorKind::ProtocolAbort,
            format!("parameter mismatch: {peer} uses n_g = {peer_n_g}, this {me} n_g = {n_g}"),
        ));
    }
    Ok(())
}

// receiver side checks of the sender's M and n_g against the caller's limits and our n_g
pub(crate) fn check_sender_sizes(m: usize, n_g: usize, max_m: usize, max_n_g: usize, own_n_g: usize) -> PartyResult<()> {
    if m == 0 || m > max_m {
        return Err(Error::new(ErrorKind::Policy, format!("Sender set size M = {m} outside policy (1..={max_m})")));
    }
    if n_g > max_n_g {
        return Err(Error::new(ErrorKind::Policy, format!("Sender n_g = {n_g} outside policy (..={max_n_g})")));
    }
    check_same_n_g("Sender", n_g, "Receiver", own_n_g)
}

// ascending indices in elements of the items in out
pub(crate) fn indices_of(elements: &[Vec<u8>], out: &[Vec<u8>]) -> PartyResult<Vec<usize>> {
    let index: HashMap<&[u8], usize> = elements.iter().enumerate().map(|(i, e)| (e.as_slice(), i)).collect();
    let mut idx: Vec<usize> = out
        .iter()
        .map(|e| index.get(e.as_slice()).copied().ok_or_else(|| Error::new(ErrorKind::Internal, "output not in set")))
        .collect::<PartyResult<_>>()?;
    idx.sort_unstable();
    Ok(idx)
}

// fresh csprng seeded from the os
pub fn fresh_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_rng(OsRng).expect("OS randomness")
}

// recommended n_g for up to max_m / max_n elements, None if a size is 0
pub fn recommended_n_g(max_m: usize, max_n: usize) -> Option<usize> {
    (max_m > 0 && max_n > 0).then(|| mask_len(max_n, max_m, DEFAULT_STAT_BITS))
}

// N of a receiver key, if it is four polys of N+1 coeffs
fn n_of_key(pk: &PkR) -> Option<usize> {
    let len = pk.polys.first()?.len();
    (pk.polys.len() == 4 && len >= 2 && pk.polys.iter().all(|p| p.len() == len)).then(|| len - 1)
}

// pp for (M, N) under n_g
// aborts like PairSetup_S if 4(N+1) > n_g, and refuses sizes that need a longer mask
fn run_pp(m: usize, n: usize, n_g: usize, key_len: usize) -> PartyResult<PublicParams> {
    if 4 * (n + 1) > n_g {
        return Err(SpicyError::abort(AbortReason::DegreeTooLarge { len: key_len, max: n_g / 4 * 4 }).into());
    }
    let need = mask_len(n, m, DEFAULT_STAT_BITS);
    if n_g < need {
        return Err(Error::new(
            ErrorKind::Policy,
            format!("n_g = {n_g} is below the {need} needed for M = {m}, N = {n} at 128-bit statistical security"),
        ));
    }
    Ok(setup_cached(&party_params(m, n, n_g)?)?)
}

// wire messages

// sender registration plus the sizes the receiver needs to rebuild pp
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SenderRegistrationWire {
    pub version: u8,
    pub m: u64,
    pub n_g: u64,
    pub reg: RegistrationS,
}

// receiver registration (id_R, pk_R) and its n_g
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ReceiverRegistrationWire {
    pub version: u8,
    pub n_g: u64,
    pub reg: RegistrationR,
}

// sender's reply: msg_pair and the intersection message
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SenderResponseWire {
    pub version: u8,
    pub msg_pair: MsgPair,
    pub intersection: IntersectionMsg,
}

// persisted secret state, wiped on drop

// sender's registration secret, without token bundles
#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct SenderSecretWire {
    version: u8,
    m: u64,
    n_g: u64,
    id_s: Vec<u8>,
    // elements in slot order
    elements: Vec<Vec<u8>>,
    rows: Vec<GcycAffine>,
    powers: Vec<Vec<Fp>>,
    blinds: Vec<Fp>,
    pi_pow: Vec<u8>,
}

impl Drop for SenderSecretWire {
    fn drop(&mut self) {
        self.elements.zeroize();
        self.powers.zeroize();
        self.blinds.zeroize();
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct ReceiverSecretWire {
    version: u8,
    n_g: u64,
    id_r: Vec<u8>,
    pk_r: PkR,
    rho: Vec<Fq0>,
    elements: Vec<Vec<u8>>,
}

impl Drop for ReceiverSecretWire {
    fn drop(&mut self) {
        self.rho.zeroize();
        self.elements.zeroize();
    }
}

// timings

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timings {
    pub total_ns: u64,
    pub decode_ns: u64,
    pub verify_registration_ns: u64,
    pub pair_setup_ns: u64,
    pub intersection_ns: u64,
    pub encode_ns: u64,
    // time building a token batch in respond, 0 if a precomputed one was used
    pub tokens_ns: u64,
}

pub(crate) fn ns(t: Instant) -> u64 {
    t.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

// sender

pub struct SenderParty {
    secret: SenderSecret,
    m: usize,
    n_g: usize,
    registration: Vec<u8>,
    // precomputed token batches, each used for exactly one pair
    tokens: std::sync::Mutex<Vec<TokenBundle>>,
}

// params for (M, N) under n_g
// the paterson-stockmeyer step depends on n_g alone
fn party_params(m: usize, n: usize, n_g: usize) -> PartyResult<Params> {
    let n_max = (n_g / 4).saturating_sub(1).max(1);
    Ok(Params::with_ps_step(m, n, n_g, default_ps_step(n_max, n_g))?)
}

fn sender_pp(m: usize, n_g: usize) -> PartyResult<PublicParams> {
    Ok(setup_cached(&party_params(m, 1, n_g)?)?)
}

fn sender_registration(secret: &SenderSecret, m: usize, n_g: usize) -> Vec<u8> {
    let reg = RegistrationS { id_s: secret.id_s.clone(), rows: secret.rows.clone(), pi_pow: secret.pi_pow.clone() };
    to_bytes(&SenderRegistrationWire { version: WIRE_VERSION, m: m as u64, n_g: n_g as u64, reg })
}

impl SenderParty {
    // Registration_S of distinct items under id_s
    pub fn register<R: RngCore>(id_s: &[u8], items: &[Vec<u8>], n_g: usize, rng: &mut R) -> PartyResult<Self> {
        check_id(id_s, "id_S")?;
        if items.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "Sender set must be non-empty"));
        }
        let m = items.len();
        let pp = sender_pp(m, n_g)?;
        let (_reg, secret) = registration_s::<Backend, _>(&pp, id_s, items, rng)?;
        let registration = sender_registration(&secret, m, n_g);
        Ok(SenderParty { secret, m, n_g, registration, tokens: Default::default() })
    }

    pub fn m(&self) -> usize {
        self.m
    }

    pub fn n_g(&self) -> usize {
        self.n_g
    }

    // encoded public registration
    pub fn registration(&self) -> &[u8] {
        &self.registration
    }

    // precomputes count token batches with pi_tok, respond takes one each
    pub fn precompute_tokens<R: RngCore>(&self, count: usize, rng: &mut R) -> PartyResult<()> {
        let pp = sender_pp(self.m, self.n_g)?;
        for _ in 0..count {
            let b = precompute_tokens::<Backend, _>(&pp, &self.secret, rng)?;
            self.tokens.lock().expect("token pool").push(b);
        }
        Ok(())
    }

    // precomputed token batches not used yet
    pub fn tokens_available(&self) -> usize {
        self.tokens.lock().expect("token pool").len()
    }

    // secret state for persistence: power-row openings and the set, without the token pool
    pub fn export_secret(&self) -> Vec<u8> {
        let s = &self.secret;
        let w = SenderSecretWire {
            version: WIRE_VERSION,
            m: self.m as u64,
            n_g: self.n_g as u64,
            id_s: s.id_s.clone(),
            elements: s.elements.clone(),
            rows: s.rows.clone(),
            powers: s.rows_secret.powers.clone(),
            blinds: s.rows_secret.blinds.clone(),
            pi_pow: s.pi_pow.clone(),
        };
        to_bytes(&w)
    }

    // rebuild from export_secret output, with an empty token pool
    pub fn import_secret(bytes: &[u8]) -> PartyResult<Self> {
        let w: SenderSecretWire = decode(bytes, "sender secret")?;
        check_version(w.version, WIRE_VERSION, "sender secret")?;
        let (m, n_g) = (w.m as usize, w.n_g as usize);
        // registered rows Z_1..Z_S and Z_g
        let n_rows = if m == 0 || n_g < 8 { 0 } else { party_params(m, 1, n_g)?.n_rows() };
        if m == 0
            || w.elements.len() != m
            || n_g < 8
            || w.rows.len() != n_rows
            || w.powers.len() != n_rows
            || w.blinds.len() != n_rows
            || w.powers.iter().any(|p| p.len() != m)
            || w.id_s.is_empty()
            || w.id_s.len() > MAX_ID_LEN
        {
            return Err(malformed("sender secret (sizes)"));
        }
        let z = check_distinct(&w.elements)?;
        if w.powers[0] != z {
            return Err(malformed("sender secret (first power row is not H1 of the set)"));
        }
        let secret = SenderSecret {
            id_s: w.id_s.clone(),
            elements: w.elements.clone(),
            z,
            rows: w.rows.clone(),
            rows_secret: PowerRowsSecret { powers: w.powers.clone(), blinds: w.blinds.clone() },
            pi_pow: w.pi_pow.clone(),
        };
        let registration = sender_registration(&secret, m, n_g);
        sender_pp(m, n_g)?;
        Ok(SenderParty { secret, m, n_g, registration, tokens: Default::default() })
    }

    // PairSetup_S and Intersection_S for session sid, with a precomputed token batch if there is one
    pub fn respond<R: RngCore>(
        &self,
        receiver_registration: &[u8],
        sid: &[u8],
        rng: &mut R,
    ) -> PartyResult<(Vec<u8>, Timings)> {
        let start = Instant::now();
        let mut t = Timings::default();

        let s = Instant::now();
        let rr: ReceiverRegistrationWire = decode(receiver_registration, "receiver registration")?;
        check_version(rr.version, WIRE_VERSION, "receiver registration")?;
        check_same_n_g("Receiver", rr.n_g as usize, "Sender", self.n_g)?;
        check_peer_id(&rr.reg.id_r, "receiver registration (id_R)")?;
        let key_len = rr.reg.pk_r.len();
        let n = n_of_key(&rr.reg.pk_r).ok_or_else(|| malformed("receiver registration (pk_R length)"))?;
        let pp = run_pp(self.m, n, self.n_g, key_len)?;
        t.decode_ns = ns(s);

        let pooled = self.tokens.lock().expect("token pool").pop();
        let bundle = match pooled {
            Some(b) => b,
            None => {
                let st = Instant::now();
                let b = precompute_tokens::<Backend, _>(&pp, &self.secret, rng)?;
                t.tokens_ns = ns(st);
                b
            }
        };
        let s = Instant::now();
        let (msg_pair, mut state) = pair_setup_s_with::<Backend, _>(&pp, &self.secret, &rr.reg, Some(bundle), rng)?;
        t.pair_setup_ns = ns(s);

        let s = Instant::now();
        let intersection = intersection_s(sid, &mut state, rng);
        t.intersection_ns = ns(s);

        let s = Instant::now();
        let out = to_bytes(&SenderResponseWire { version: WIRE_VERSION, msg_pair, intersection });
        t.encode_ns = ns(s);
        t.total_ns = ns(start);
        Ok((out, t))
    }
}

// receiver

// sender registration whose pi_pow verified, plus the run's public params
pub struct VerifiedSenderRegistration {
    pp: PublicParams,
    verified: spicy::protocol::registration::VerifiedSender,
}

pub struct ReceiverParty {
    secret: ReceiverSecret,
    n_g: usize,
    registration: Vec<u8>,
}

fn receiver_registration(secret: &ReceiverSecret, n_g: usize) -> Vec<u8> {
    let reg = RegistrationR { id_r: secret.id_r.clone(), pk_r: secret.pk_r.clone() };
    to_bytes(&ReceiverRegistrationWire { version: WIRE_VERSION, n_g: n_g as u64, reg })
}

impl ReceiverParty {
    // Registration_R of distinct items under id_r, needs n_g >= 4(N+1)
    pub fn register<R: RngCore>(id_r: &[u8], items: &[Vec<u8>], n_g: usize, rng: &mut R) -> PartyResult<Self> {
        check_id(id_r, "id_R")?;
        if items.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "Receiver set must be non-empty"));
        }
        let n = items.len();
        // M does not enter Registration_R
        let pp = setup_cached(&party_params(1, n, n_g)?)?;
        let (_reg, secret) = registration_r(&pp, id_r, items, rng)?;
        let registration = receiver_registration(&secret, n_g);
        Ok(ReceiverParty { secret, n_g, registration })
    }

    pub fn n(&self) -> usize {
        self.secret.elements.len()
    }

    pub fn n_g(&self) -> usize {
        self.n_g
    }

    // encoded public registration
    pub fn registration(&self) -> &[u8] {
        &self.registration
    }

    // secret state for persistence: sk_R and the set
    pub fn export_secret(&self) -> Vec<u8> {
        let s = &self.secret;
        to_bytes(&ReceiverSecretWire {
            version: WIRE_VERSION,
            n_g: self.n_g as u64,
            id_r: s.id_r.clone(),
            pk_r: s.pk_r.clone(),
            rho: s.sk_r.rho.clone(),
            elements: s.elements.clone(),
        })
    }

    // rebuild from export_secret output
    pub fn import_secret(bytes: &[u8]) -> PartyResult<Self> {
        let w: ReceiverSecretWire = decode(bytes, "receiver secret")?;
        check_version(w.version, WIRE_VERSION, "receiver secret")?;
        let n = w.elements.len();
        let n_g = w.n_g as usize;
        if n == 0
            || w.rho.len() != n
            || w.pk_r.len() != 4 * (n + 1)
            || n_g < 4 * (n + 1)
            || w.id_r.is_empty()
            || w.id_r.len() > MAX_ID_LEN
        {
            return Err(malformed("receiver secret (sizes)"));
        }
        check_distinct(&w.elements)?;
        let secret = ReceiverSecret {
            id_r: w.id_r.clone(),
            w_r: w_r(&w.id_r),
            pk_r: w.pk_r.clone(),
            sk_r: SkR { rho: w.rho.clone() },
            elements: w.elements.clone(),
        };
        let registration = receiver_registration(&secret, n_g);
        Ok(ReceiverParty { secret, n_g, registration })
    }

    // verifies the sender registration and response for sid
    // returns the ascending indices of our items in the intersection
    // max_m and max_n_g cap the sender's M and n_g
    pub fn finish(
        &self,
        sender_registration: &[u8],
        response: &[u8],
        sid: &[u8],
        max_m: usize,
        max_n_g: usize,
    ) -> PartyResult<(Vec<usize>, Timings)> {
        let start = Instant::now();
        let (sender, mut t) = self.verify_sender(sender_registration, max_m, max_n_g)?;
        let (idx, t2) = self.finish_verified(&sender, response, sid)?;
        t.pair_setup_ns = t2.pair_setup_ns;
        t.intersection_ns = t2.intersection_ns;
        t.decode_ns += t2.decode_ns;
        t.encode_ns = t2.encode_ns;
        t.total_ns = ns(start);
        Ok((idx, t))
    }

    // first part of finish: decoding, policy checks, verifying pi_pow
    // can run while the sender is still computing its response
    pub fn verify_sender(
        &self,
        sender_registration: &[u8],
        max_m: usize,
        max_n_g: usize,
    ) -> PartyResult<(VerifiedSenderRegistration, Timings)> {
        let start = Instant::now();
        let mut t = Timings::default();

        let s = Instant::now();
        let sr: SenderRegistrationWire = decode(sender_registration, "sender registration")?;
        check_version(sr.version, WIRE_VERSION, "sender registration")?;
        let (m, n_g) = (sr.m as usize, sr.n_g as usize);
        check_sender_sizes(m, n_g, max_m, max_n_g, self.n_g)?;
        check_peer_id(&sr.reg.id_s, "sender registration (id_S)")?;
        let pp = run_pp(m, self.n(), n_g, self.secret.pk_r.len())?;
        t.decode_ns = ns(s);

        let s = Instant::now();
        let verified = verify_registration_s::<Backend>(&pp, &sr.reg)?;
        t.verify_registration_ns = ns(s);
        t.total_ns = ns(start);
        Ok((VerifiedSenderRegistration { pp, verified }, t))
    }

    // rest of finish after verify_sender: PairSetup_R and Intersection_R
    pub fn finish_verified(
        &self,
        sender: &VerifiedSenderRegistration,
        response: &[u8],
        sid: &[u8],
    ) -> PartyResult<(Vec<usize>, Timings)> {
        let start = Instant::now();
        let mut t = Timings::default();
        let pp = &sender.pp;

        let s = Instant::now();
        let resp: SenderResponseWire = decode(response, "sender response")?;
        check_version(resp.version, WIRE_VERSION, "sender response")?;
        t.decode_ns = ns(s);

        let s = Instant::now();
        let state = pair_setup_r::<Backend>(pp, &sender.verified, &resp.msg_pair, &self.secret)?;
        t.pair_setup_ns = ns(s);

        let s = Instant::now();
        let out = intersection_r(pp, sid, &state, &self.secret, &resp.intersection)?;
        t.intersection_ns = ns(s);

        let s = Instant::now();
        let idx = indices_of(&self.secret.elements, &out)?;
        t.encode_ns = ns(s);
        t.total_ns = ns(start);
        Ok((idx, t))
    }
}

// handles are shared between threads
#[allow(dead_code)]
fn _assert_send_sync() {
    fn is<T: Send + Sync>() {}
    is::<SenderParty>();
    is::<ReceiverParty>();
}
