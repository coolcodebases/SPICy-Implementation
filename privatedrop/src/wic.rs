// safe rust layer between the c api and spicy_ws (spicy wic), framed like the cic layer in party.rs
// the receiver sends (id_R, pk_R)
// the sender replies with its registration, msg_pair and the intersection message
// every exchange does a fresh pair setup and keeps no pair state
// privatedrop's sid is hashed to the protocol's 16-byte sid
// the receiver checks that the intersection message carries it

use std::time::Instant;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use spicy_ws::encoding::psi_encoding::{PkR, NPOLYS};
use spicy_ws::error::{AbortReason, SpicyError};
use spicy_ws::leaves::{leaf, Nonce};
use spicy_ws::oprf::{check_distinct, SkR};
use spicy_ws::params::{mask_len, setup, w_r, Params, PublicParams, DEFAULT_STAT_BITS};
use spicy_ws::protocol::messages::{IntersectionMsg, MsgPair, RegistrationR, RegistrationS, SID_BYTES};
use spicy_ws::protocol::pair_setup::enc_fp;
use spicy_ws::protocol::{
    intersection_r, intersection_s_with_sid, pair_setup_r, pair_setup_s, registration_r, registration_s,
    verify_registration_s, ReceiverSecret, SenderSecret,
};
use spicy_ws::serialize::to_bytes;
use spicy_ws::types::Fq0;

use crate::party::{
    check_id, check_peer_id, check_same_n_g, check_sender_sizes, decode, indices_of, malformed, ns, Error, ErrorKind,
    PartyResult, Timings, MAX_ID_LEN,
};

// version byte at the start of every wic wire and secret encoding
// it differs from the cic version byte
pub const WIC_WIRE_VERSION: u8 = 0x51;

impl From<SpicyError> for Error {
    fn from(e: SpicyError) -> Self {
        let kind = match &e {
            SpicyError::Abort(AbortReason::MalformedMessage(_)) => ErrorKind::Malformed,
            SpicyError::Abort(_) => ErrorKind::ProtocolAbort,
            SpicyError::Params(_) | SpicyError::Input(_) => ErrorKind::InvalidInput,
            SpicyError::Serialization(_) => ErrorKind::Malformed,
            SpicyError::SamplingFailed => ErrorKind::Internal,
        };
        Error::new(kind, e.to_string())
    }
}

fn check_version(v: u8, what: &str) -> PartyResult<()> {
    crate::party::check_version(v, WIC_WIRE_VERSION, what)
}

// the protocol's 16-byte sid for privatedrop session id sid
pub fn protocol_sid(sid: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"PrivateDrop/SPICy-WIC/sid");
    h.update(sid);
    h.finalize()[..SID_BYTES].to_vec()
}

// recommended n_g for up to max_m / max_n elements, None if a size is 0
pub fn recommended_n_g(max_m: usize, max_n: usize) -> Option<usize> {
    (max_m > 0 && max_n > 0).then(|| mask_len(max_n, max_m, DEFAULT_STAT_BITS))
}

// pp for (M, N) under n_g
// aborts if 4(N+1) > n_g, and refuses sizes that need a longer mask
fn run_pp(m: usize, n: usize, n_g: usize) -> PartyResult<PublicParams> {
    if 4 * (n + 1) > n_g {
        return Err(SpicyError::abort(AbortReason::DegreeTooLarge { len: n + 1, max: n_g / 4 }).into());
    }
    let need = mask_len(n, m, DEFAULT_STAT_BITS);
    if n_g < need {
        return Err(Error::new(
            ErrorKind::Policy,
            format!("n_g = {n_g} is below the {need} needed for M = {m}, N = {n} at 128-bit statistical security"),
        ));
    }
    Ok(setup(&Params::with_mask_len(m, n, n_g)?)?)
}

// N of a receiver key, if it is four polys of N+1 coeffs
fn n_of_key(pk_r: &PkR) -> Option<usize> {
    let len = pk_r.polys.first()?.len();
    (pk_r.polys.len() == NPOLYS && len >= 2 && pk_r.polys.iter().all(|p| p.len() == len)).then(|| len - 1)
}

// wire messages

// sender registration (id_S and the M leaves) plus the sizes the receiver needs to rebuild pp
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct WicSenderRegistrationWire {
    pub version: u8,
    pub m: u64,
    pub n_g: u64,
    pub reg: RegistrationS,
}

// receiver registration (id_R, pk_R) and its n_g
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct WicReceiverRegistrationWire {
    pub version: u8,
    pub n_g: u64,
    pub reg: RegistrationR,
}

// sender's reply: msg_pair and the intersection message
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct WicSenderResponseWire {
    pub version: u8,
    pub msg_pair: MsgPair,
    pub intersection: IntersectionMsg,
}

// persisted secret state, wiped on drop

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct WicSenderSecretWire {
    version: u8,
    m: u64,
    n_g: u64,
    id_s: Vec<u8>,
    // elements in slot order
    elements: Vec<Vec<u8>>,
    // registration nonces r_j
    r: Vec<Nonce>,
}

impl Drop for WicSenderSecretWire {
    fn drop(&mut self) {
        self.elements.zeroize();
        self.r.iter_mut().for_each(|r| r.zeroize());
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct WicReceiverSecretWire {
    version: u8,
    n_g: u64,
    id_r: Vec<u8>,
    pk_r: PkR,
    rho: Vec<Fq0>,
    elements: Vec<Vec<u8>>,
}

impl Drop for WicReceiverSecretWire {
    fn drop(&mut self) {
        self.rho.zeroize();
        self.elements.zeroize();
    }
}

// sender

pub struct WicSenderParty {
    secret: SenderSecret,
    m: usize,
    n_g: usize,
    registration: Vec<u8>,
}

impl Drop for WicSenderParty {
    fn drop(&mut self) {
        self.secret.elements.zeroize();
        self.secret.r.iter_mut().for_each(|r| r.zeroize());
    }
}

fn sender_pp(m: usize, n_g: usize) -> PartyResult<PublicParams> {
    Ok(setup(&Params::with_mask_len(m, 1, n_g)?)?)
}

fn sender_registration(secret: &SenderSecret, m: usize, n_g: usize) -> Vec<u8> {
    let reg = RegistrationS { id_s: secret.id_s.clone(), leaves: secret.leaves.clone() };
    to_bytes(&WicSenderRegistrationWire { version: WIC_WIRE_VERSION, m: m as u64, n_g: n_g as u64, reg })
}

impl WicSenderParty {
    // Registration_S of distinct items under id_s
    pub fn register<R: RngCore + CryptoRng>(id_s: &[u8], items: &[Vec<u8>], n_g: usize, rng: &mut R) -> PartyResult<Self> {
        check_id(id_s, "id_S")?;
        if items.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "Sender set must be non-empty"));
        }
        let m = items.len();
        let pp = sender_pp(m, n_g)?;
        let (_, secret) = registration_s(&pp, id_s, items, rng)?;
        let registration = sender_registration(&secret, m, n_g);
        Ok(WicSenderParty { secret, m, n_g, registration })
    }

    pub fn m(&self) -> usize {
        self.m
    }

    pub fn n_g(&self) -> usize {
        self.n_g
    }

    pub fn registration(&self) -> &[u8] {
        &self.registration
    }

    // secret state for persistence
    pub fn export_secret(&self) -> Vec<u8> {
        let s = &self.secret;
        to_bytes(&WicSenderSecretWire {
            version: WIC_WIRE_VERSION,
            m: self.m as u64,
            n_g: self.n_g as u64,
            id_s: s.id_s.clone(),
            elements: s.elements.clone(),
            r: s.r.clone(),
        })
    }

    // rebuild a sender from export_secret output, the leaves are recomputed
    pub fn import_secret(bytes: &[u8]) -> PartyResult<Self> {
        let w: WicSenderSecretWire = decode(bytes, "WIC sender secret")?;
        check_version(w.version, "WIC sender secret")?;
        let (m, n_g) = (w.m as usize, w.n_g as usize);
        if m == 0 || w.elements.len() != m || w.r.len() != m || n_g < 8 || w.id_s.is_empty() || w.id_s.len() > MAX_ID_LEN {
            return Err(malformed("WIC sender secret (sizes)"));
        }
        sender_pp(m, n_g)?;
        let z = check_distinct(&w.elements)?;
        let leaves = (0..m).map(|j| leaf(&w.id_s, j, &enc_fp(&z[j]), &w.r[j])).collect();
        let secret = SenderSecret { id_s: w.id_s.clone(), elements: w.elements.clone(), z, r: w.r.clone(), leaves };
        let registration = sender_registration(&secret, m, n_g);
        Ok(WicSenderParty { secret, m, n_g, registration })
    }

    // PairSetup_S and Intersection_S for the receiver's registration and session sid
    pub fn respond<R: RngCore + CryptoRng>(
        &self,
        receiver_registration: &[u8],
        sid: &[u8],
        rng: &mut R,
    ) -> PartyResult<(Vec<u8>, Timings)> {
        let start = Instant::now();
        let mut t = Timings::default();

        let s = Instant::now();
        let rr: WicReceiverRegistrationWire = decode(receiver_registration, "WIC receiver registration")?;
        check_version(rr.version, "WIC receiver registration")?;
        check_same_n_g("Receiver", rr.n_g as usize, "Sender", self.n_g)?;
        check_peer_id(&rr.reg.id_r, "WIC receiver registration (id_R)")?;
        let n = n_of_key(&rr.reg.pk_r).ok_or_else(|| malformed("WIC receiver registration (pk_R shape)"))?;
        let pp = run_pp(self.m, n, self.n_g)?;
        t.decode_ns = ns(s);

        let s = Instant::now();
        let (msg_pair, state) = pair_setup_s(&pp, &self.secret, &rr.reg, rng)?;
        t.pair_setup_ns = ns(s);

        let s = Instant::now();
        let intersection = intersection_s_with_sid(&protocol_sid(sid), &state);
        t.intersection_ns = ns(s);

        let s = Instant::now();
        let out = to_bytes(&WicSenderResponseWire { version: WIC_WIRE_VERSION, msg_pair, intersection });
        t.encode_ns = ns(s);
        t.total_ns = ns(start);
        Ok((out, t))
    }
}

// receiver

pub struct WicReceiverParty {
    secret: ReceiverSecret,
    n_g: usize,
    registration: Vec<u8>,
}

impl Drop for WicReceiverParty {
    fn drop(&mut self) {
        self.secret.sk_r.rho.zeroize();
        self.secret.elements.zeroize();
    }
}

fn receiver_registration(secret: &ReceiverSecret, n_g: usize) -> Vec<u8> {
    let reg = RegistrationR { id_r: secret.id_r.clone(), pk_r: secret.pk_r.clone() };
    to_bytes(&WicReceiverRegistrationWire { version: WIC_WIRE_VERSION, n_g: n_g as u64, reg })
}

impl WicReceiverParty {
    // Registration_R of distinct items under id_r, needs 4(N+1) <= n_g
    pub fn register<R: RngCore + CryptoRng>(id_r: &[u8], items: &[Vec<u8>], n_g: usize, rng: &mut R) -> PartyResult<Self> {
        check_id(id_r, "id_R")?;
        if items.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "Receiver set must be non-empty"));
        }
        let n = items.len();
        // Registration_R does not use M, so M = 1
        let pp = setup(&Params::with_mask_len(1, n, n_g)?)?;
        let (_, secret) = registration_r(&pp, id_r, items, rng)?;
        let registration = receiver_registration(&secret, n_g);
        Ok(WicReceiverParty { secret, n_g, registration })
    }

    pub fn n(&self) -> usize {
        self.secret.elements.len()
    }

    pub fn n_g(&self) -> usize {
        self.n_g
    }

    pub fn registration(&self) -> &[u8] {
        &self.registration
    }

    // secret state for persistence
    pub fn export_secret(&self) -> Vec<u8> {
        let s = &self.secret;
        to_bytes(&WicReceiverSecretWire {
            version: WIC_WIRE_VERSION,
            n_g: self.n_g as u64,
            id_r: s.id_r.clone(),
            pk_r: s.pk_r.clone(),
            rho: s.sk_r.rho.clone(),
            elements: s.elements.clone(),
        })
    }

    // rebuild a receiver from export_secret output
    pub fn import_secret(bytes: &[u8]) -> PartyResult<Self> {
        let w: WicReceiverSecretWire = decode(bytes, "WIC receiver secret")?;
        check_version(w.version, "WIC receiver secret")?;
        let n_g = w.n_g as usize;
        let n = w.elements.len();
        if n == 0
            || w.rho.len() != n
            || n_of_key(&w.pk_r) != Some(n)
            || 4 * (n + 1) > n_g
            || w.id_r.is_empty()
            || w.id_r.len() > MAX_ID_LEN
        {
            return Err(malformed("WIC receiver secret (sizes)"));
        }
        let z = check_distinct(&w.elements)?;
        let secret = ReceiverSecret {
            id_r: w.id_r.clone(),
            w_r: w_r(&w.id_r),
            pk_r: w.pk_r.clone(),
            sk_r: SkR { rho: w.rho.clone() },
            elements: w.elements.clone(),
            z,
        };
        let registration = receiver_registration(&secret, n_g);
        Ok(WicReceiverParty { secret, n_g, registration })
    }

    // verifies the sender's registration and response for session sid
    // returns the ascending indices of our items in the output
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
        let mut t = Timings::default();

        let s = Instant::now();
        let sr: WicSenderRegistrationWire = decode(sender_registration, "WIC sender registration")?;
        check_version(sr.version, "WIC sender registration")?;
        let resp: WicSenderResponseWire = decode(response, "WIC sender response")?;
        check_version(resp.version, "WIC sender response")?;
        let (m, n_g) = (sr.m as usize, sr.n_g as usize);
        check_sender_sizes(m, n_g, max_m, max_n_g, self.n_g)?;
        check_peer_id(&sr.reg.id_s, "WIC sender registration (id_S)")?;
        if resp.intersection.sid != protocol_sid(sid) {
            return Err(Error::new(ErrorKind::ProtocolAbort, "WIC intersection message is for another session"));
        }
        let pp = run_pp(m, self.n(), n_g)?;
        t.decode_ns = ns(s);

        let s = Instant::now();
        let verified = verify_registration_s(&pp, &sr.reg)?;
        t.verify_registration_ns = ns(s);

        let s = Instant::now();
        let state = pair_setup_r(&pp, &verified, &resp.msg_pair, &self.secret)?;
        t.pair_setup_ns = ns(s);

        let s = Instant::now();
        let out = intersection_r(&pp, &state, &self.secret, &resp.intersection)?;
        t.intersection_ns = ns(s);

        let s = Instant::now();
        let idx = indices_of(&self.secret.elements, &out.int)?;
        t.encode_ns = ns(s);
        t.total_ns = ns(start);
        Ok((idx, t))
    }
}
