// c api for privatedrop's swift code, declared in include/spicy_ffi.h
// i32 functions return SPICY_OK or an error code, panics give SPICY_ERR_PANIC
// on error a non-null err gets a utf-8 message, free it with spicy_buffer_free
// handles are opaque and thread-safe, their secrets are wiped on free
// ids are 1..1024 bytes and both sides need the same n_g

#![allow(clippy::missing_safety_doc)]

pub mod party;
pub mod wic;
mod wic_ffi;
pub use wic_ffi::*;

use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use zeroize::Zeroize;

use party::{Error, ErrorKind, ReceiverParty, SenderParty, Timings};

pub const SPICY_OK: i32 = 0;

// owned byte buffer returned by rust
#[repr(C)]
pub struct SpicyBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

impl SpicyBuffer {
    const fn empty() -> Self {
        SpicyBuffer { ptr: ptr::null_mut(), len: 0 }
    }

    fn from_vec(v: Vec<u8>) -> Self {
        if v.is_empty() {
            return Self::empty();
        }
        let b = v.into_boxed_slice();
        let len = b.len();
        SpicyBuffer { ptr: Box::into_raw(b) as *mut u8, len }
    }
}

// owned index list returned by rust
#[repr(C)]
pub struct SpicyIndexList {
    pub ptr: *mut u64,
    pub len: usize,
}

impl SpicyIndexList {
    fn from_indices(idx: Vec<usize>) -> Self {
        if idx.is_empty() {
            return SpicyIndexList { ptr: ptr::null_mut(), len: 0 };
        }
        let b: Box<[u64]> = idx.into_iter().map(|i| i as u64).collect();
        let len = b.len();
        SpicyIndexList { ptr: Box::into_raw(b) as *mut u64, len }
    }
}

// set of byte-string items: data holds them back to back, lengths[i] is item i's length, lengths sum to data_len
#[repr(C)]
pub struct SpicyItems {
    pub data: *const u8,
    pub data_len: usize,
    pub lengths: *const usize,
    pub count: usize,
}

// time spent inside rust per step, in ns
#[repr(C)]
#[derive(Default)]
pub struct SpicyTimings {
    pub total_ns: u64,
    pub decode_ns: u64,
    pub verify_registration_ns: u64,
    pub pair_setup_ns: u64,
    pub intersection_ns: u64,
    pub encode_ns: u64,
    pub tokens_ns: u64,
}

impl From<Timings> for SpicyTimings {
    fn from(t: Timings) -> Self {
        SpicyTimings {
            total_ns: t.total_ns,
            decode_ns: t.decode_ns,
            verify_registration_ns: t.verify_registration_ns,
            pair_setup_ns: t.pair_setup_ns,
            intersection_ns: t.intersection_ns,
            encode_ns: t.encode_ns,
            tokens_ns: t.tokens_ns,
        }
    }
}

// opaque sender handle
pub struct SpicySender(SenderParty);
// opaque receiver handle
pub struct SpicyReceiver(ReceiverParty);

// helpers

fn invalid(msg: &str) -> Error {
    Error::new(ErrorKind::InvalidArgument, msg)
}

// runs f, turns errors and panics into a status code plus optional message
fn guard<F: FnOnce() -> Result<(), Error>>(err: *mut SpicyBuffer, f: F) -> i32 {
    let res = catch_unwind(AssertUnwindSafe(f));
    let e = match res {
        Ok(Ok(())) => return SPICY_OK,
        Ok(Err(e)) => e,
        Err(p) => {
            let msg = p
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| p.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".into());
            Error::new(ErrorKind::Panic, format!("panic in spicy-ffi: {msg}"))
        }
    };
    if !err.is_null() {
        unsafe { *err = SpicyBuffer::from_vec(e.message.into_bytes()) };
    }
    e.kind as i32
}

unsafe fn bytes<'a>(p: *const u8, len: usize, what: &str) -> Result<&'a [u8], Error> {
    if len == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(invalid(&format!("{what} is null")));
    }
    Ok(std::slice::from_raw_parts(p, len))
}

unsafe fn items(it: &SpicyItems) -> Result<Vec<Vec<u8>>, Error> {
    if it.count == 0 {
        return Ok(Vec::new());
    }
    if it.lengths.is_null() {
        return Err(invalid("items.lengths is null"));
    }
    let lens = std::slice::from_raw_parts(it.lengths, it.count);
    let total = lens.iter().try_fold(0usize, |a, l| a.checked_add(*l)).ok_or_else(|| invalid("item lengths overflow"))?;
    if total != it.data_len {
        return Err(invalid("item lengths do not sum to data_len"));
    }
    let data = bytes(it.data, it.data_len, "items.data")?;
    let mut out = Vec::with_capacity(it.count);
    let mut off = 0;
    for l in lens {
        out.push(data[off..off + l].to_vec());
        off += l;
    }
    Ok(out)
}

unsafe fn put_buffer(out: *mut SpicyBuffer, v: Vec<u8>) -> Result<(), Error> {
    if out.is_null() {
        return Err(invalid("output buffer pointer is null"));
    }
    *out = SpicyBuffer::from_vec(v);
    Ok(())
}

unsafe fn handle<'a, T>(p: *const T, what: &str) -> Result<&'a T, Error> {
    p.as_ref().ok_or_else(|| invalid(&format!("{what} handle is null")))
}

// session id argument, must be non-empty
unsafe fn sid_bytes<'a>(p: *const u8, len: usize) -> Result<&'a [u8], Error> {
    let sid = bytes(p, len, "sid")?;
    if sid.is_empty() {
        return Err(invalid("sid must be non-empty"));
    }
    Ok(sid)
}

// fails before any work if an output pointer is null
fn check_out<T>(out: *mut T) -> Result<(), Error> {
    if out.is_null() {
        return Err(invalid("out is null"));
    }
    Ok(())
}

// moves v into a new handle at *out, out must be non-null
unsafe fn put_handle<T>(out: *mut *mut T, v: T) {
    *out = Box::into_raw(Box::new(v));
}

unsafe fn put_timings(timings: *mut SpicyTimings, t: Timings) {
    if !timings.is_null() {
        *timings = t.into();
    }
}

// library info and memory

// static nul-terminated version string, do not free
#[no_mangle]
pub extern "C" fn spicy_version() -> *const c_char {
    concat!("spicy-ffi ", env!("CARGO_PKG_VERSION"), " wire 3\0").as_ptr() as *const c_char
}

// wipes and frees a buffer from this library; null or empty buffers are ignored
#[no_mangle]
pub unsafe extern "C" fn spicy_buffer_free(buf: SpicyBuffer) {
    if buf.ptr.is_null() || buf.len == 0 {
        return;
    }
    let mut b = Box::from_raw(ptr::slice_from_raw_parts_mut(buf.ptr, buf.len));
    b.zeroize();
}

// recommended n_g for up to max_m / max_n elements; returns 0 if a size is 0
#[no_mangle]
pub extern "C" fn spicy_recommended_n_g(max_m: usize, max_n: usize) -> usize {
    catch_unwind(|| party::recommended_n_g(max_m, max_n).unwrap_or(0)).unwrap_or(0)
}

// frees an index list from this library; null or empty lists are ignored
#[no_mangle]
pub unsafe extern "C" fn spicy_index_list_free(list: SpicyIndexList) {
    if list.ptr.is_null() || list.len == 0 {
        return;
    }
    drop(Box::from_raw(ptr::slice_from_raw_parts_mut(list.ptr, list.len)));
}

// sender

// Registration_S of items under id
// new handle in *out, free with spicy_sender_free
#[no_mangle]
pub unsafe extern "C" fn spicy_sender_register(
    items_in: SpicyItems,
    id: *const u8,
    id_len: usize,
    n_g: usize,
    out: *mut *mut SpicySender,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || {
        check_out(out)?;
        let id = bytes(id, id_len, "id")?;
        let xs = items(&items_in)?;
        let p = SenderParty::register(id, &xs, n_g, &mut party::fresh_rng())?;
        put_handle(out, SpicySender(p));
        Ok(())
    })
}

// rebuilds a sender from export_secret output into a new handle *out
#[no_mangle]
pub unsafe extern "C" fn spicy_sender_import(
    secret: *const u8,
    secret_len: usize,
    out: *mut *mut SpicySender,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || {
        check_out(out)?;
        let p = SenderParty::import_secret(bytes(secret, secret_len, "secret")?)?;
        put_handle(out, SpicySender(p));
        Ok(())
    })
}

// writes the sender's public registration to out, free with spicy_buffer_free
#[no_mangle]
pub unsafe extern "C" fn spicy_sender_registration(
    s: *const SpicySender,
    out: *mut SpicyBuffer,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || put_buffer(out, handle(s, "sender")?.0.registration().to_vec()))
}

// writes the secret state to out for persistence, free with spicy_buffer_free
#[no_mangle]
pub unsafe extern "C" fn spicy_sender_export_secret(
    s: *const SpicySender,
    out: *mut SpicyBuffer,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || put_buffer(out, handle(s, "sender")?.0.export_secret()))
}

// M, or 0 if s is null
#[no_mangle]
pub unsafe extern "C" fn spicy_sender_m(s: *const SpicySender) -> usize {
    s.as_ref().map_or(0, |s| s.0.m())
}

// n_g, or 0 if s is null
#[no_mangle]
pub unsafe extern "C" fn spicy_sender_n_g(s: *const SpicySender) -> usize {
    s.as_ref().map_or(0, |s| s.0.n_g())
}

// precomputes count token batches with pi_tok
// each spicy_sender_respond uses one
#[no_mangle]
pub unsafe extern "C" fn spicy_sender_precompute_tokens(s: *const SpicySender, count: usize, err: *mut SpicyBuffer) -> i32 {
    guard(err, || handle(s, "sender")?.0.precompute_tokens(count, &mut party::fresh_rng()))
}

// number of unused precomputed token batches
#[no_mangle]
pub unsafe extern "C" fn spicy_sender_tokens_available(s: *const SpicySender) -> usize {
    s.as_ref().map_or(0, |s| s.0.tokens_available())
}

// PairSetup_S and Intersection_S for receiver_reg and a non-empty sid
// uses a precomputed token batch or builds one
// writes the response to out, free with spicy_buffer_free; timings may be null
#[no_mangle]
pub unsafe extern "C" fn spicy_sender_respond(
    s: *const SpicySender,
    receiver_reg: *const u8,
    receiver_reg_len: usize,
    sid: *const u8,
    sid_len: usize,
    out: *mut SpicyBuffer,
    timings: *mut SpicyTimings,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || {
        let s = handle(s, "sender")?;
        let rr = bytes(receiver_reg, receiver_reg_len, "receiver_reg")?;
        let sid = sid_bytes(sid, sid_len)?;
        let (resp, t) = s.0.respond(rr, sid, &mut party::fresh_rng())?;
        put_timings(timings, t);
        put_buffer(out, resp)
    })
}

// frees a sender and wipes its secrets
#[no_mangle]
pub unsafe extern "C" fn spicy_sender_free(s: *mut SpicySender) {
    if !s.is_null() {
        drop(Box::from_raw(s));
    }
}

// receiver

// Registration_R of items under id, needs 4(N+1) <= n_g
// new handle in *out, free with spicy_receiver_free
#[no_mangle]
pub unsafe extern "C" fn spicy_receiver_register(
    items_in: SpicyItems,
    id: *const u8,
    id_len: usize,
    n_g: usize,
    out: *mut *mut SpicyReceiver,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || {
        check_out(out)?;
        let id = bytes(id, id_len, "id")?;
        let ys = items(&items_in)?;
        let p = ReceiverParty::register(id, &ys, n_g, &mut party::fresh_rng())?;
        put_handle(out, SpicyReceiver(p));
        Ok(())
    })
}

// rebuilds a receiver from export_secret output into a new handle *out
#[no_mangle]
pub unsafe extern "C" fn spicy_receiver_import(
    secret: *const u8,
    secret_len: usize,
    out: *mut *mut SpicyReceiver,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || {
        check_out(out)?;
        let p = ReceiverParty::import_secret(bytes(secret, secret_len, "secret")?)?;
        put_handle(out, SpicyReceiver(p));
        Ok(())
    })
}

// writes the receiver's public registration to out, free with spicy_buffer_free
#[no_mangle]
pub unsafe extern "C" fn spicy_receiver_registration(
    r: *const SpicyReceiver,
    out: *mut SpicyBuffer,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || put_buffer(out, handle(r, "receiver")?.0.registration().to_vec()))
}

// writes the secret state to out for persistence, free with spicy_buffer_free
#[no_mangle]
pub unsafe extern "C" fn spicy_receiver_export_secret(
    r: *const SpicyReceiver,
    out: *mut SpicyBuffer,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || put_buffer(out, handle(r, "receiver")?.0.export_secret()))
}

// N, or 0 if r is null
#[no_mangle]
pub unsafe extern "C" fn spicy_receiver_n(r: *const SpicyReceiver) -> usize {
    r.as_ref().map_or(0, |r| r.0.n())
}

// n_g, or 0 if r is null
#[no_mangle]
pub unsafe extern "C" fn spicy_receiver_n_g(r: *const SpicyReceiver) -> usize {
    r.as_ref().map_or(0, |r| r.0.n_g())
}

// verifies the sender registration and response for sid
// writes the ascending indices of our items in the intersection to out, free with spicy_index_list_free
// a failed check gives PROTOCOL_ABORT or MALFORMED, a sender over max_m or max_n_g gives POLICY
#[no_mangle]
pub unsafe extern "C" fn spicy_receiver_finish(
    r: *const SpicyReceiver,
    sender_reg: *const u8,
    sender_reg_len: usize,
    response: *const u8,
    response_len: usize,
    sid: *const u8,
    sid_len: usize,
    max_m: usize,
    max_n_g: usize,
    out: *mut SpicyIndexList,
    timings: *mut SpicyTimings,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || {
        let r = handle(r, "receiver")?;
        check_out(out)?;
        let sr = bytes(sender_reg, sender_reg_len, "sender_reg")?;
        let resp = bytes(response, response_len, "response")?;
        let sid = sid_bytes(sid, sid_len)?;
        let (idx, t) = r.0.finish(sr, resp, sid, max_m, max_n_g)?;
        put_timings(timings, t);
        *out = SpicyIndexList::from_indices(idx);
        Ok(())
    })
}

// frees a receiver and wipes its secrets
#[no_mangle]
pub unsafe extern "C" fn spicy_receiver_free(r: *mut SpicyReceiver) {
    if !r.is_null() {
        drop(Box::from_raw(r));
    }
}
