// c api for spicy wic, with the conventions, buffers and error codes of the cic functions in lib.rs
// only the handle types and the spicy_wic_ prefix differ

use std::panic::catch_unwind;

use crate::party::fresh_rng;
use crate::wic::{WicReceiverParty, WicSenderParty};
use crate::{
    bytes, check_out, guard, handle, items, put_buffer, put_handle, put_timings, sid_bytes, SpicyBuffer, SpicyIndexList,
    SpicyItems, SpicyTimings,
};

// opaque wic sender handle
pub struct SpicyWicSender(WicSenderParty);
// opaque wic receiver handle
pub struct SpicyWicReceiver(WicReceiverParty);

// recommended wic n_g for up to max_m / max_n elements; returns 0 if a size is 0
#[no_mangle]
pub extern "C" fn spicy_wic_recommended_n_g(max_m: usize, max_n: usize) -> usize {
    catch_unwind(|| crate::wic::recommended_n_g(max_m, max_n).unwrap_or(0)).unwrap_or(0)
}

// sender

// Registration_S of items under id
// new handle in *out, free with spicy_wic_sender_free
#[no_mangle]
pub unsafe extern "C" fn spicy_wic_sender_register(
    items_in: SpicyItems,
    id: *const u8,
    id_len: usize,
    n_g: usize,
    out: *mut *mut SpicyWicSender,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || {
        check_out(out)?;
        let id = bytes(id, id_len, "id")?;
        let xs = items(&items_in)?;
        let p = WicSenderParty::register(id, &xs, n_g, &mut fresh_rng())?;
        put_handle(out, SpicyWicSender(p));
        Ok(())
    })
}

// rebuilds a sender from export_secret output into a new handle *out
#[no_mangle]
pub unsafe extern "C" fn spicy_wic_sender_import(
    secret: *const u8,
    secret_len: usize,
    out: *mut *mut SpicyWicSender,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || {
        check_out(out)?;
        let p = WicSenderParty::import_secret(bytes(secret, secret_len, "secret")?)?;
        put_handle(out, SpicyWicSender(p));
        Ok(())
    })
}

// writes the sender's public registration to out, free with spicy_buffer_free
#[no_mangle]
pub unsafe extern "C" fn spicy_wic_sender_registration(
    s: *const SpicyWicSender,
    out: *mut SpicyBuffer,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || put_buffer(out, handle(s, "WIC sender")?.0.registration().to_vec()))
}

// writes the secret state to out for persistence, free with spicy_buffer_free
#[no_mangle]
pub unsafe extern "C" fn spicy_wic_sender_export_secret(
    s: *const SpicyWicSender,
    out: *mut SpicyBuffer,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || put_buffer(out, handle(s, "WIC sender")?.0.export_secret()))
}

// M, or 0 if s is null
#[no_mangle]
pub unsafe extern "C" fn spicy_wic_sender_m(s: *const SpicyWicSender) -> usize {
    s.as_ref().map_or(0, |s| s.0.m())
}

// n_g, or 0 if s is null
#[no_mangle]
pub unsafe extern "C" fn spicy_wic_sender_n_g(s: *const SpicyWicSender) -> usize {
    s.as_ref().map_or(0, |s| s.0.n_g())
}

// PairSetup_S and Intersection_S for receiver_reg and a non-empty sid
// writes the response to out, free with spicy_buffer_free; timings may be null
#[no_mangle]
pub unsafe extern "C" fn spicy_wic_sender_respond(
    s: *const SpicyWicSender,
    receiver_reg: *const u8,
    receiver_reg_len: usize,
    sid: *const u8,
    sid_len: usize,
    out: *mut SpicyBuffer,
    timings: *mut SpicyTimings,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || {
        let s = handle(s, "WIC sender")?;
        let rr = bytes(receiver_reg, receiver_reg_len, "receiver_reg")?;
        let sid = sid_bytes(sid, sid_len)?;
        let (resp, t) = s.0.respond(rr, sid, &mut fresh_rng())?;
        put_timings(timings, t);
        put_buffer(out, resp)
    })
}

// frees a sender and wipes its secrets
#[no_mangle]
pub unsafe extern "C" fn spicy_wic_sender_free(s: *mut SpicyWicSender) {
    if !s.is_null() {
        drop(Box::from_raw(s));
    }
}

// receiver

// Registration_R of items under id, needs 4(N+1) <= n_g
// new handle in *out, free with spicy_wic_receiver_free
#[no_mangle]
pub unsafe extern "C" fn spicy_wic_receiver_register(
    items_in: SpicyItems,
    id: *const u8,
    id_len: usize,
    n_g: usize,
    out: *mut *mut SpicyWicReceiver,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || {
        check_out(out)?;
        let id = bytes(id, id_len, "id")?;
        let ys = items(&items_in)?;
        let p = WicReceiverParty::register(id, &ys, n_g, &mut fresh_rng())?;
        put_handle(out, SpicyWicReceiver(p));
        Ok(())
    })
}

// rebuilds a receiver from export_secret output into a new handle *out
#[no_mangle]
pub unsafe extern "C" fn spicy_wic_receiver_import(
    secret: *const u8,
    secret_len: usize,
    out: *mut *mut SpicyWicReceiver,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || {
        check_out(out)?;
        let p = WicReceiverParty::import_secret(bytes(secret, secret_len, "secret")?)?;
        put_handle(out, SpicyWicReceiver(p));
        Ok(())
    })
}

// writes the receiver's public registration to out, free with spicy_buffer_free
#[no_mangle]
pub unsafe extern "C" fn spicy_wic_receiver_registration(
    r: *const SpicyWicReceiver,
    out: *mut SpicyBuffer,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || put_buffer(out, handle(r, "WIC receiver")?.0.registration().to_vec()))
}

// writes the secret state to out for persistence, free with spicy_buffer_free
#[no_mangle]
pub unsafe extern "C" fn spicy_wic_receiver_export_secret(
    r: *const SpicyWicReceiver,
    out: *mut SpicyBuffer,
    err: *mut SpicyBuffer,
) -> i32 {
    guard(err, || put_buffer(out, handle(r, "WIC receiver")?.0.export_secret()))
}

// N, or 0 if r is null
#[no_mangle]
pub unsafe extern "C" fn spicy_wic_receiver_n(r: *const SpicyWicReceiver) -> usize {
    r.as_ref().map_or(0, |r| r.0.n())
}

// n_g, or 0 if r is null
#[no_mangle]
pub unsafe extern "C" fn spicy_wic_receiver_n_g(r: *const SpicyWicReceiver) -> usize {
    r.as_ref().map_or(0, |r| r.0.n_g())
}

// verifies the sender registration and response for sid
// writes the ascending indices of our items in the output to out, free with spicy_index_list_free
// a failed check gives PROTOCOL_ABORT or MALFORMED, a sender over max_m or max_n_g gives POLICY
#[no_mangle]
pub unsafe extern "C" fn spicy_wic_receiver_finish(
    r: *const SpicyWicReceiver,
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
        let r = handle(r, "WIC receiver")?;
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
pub unsafe extern "C" fn spicy_wic_receiver_free(r: *mut SpicyWicReceiver) {
    if !r.is_null() {
        drop(Box::from_raw(r));
    }
}
