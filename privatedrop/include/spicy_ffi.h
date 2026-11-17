/*
 * spicy_ffi.h: C interface of spicy-ffi, implemented in src/lib.rs and src/wic_ffi.rs
 *
 * - functions return SPICY_OK or a SPICY_ERR_* code
 * - on error a non-NULL err gets a UTF-8 message without a NUL terminator, free it with spicy_buffer_free
 * - handles can be shared between threads, spicy_*_free frees them and wipes their secrets
 * - both parties register with an identity of 1..1024 bytes and the same mask length n_g
 * - spicy_recommended_n_g gives n_g, and a receiver needs 4(N+1) <= n_g
 * - returned buffers and lists belong to the caller, free them with spicy_buffer_free or
 *   spicy_index_list_free
 */
#ifndef SPICY_FFI_H
#define SPICY_FFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SPICY_OK 0
#define SPICY_ERR_INVALID_ARGUMENT 1 /* null pointer, inconsistent lengths, empty sid */
#define SPICY_ERR_INVALID_INPUT 2    /* empty/duplicate set, empty id, invalid sizes / n_g */
#define SPICY_ERR_PROTOCOL_ABORT 3   /* proof rejected, bad point, pk_R too long for n_g,
                                        or the peers use different n_g */
#define SPICY_ERR_MALFORMED 4        /* message or secret can't be decoded */
#define SPICY_ERR_POLICY 5           /* peer's M or n_g over the caller's limits, or n_g too
                                        short for (M, N) */
#define SPICY_ERR_INTERNAL 6         /* internal failure */
#define SPICY_ERR_PANIC 7            /* a Rust panic was caught */

typedef struct SpicySender SpicySender;
typedef struct SpicyReceiver SpicyReceiver;

typedef struct SpicyBuffer {
    uint8_t *ptr;
    size_t len;
} SpicyBuffer;

typedef struct SpicyIndexList {
    uint64_t *ptr;
    size_t len;
} SpicyIndexList;

/* items stored back to back in data; lengths[i] is the size of item i */
typedef struct SpicyItems {
    const uint8_t *data;
    size_t data_len;
    const size_t *lengths;
    size_t count;
} SpicyItems;

/* time spent in each step of a call, in nanoseconds */
typedef struct SpicyTimings {
    uint64_t total_ns;
    uint64_t decode_ns;
    uint64_t verify_registration_ns;
    uint64_t pair_setup_ns;
    uint64_t intersection_ns;
    uint64_t encode_ns;
    uint64_t tokens_ns; /* building a token batch and pi_tok, 0 if a precomputed one was used */
} SpicyTimings;

const char *spicy_version(void);
void spicy_buffer_free(SpicyBuffer buf);
void spicy_index_list_free(SpicyIndexList list);
/* recommended n_g for senders of up to max_m and receivers of up to max_n items, 0 if a size is 0 */
size_t spicy_recommended_n_g(size_t max_m, size_t max_n);

/* sender: holds X */
int32_t spicy_sender_register(SpicyItems items, const uint8_t *id, size_t id_len, size_t n_g,
                              SpicySender **out, SpicyBuffer *err);
int32_t spicy_sender_import(const uint8_t *secret, size_t secret_len, SpicySender **out, SpicyBuffer *err);
int32_t spicy_sender_registration(const SpicySender *s, SpicyBuffer *out, SpicyBuffer *err);
int32_t spicy_sender_export_secret(const SpicySender *s, SpicyBuffer *out, SpicyBuffer *err);
size_t spicy_sender_m(const SpicySender *s);
size_t spicy_sender_n_g(const SpicySender *s);
/* precomputes token batches with pi_tok, each respond uses one or builds one if none is left */
int32_t spicy_sender_precompute_tokens(const SpicySender *s, size_t count, SpicyBuffer *err);
size_t spicy_sender_tokens_available(const SpicySender *s);
int32_t spicy_sender_respond(const SpicySender *s,
                             const uint8_t *receiver_reg, size_t receiver_reg_len,
                             const uint8_t *sid, size_t sid_len,
                             SpicyBuffer *out, SpicyTimings *timings, SpicyBuffer *err);
void spicy_sender_free(SpicySender *s);

/* receiver: holds Y, learns the intersection */
int32_t spicy_receiver_register(SpicyItems items, const uint8_t *id, size_t id_len, size_t n_g,
                                SpicyReceiver **out, SpicyBuffer *err);
int32_t spicy_receiver_import(const uint8_t *secret, size_t secret_len, SpicyReceiver **out, SpicyBuffer *err);
int32_t spicy_receiver_registration(const SpicyReceiver *r, SpicyBuffer *out, SpicyBuffer *err);
int32_t spicy_receiver_export_secret(const SpicyReceiver *r, SpicyBuffer *out, SpicyBuffer *err);
size_t spicy_receiver_n(const SpicyReceiver *r);
size_t spicy_receiver_n_g(const SpicyReceiver *r);
int32_t spicy_receiver_finish(const SpicyReceiver *r,
                              const uint8_t *sender_reg, size_t sender_reg_len,
                              const uint8_t *response, size_t response_len,
                              const uint8_t *sid, size_t sid_len,
                              size_t max_m, size_t max_n_g,
                              SpicyIndexList *out, SpicyTimings *timings, SpicyBuffer *err);
void spicy_receiver_free(SpicyReceiver *r);

/* spicy wic: same conventions, buffers and error codes as the functions above
   wic messages and secrets given to cic functions, or the reverse, give SPICY_ERR_MALFORMED */
typedef struct SpicyWicSender SpicyWicSender;
typedef struct SpicyWicReceiver SpicyWicReceiver;

/* recommended n_g for wic senders of up to max_m and receivers of up to max_n items, 0 if a size is 0 */
size_t spicy_wic_recommended_n_g(size_t max_m, size_t max_n);

/* wic sender: holds X */
int32_t spicy_wic_sender_register(SpicyItems items, const uint8_t *id, size_t id_len, size_t n_g,
                                  SpicyWicSender **out, SpicyBuffer *err);
int32_t spicy_wic_sender_import(const uint8_t *secret, size_t secret_len, SpicyWicSender **out, SpicyBuffer *err);
int32_t spicy_wic_sender_registration(const SpicyWicSender *s, SpicyBuffer *out, SpicyBuffer *err);
int32_t spicy_wic_sender_export_secret(const SpicyWicSender *s, SpicyBuffer *out, SpicyBuffer *err);
size_t spicy_wic_sender_m(const SpicyWicSender *s);
size_t spicy_wic_sender_n_g(const SpicyWicSender *s);
int32_t spicy_wic_sender_respond(const SpicyWicSender *s,
                                 const uint8_t *receiver_reg, size_t receiver_reg_len,
                                 const uint8_t *sid, size_t sid_len,
                                 SpicyBuffer *out, SpicyTimings *timings, SpicyBuffer *err);
void spicy_wic_sender_free(SpicyWicSender *s);

/* wic receiver: holds Y, learns the intersection */
int32_t spicy_wic_receiver_register(SpicyItems items, const uint8_t *id, size_t id_len, size_t n_g,
                                    SpicyWicReceiver **out, SpicyBuffer *err);
int32_t spicy_wic_receiver_import(const uint8_t *secret, size_t secret_len, SpicyWicReceiver **out, SpicyBuffer *err);
int32_t spicy_wic_receiver_registration(const SpicyWicReceiver *r, SpicyBuffer *out, SpicyBuffer *err);
int32_t spicy_wic_receiver_export_secret(const SpicyWicReceiver *r, SpicyBuffer *out, SpicyBuffer *err);
size_t spicy_wic_receiver_n(const SpicyWicReceiver *r);
size_t spicy_wic_receiver_n_g(const SpicyWicReceiver *r);
int32_t spicy_wic_receiver_finish(const SpicyWicReceiver *r,
                                  const uint8_t *sender_reg, size_t sender_reg_len,
                                  const uint8_t *response, size_t response_len,
                                  const uint8_t *sid, size_t sid_len,
                                  size_t max_m, size_t max_n_g,
                                  SpicyIndexList *out, SpicyTimings *timings, SpicyBuffer *err);
void spicy_wic_receiver_free(SpicyWicReceiver *r);

#ifdef __cplusplus
}
#endif

#endif /* SPICY_FFI_H */
