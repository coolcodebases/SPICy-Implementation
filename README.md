# SPICy
This is a Rust implementation of the protocols in the paper *Stable Private Intersection with Consistency*:
SPICy with complete input consistency (CIC, in `src/`), SPICy with weak input consistency (WIC, in `spicy-wic/`),
and the PSI protocol without consistency (Our PSI, `src/protocol/plain_psi.rs`).

## Running
The Rust version is pinned in `rust-toolchain.toml`.

To run a protocol between two parties over TCP, start the receiver first and then the sender with the same (log_set_size):
> cargo run --release --example plain_psi_net (role) (ip:port) (log_set_size)

> cd spicy-wic && cargo run --release --example ws_net (role) (ip:port) (log_set_size)

> cd privatedrop && cargo run --release --example spicy_net (role) (ip:port) (log_set_size)

These run Our PSI, SPICy WIC and SPICy CIC respectively. Role is receiver or sender, and every third element is in both sets.
Each party prints its phase times, the size of the intersection and the data sent.

To run SPICy CIC in a single process and print the cost of every phase:
> cargo run --release --example end_to_end (set_size) (set_size)

To run SPICy CIC and SPICy WIC as the PSI of PrivateDrop, see `privatedrop/README.md`.

## Built on
1. arkworks: https://github.com/arkworks-rs
2. Spartan: https://github.com/microsoft/Spartan
