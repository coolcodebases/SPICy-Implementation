# SPICy WIC
SPICy with weak input consistency. The receiver side is the same as in SPICy CIC; the sender publishes one hash leaf
per element instead of proving circuits, and proves knowledge of its pair key with a Fischlin proof (src/rep_proof.rs).
The sender cannot inject elements, but it can omit them.

## Running
> cargo run --release --example ws_net (role) (ip:port) (log_set_size)

> cargo run --release --example bench_phases (log_set_size) (reps)
