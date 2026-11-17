# spicy-ffi
C interface to SPICy CIC and SPICy WIC (`include/spicy_ffi.h`), and their integration into PrivateDrop as its PSI.

## Running
To run SPICy CIC between two parties over TCP:
> cargo run --release --example spicy_net (role) (ip:port) (log_set_size)

## PrivateDrop
`patches/` holds our changes to PrivateDrop (commit fb47cb6) and PrivateDrop-Base (commit 43f6bbc), and `app/` the Swift code we add to it.
The setup script clones both at these commits, applies the patches, copies `app/` into the checkout as `spicy/`, builds the library and creates test identities signed by a test authority.
It runs on macOS and needs git, openssl, python3 and the Rust targets aarch64-apple-darwin and x86_64-apple-darwin:
> ./scripts/setup-privatedrop.sh (destination) [macos|ios|all]

To run the PSI exchange of PrivateDrop with SPICy, and to compare it with the original PSI on the same inputs (x86_64, so through Rosetta on Apple silicon):
> cd (destination)/spicy && [HARNESS_LEVEL=wic] [HARNESS_HTTPS=1] ./scripts/run-airdrop-harness.sh e2e

> cd (destination)/spicy && ./scripts/run-airdrop-harness.sh compare

To measure an exchange between (m) identifiers and (n) contacts:
> cd (destination)/spicy && swift run -c release spicy-psi-bench --level (cic|wic) (m),(n)

After setting up with `all`, the PrivateDrop apps build in Xcode from `(destination)/PrivateDrop.xcworkspace`, and the launch argument `-PrivateDropSpicyLevel wic` selects SPICy WIC.
