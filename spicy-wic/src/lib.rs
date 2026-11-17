// spicy with weak sender input consistency (wic), no circuits
// receiver side (pk_R, elligator squared, mask g) same as the circuit crate; sender publishes hash leaves, proves its pair key with pi_rep at pair setup, then one message per intersection
#![allow(rustdoc::broken_intra_doc_links)]

pub mod ct;
pub mod encoding;
pub mod error;
pub mod field;
pub mod leaves;
pub mod oprf;
pub mod oracle;
pub mod par;
pub mod params;
pub mod protocol;
pub mod rep_proof;
pub mod serialize;
pub mod transcript;
pub mod types;
