// sigma protocols over G0: generic maurer proof, R_open and R_key
#[cfg(feature = "fischlin")]
pub mod fischlin;
pub mod key_relation;
pub mod maurer;
pub mod open_relation;

// length-prefixed concatenation of context parts
pub fn context(parts: &[&[u8]]) -> Vec<u8> {
    let mut c = Vec::new();
    for p in parts {
        c.extend_from_slice(&(p.len() as u64).to_le_bytes());
        c.extend_from_slice(p);
    }
    c
}
