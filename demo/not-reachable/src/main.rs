//! A data decoder that only decodes base64 data.
//!
//! The base64 crate (< 0.5.2) has a heap buffer overflow vulnerability
//! in its *encoding* functions (encode_config, encode_config_buf).
//! See: RUSTSEC-2017-0004
//!
//! This program only decodes, so the vulnerable functions are never called.

use base64;

fn decode_payload(encoded: &str) -> Vec<u8> {
    // Only uses decode — the vulnerability is in encode_config / encode_config_buf,
    // which this code never calls. Safe despite the vulnerable dependency.
    base64::decode(encoded).unwrap()
}

fn main() {
    let data = decode_payload("SGVsbG8gV29ybGQ=");
    println!("Decoded: {}", String::from_utf8_lossy(&data));
}
