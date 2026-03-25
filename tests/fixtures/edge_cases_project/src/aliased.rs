//! Edge case: aliased import.
//!
//! `use hyper::proto::h1::decode::Decoder as HyperDecoder;`
//! Then `HyperDecoder::decode(...)` should still be detected.

use hyper::proto::h1::decode::Decoder as HyperDecoder;

pub fn run() {
    let dec = HyperDecoder::new();
    let result = dec.decode(data);
    println!("{:?}", result);
}
