//! Edge case: vulnerable calls that are commented out.
//!
//! These should NOT be detected as call sites.

use hyper::proto::h1::role::Client;
use serde_json::de::Deserializer;

pub fn run() {
    // Client::encode(raw_request);
    // let d = Deserializer::parse(input);

    /* Also in block comments:
       Client::encode(raw_request);
       Deserializer::parse(input);
    */

    // Only safe code actually runs here
    println!("nothing vulnerable here");
}
