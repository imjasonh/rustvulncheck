//! Server module that uses hyper for HTTP handling.

use hyper::proto::h1::role::Client;
use hyper::proto::h1::decode::Decoder;

pub fn run_server() {
    // Case 1: Qualified associated-function call (HIGH confidence expected)
    let client = Client::encode(raw_request);

    // Case 2: Method call on typed variable (HIGH confidence with type tracking)
    let decoder: Decoder = Decoder::new();
    let result = decoder.decode(buf);

    println!("Server running: {:?} {:?}", client, result);
}
