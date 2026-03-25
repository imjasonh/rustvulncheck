//! Edge case: same method name on a different type.
//!
//! `tokio::runtime::task::JoinHandle::abort` is vulnerable, but calling
//! `.abort()` on an unrelated type should NOT be flagged.
//!
//! Also: `serde_json::de::Deserializer::parse` is vulnerable, but calling
//! `.parse()` on a String (a very common Rust pattern) should NOT be flagged.

use tokio::runtime::task::JoinHandle;

struct MyHandle {
    id: u32,
}

impl MyHandle {
    fn abort(&self) {
        println!("aborting {}", self.id);
    }
}

pub fn run() {
    // .abort() on our own MyHandle — should NOT match JoinHandle::abort
    let h = MyHandle { id: 42 };
    h.abort();

    // .parse() is very common on strings — should NOT match serde_json Deserializer::parse
    // because serde_json::de::Deserializer is not imported
    let n: u32 = "42".parse().unwrap();
    let port: u16 = "8080".parse().unwrap();

    // JoinHandle is imported but we never call .abort() on one
    let handles: Vec<JoinHandle> = Vec::new();
    for handle in handles {
        // We only print, never abort
        println!("handle exists");
    }

    println!("n={}, port={}", n, port);
}
