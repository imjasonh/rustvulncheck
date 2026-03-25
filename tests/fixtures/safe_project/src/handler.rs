//! Handler module.
//!
//! Uses tokio and regex, but does NOT call the vulnerable symbols.
//! - tokio is at a vulnerable version but abort() is never called
//! - regex is at a vulnerable version but Compiler::compile is internal and not called
//! - hyper is at a PATCHED version (1.2.0 >= 1.0.0)
//! - smallvec is at a PATCHED version (1.11.0 >= 1.11.0)

use tokio::runtime::task::JoinHandle;
use regex::Regex;

pub fn run() {
    // Uses regex but NOT the vulnerable Compiler::compile — just the public API
    let re = Regex::new(r"\d+").unwrap();
    let matched = re.is_match("hello 123");
    println!("Matched: {}", matched);

    // References JoinHandle type but never calls .abort()
    let handles: Vec<JoinHandle> = Vec::new();
    for handle in handles {
        // Just awaits, doesn't abort
        println!("waiting on handle");
    }
}
