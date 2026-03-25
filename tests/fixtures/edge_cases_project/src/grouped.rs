//! Edge case: grouped import.
//!
//! `use cookie::{parse::parse_cookie, jar::CookieJar};`
//! Both symbols from the cookie advisory should be detected.

use cookie::parse::parse_cookie;
use cookie::jar::CookieJar;

pub fn run() {
    // Qualified call to a free function
    let c = parse_cookie("session=abc123");

    // Method call on a typed local
    let jar: CookieJar = CookieJar::new();
    jar.add(c);
}
