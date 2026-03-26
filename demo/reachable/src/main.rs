//! A config loader that deserializes YAML from user input.
//!
//! This calls `serde_yaml::de::from_str`, which is vulnerable to uncontrolled
//! recursion (stack overflow) in serde_yaml < 0.8.4.
//! See: RUSTSEC-2018-0005

use serde_yaml::de::from_str;

fn load_config(yaml_input: &str) {
    // This calls the vulnerable `serde_yaml::de::from_str` function.
    // An attacker could craft deeply nested YAML to trigger a stack overflow.
    let value: serde_yaml::Value = from_str(yaml_input).unwrap();
    println!("Loaded config: {:?}", value);
}

fn main() {
    let config = "server:\n  host: localhost\n  port: 8080";
    load_config(config);
}
