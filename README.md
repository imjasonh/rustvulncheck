# `rustvulncheck`

### Background: `govulncheck`

There are a lot of hidden gems in the Go ecosystem, and one of the best has to be [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck).

Traditional vulnerability scanners detect dependencies in a codebase, and match those against a database of vulnerable dependencies (usually derived from [NVD]([url](https://nvd.nist.gov/vuln))), and tell you whether your codebase has any dependencies that are marked as vulnerable. This is ...fine, but can lead to a certain amount of false positives.

As an example, you depend on something like [`github.com/gorilla/websocket`](https://github.com/gorilla/websocket). Someone reports a vulnerability saying that if you call [`SetPingHandler`](https://pkg.go.dev/github.com/gorilla/websocket#Conn.SetPingHandler) and that handler panics on malformed input, and an untrusted client sends malformed input, you could be susceptible to a DoS, and personal liability, and all the dairy in your fridge will go bad immediately. This is categorized as a **`CRITICAL`** CVE, with a CVSS score of one trillion. (This is an entirely made up example I have no idea if that's possible, but stick with me). Okay, that's certainly good to know, and I definitely don't want to have that happen to me.

But... what if I never call `SetPingHandler` anywhere in my code? Do I need to care about this vulnerability? Is my milk safe?

This is where `govulncheck` comes in. First, the Go team maintains a [very thorough database of Go vulnerabilities](https://pkg.go.dev/vuln/). Not just the names and version ranges of vulnerable modules, but structured data about the actual vulnerable methods and symbols you'd need to call to actually be vulnerable. This is manual work by experts with good taste -- let's just call it "expensive". But it leads to what's next:

Then there's a tool called `govulncheck`, which crawls your codebase (or already-built binaries) and searches for those vulnerable symbols. Only when it finds the vulnerable symbol in your code, does it report the genuine vulnerability. If you depend on `gorilla/websocket` but never call `SetPingHandler`, you're safe, and `govulncheck` will tell you that. You can safely ignore the big scary vuln, and your milk is safe (for now!). If you call `SetPingHandler`, `govulncheck` will tell you, and will even tell you the call path that leads to it, to help you better understand the issue. If `SetPingHandler` is only ever called with a bulletproof handler that can't panic, great! If not, you should upgrade to a fixed version of `gorilla/websocket`.

Used correctly, this can become a powerful tool in cutting through vulnerability noise -- instead of just blindly immediately upgrading your dependency (which you should do soon anyway, not blindly), you can determine that that **`CRITICAL`** vuln is actually maybe just a nice-to-have, and prioritize fixing it later, and not omgimmediately. Whole swathes of reports from traditional vulnerability scanners can be marked as not-affected and deprioritized, letting teams focus on the actual vulns that can hurt you.

Basically, I wanted that, but for Rust.

### `rustvulncheck`

This is an early vibe-coded experiment to see if we can bring some of the benefits of `govulncheck` to the Rust ecosystem. Early signs are positive.

The Rust ecosystem already has a well-maintained database of security advisories at https://github.com/RustSec/advisory-db -- it just doesn't include data about the specific vulnerable symbols you'd need to exploit them. That's the first thing this tool does.

The tool "enriches" the advisory DB by looking at the commit that fixed the vulnerability, and fairly naively looking for symbols modified in the fix. For example, If `v1.2.3` was vulnerable and `v1.2.4` was fixed, and the diff between those two tags was a single commit modifying `conn::set_ping_handler`, then we can surmise that that was the vulnerable symbol, and record that. This analysis is done entirely using traditional, deterministic code -- no LLMs are involved here (though that code was indeed written by Claude).

Next, like `govulncheck`, `rustvulncheck` ingests the enriched database, and crawls some Rust codebase to see if it uses any of those vulnerable symbols, at vulnerable dependency version ranges. If so, watch out! If not, you're good.

This isn't perfect, of course -- if a fixed version `v1.2.4` included a hundred commits changing dozens of symbols, you'll get false positives, but those false positives should at least be _less_ false positive than without symbol-aware enrichment. Without `rustvulncheck` you would have only seen a vulnerable crate as a dependency and assumed you were susceptible.

### Demo

The `demo/` directory contains two small projects that show the difference between a traditional scanner and reachability-aware analysis.

**Reachable vulnerability** — `demo/reachable/` depends on `serde_yaml 0.8.3` and calls `serde_yaml::de::from_str`, which is vulnerable to uncontrolled recursion ([RUSTSEC-2018-0005](https://rustsec.org/advisories/RUSTSEC-2018-0005.html)). The analyzer correctly flags this:

```
$ cargo-deep-audit analyze --project demo/reachable --db vuln_db.json

  RUSTSEC-2018-0005 (serde_yaml) :: serde_yaml::de::from_str
  1 call site(s) (1 high confidence, 0 medium confidence)
    [HIGH] src/main.rs:12 → let value: serde_yaml::Value = from_str(yaml_input).unwrap();

RESULT: VULNERABLE - reachable vulnerable symbols detected
```

**Not reachable** — `demo/not-reachable/` depends on `base64 0.5.1`, which has a heap buffer overflow in its *encoding* functions ([RUSTSEC-2017-0004](https://rustsec.org/advisories/RUSTSEC-2017-0004.html)). But this project only *decodes*, so the vulnerable symbols are never called:

```
$ cargo-deep-audit analyze --project demo/not-reachable --db vuln_db.json

  RUSTSEC-2017-0004 base64 @ 0.5.1
  Vulnerable symbols:
    - base64::encode_config
    - base64::encode_config_buf
    - base64::encoded_size

  None of the 3 vulnerable symbols appear to be called from your code.

RESULT: POSSIBLY SAFE - vulnerable dependencies present but symbols not detected in source
```

A traditional scanner would flag both projects equally. `rustvulncheck` tells you which one actually matters.

### Status

The enriched database is available at [`./vuln_db.json`](./vuln_db.json), and is continuously rebuilt by periodically scraping RustSec's advisories and doing the diff analysis to determine affected symbols. Right now I'm having Claude spot-check and improve the enriched DB and add tests for corner cases it discovers. It's going pretty well!

Eventually, it would probably be useful for humans and more agents to spot-check and tweak the findings. The idea isn't to replace the experts with good taste, it's to give them a leg up on the backlog and ongoing analysis.

The call analysis code could probably also be improved to both find more cases, and to filter out negatives better.

Ultimately I don't really even need this exact code to become The Thing, I just want The Thing to exist, and this was a useful experiment to see what it would take. If this inspires you to do better, _please do_!
