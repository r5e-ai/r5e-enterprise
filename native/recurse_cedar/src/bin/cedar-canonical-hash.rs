//! cedar-canonical-hash — standalone offline companion to the `canonical_hash`
//! NIF in ../lib.rs, for `docs/auditor/recurse-verify` Step 4 (rule 1).
//!
//! Computes SHA-256(JCS(PolicySet::to_json(parse(source)))) — byte-identical
//! to `Recurse.Cedar.canonical_hash/1` because it is compiled from the SAME
//! crate with the SAME content-addressed cedar-policy pin (=4.9.1, research
//! D2 / FR-039) and the same serde_jcs RFC 8785 encoder. If the pin bumps,
//! rebuild this binary alongside the NIF (`cargo build --release` in
//! native/recurse_cedar) and re-vendor it into docs/auditor/.
//!
//! Usage: cedar-canonical-hash <bundle.cedar>
//! Output: lowercase 64-hex SHA-256 on stdout; exit 0.
//! Exit 1 on cedar parse/serialize failure, 3 on bad invocation.

use cedar_policy::PolicySet;
use sha2::{Digest, Sha256};
use std::str::FromStr;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: cedar-canonical-hash <bundle.cedar>");
        std::process::exit(3);
    }

    let source = match std::fs::read_to_string(&args[1]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cedar-canonical-hash: read error: {e}");
            std::process::exit(3);
        }
    };

    let policy_set = match PolicySet::from_str(&source) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cedar-canonical-hash: cedar parse error: {e}");
            std::process::exit(1);
        }
    };

    let json = match policy_set.to_json() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("cedar-canonical-hash: cedar to_json error: {e}");
            std::process::exit(1);
        }
    };

    let canonical = match serde_jcs::to_string(&json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cedar-canonical-hash: jcs encode error: {e}");
            std::process::exit(1);
        }
    };

    let digest = Sha256::digest(canonical.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    println!("{hex}");
}
