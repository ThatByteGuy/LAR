use crate::error::{LarError, Result};
use crate::security::{Action, AnalysisReport, Confidence, Finding, Severity, Verdict};
use serde::{Deserialize, Serialize};
use sha2::Digest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteVerdict {
    Clean,
    Advisory,
    Malicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    pub id: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyPayload {
    pub package: String,
    pub version: String,
    pub verdict: RemoteVerdict,
    pub advisories: Vec<Advisory>,
    pub known_good_hash: Option<String>,
    pub issued_unix: u64,
    pub expires_unix: u64,
}

#[derive(Debug, Clone)]
pub struct VerifiedView {
    pub package: String,
    pub version: String,
    pub verdict: RemoteVerdict,
    pub advisories: Vec<Advisory>,
    pub known_good_hash: Option<String>,
}

#[must_use]
pub fn sha256_hex(s: &str) -> String {
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

#[must_use]
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireResponse {
    payload: VerifyPayload,
    sig: String,
}

// One GET per package. Any failure means "no remote input", never a verdict.
pub async fn fetch_verified(
    base_url: &str,
    trust_root: &str,
    package: &str,
    version: &str,
    pkgbuild_sha256: &str,
) -> Result<VerifiedView> {
    let url =
        format!("{base_url}/verify?package={package}&version={version}&hash={pkgbuild_sha256}");
    let resp = reqwest::Client::builder()
        .user_agent("lar/0.1.0")
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
        .get(&url)
        .send()
        .await
        .map_err(|e| LarError::Fetch("reputation".to_owned(), e.to_string()))?;
    if !resp.status().is_success() {
        return Err(LarError::Fetch(
            "reputation".to_owned(),
            format!("http {}", resp.status()),
        ));
    }
    let wire: WireResponse = resp
        .json()
        .await
        .map_err(|e| LarError::Fetch("reputation".to_owned(), e.to_string()))?;
    if wire.payload.package != package {
        return Err(LarError::Verify(
            "response is for another package".to_owned(),
        ));
    }
    check_response(trust_root, now_unix(), &wire.payload, &wire.sig)
}

fn signing_key(secret_hex: &str) -> Result<ed25519_dalek::SigningKey> {
    let bytes = hex::decode(secret_hex).map_err(|e| LarError::Verify(format!("bad key: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| LarError::Verify("secret key must be 32 bytes".to_owned()))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
}

fn verifying_key(pub_hex: &str) -> Result<ed25519_dalek::VerifyingKey> {
    let bytes = hex::decode(pub_hex).map_err(|e| LarError::Verify(format!("bad key: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| LarError::Verify("public key must be 32 bytes".to_owned()))?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|e| LarError::Verify(format!("bad public key: {e}")))
}

fn canonical(payload: &VerifyPayload) -> Result<Vec<u8>> {
    serde_json::to_vec(payload).map_err(|e| LarError::Verify(format!("encode: {e}")))
}

pub fn sign(secret_hex: &str, payload: &VerifyPayload) -> Result<String> {
    use ed25519_dalek::Signer as _;
    let key = signing_key(secret_hex)?;
    let sig = key.sign(&canonical(payload)?);
    Ok(hex::encode(sig.to_bytes()))
}

// Binding, freshness, then signature. Any failure = discard, caller stays local.
pub fn check_response(
    pub_hex: &str,
    now_unix: u64,
    payload: &VerifyPayload,
    sig_hex: &str,
) -> Result<VerifiedView> {
    use ed25519_dalek::Verifier as _;
    if payload.expires_unix <= now_unix {
        return Err(LarError::Verify("response expired".to_owned()));
    }
    if payload.issued_unix > now_unix + 300 {
        return Err(LarError::Verify("response from the future".to_owned()));
    }
    let bytes = canonical(payload)?;
    let sig_bytes = hex::decode(sig_hex).map_err(|e| LarError::Verify(format!("bad sig: {e}")))?;
    let arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| LarError::Verify("signature must be 64 bytes".to_owned()))?;
    verifying_key(pub_hex)?
        .verify(&bytes, &ed25519_dalek::Signature::from_bytes(&arr))
        .map_err(|_| LarError::Verify("bad signature".to_owned()))?;
    Ok(VerifiedView {
        package: payload.package.clone(),
        version: payload.version.clone(),
        verdict: payload.verdict,
        advisories: payload.advisories.clone(),
        known_good_hash: payload.known_good_hash.clone(),
    })
}

// Remote input can only escalate or confirm. It can never clear a local BLOCK.
#[must_use]
pub fn merge(mut report: AnalysisReport, view: &VerifiedView) -> AnalysisReport {
    report.reputation_consulted = true;
    match view.verdict {
        RemoteVerdict::Malicious => {
            report.findings.push(Finding {
                rule_id: "LAR-REP-001".to_owned(),
                title: "Remote advisory flags this package".to_owned(),
                severity: Severity::Critical,
                confidence: Confidence::Confirmed,
                action: Action::Block,
                span: "reputation".to_owned(),
                excerpt: view
                    .advisories
                    .first()
                    .map(|a| format!("{}: {}", a.id, a.summary))
                    .unwrap_or_else(|| "flagged malicious".to_owned()),
                url: None,
                why: "A configured trust source reports this package as malicious.".to_owned(),
                recommendation: "Do not install. Investigate the advisory first.".to_owned(),
                static_detection: false,
            });
            AnalysisReport::decide(&report.package, report.findings, &report.input_hash)
        }
        RemoteVerdict::Advisory => {
            report.findings.push(Finding {
                rule_id: "LAR-REP-002".to_owned(),
                title: "Remote advisory exists for this package".to_owned(),
                severity: Severity::High,
                confidence: Confidence::Confirmed,
                action: Action::Review,
                span: "reputation".to_owned(),
                excerpt: view
                    .advisories
                    .first()
                    .map(|a| format!("{}: {}", a.id, a.summary))
                    .unwrap_or_else(|| "advisory".to_owned()),
                url: None,
                why: "A configured trust source has a security note on this package.".to_owned(),
                recommendation: "Read the advisory before building.".to_owned(),
                static_detection: false,
            });
            AnalysisReport::decide(&report.package, report.findings, &report.input_hash)
        }
        RemoteVerdict::Clean => report,
    }
}

// Clean + hash match upgrades ANALYZED to VERIFIED. Nothing else changes.
#[must_use]
pub fn confirm_hash(
    mut report: AnalysisReport,
    view: &VerifiedView,
    pkgbuild_sha256: &str,
) -> AnalysisReport {
    if view.verdict == RemoteVerdict::Clean
        && report.verdict == Verdict::Analyzed
        && view.known_good_hash.as_deref() == Some(pkgbuild_sha256)
    {
        report.verdict = Verdict::Verified;
    }
    report
}

pub fn pubkey_of(secret_hex: &str) -> Result<String> {
    let key = signing_key(secret_hex)?;
    Ok(hex::encode(key.verifying_key().to_bytes()))
}
