// JSONL security log. Fixed fields only, never secrets or env.
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SecurityEvent {
    pub ts: String,
    pub package: String,
    pub version: String,
    pub verdict: String,
    pub rules: Vec<String>,
    pub score: u32,
    pub override_scope: Option<String>,
    pub build: Option<String>,
    pub install: Option<String>,
}

impl SecurityEvent {
    #[must_use]
    pub fn new(package: &str, version: &str, verdict: &str, rules: &[String], score: u32) -> Self {
        Self {
            ts: now_ts(),
            package: package.to_owned(),
            version: version.to_owned(),
            verdict: verdict.to_owned(),
            rules: rules.to_vec(),
            score,
            override_scope: None,
            build: None,
            install: None,
        }
    }

    // Best-effort append. Never panics, never blocks the verdict.
    pub fn append(&self) {
        let path = log_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(line) = serde_json::to_string(self) {
            use std::io::Write as _;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                let _ = writeln!(f, "{line}");
            }
        }
    }
}

fn now_ts() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or("0".to_owned(), |d| d.as_secs().to_string())
}

fn log_path() -> std::path::PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".local/share/lar/security.log")
}

// Drops URL query strings and token-looking fragments before display/log.
#[must_use]
pub fn redact(s: &str) -> String {
    let mut out = s.to_owned();
    while let Some(q) = out.find('?') {
        let end = out[q..].find([' ', '"', '\'']).map_or(out.len(), |i| q + i);
        out.replace_range(q..end, "[redacted-query]");
    }
    for secret in ["token=", "password=", "secret=", "api_key="] {
        out = out.replace(secret, &format!("{secret}[redacted]"));
    }
    out
}
