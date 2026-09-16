// Verdicts and findings. The UI renders these, it never decides.
use serde::{Deserialize, Serialize};

// Never add a `Safe` variant. ANALYZED is not safe, it is "nothing known-bad found".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Unknown,
    Analyzed,
    Suspicious,
    Blocked,
    Verified,
}

impl Verdict {
    #[must_use]
    pub const fn subtitle(&self) -> &'static str {
        match self {
            Self::Unknown => "Not sufficiently evaluated.",
            Self::Analyzed => "No known blocking behavior. Not guaranteed safe.",
            Self::Suspicious => "Heuristic detections require review.",
            Self::Blocked => "A security rule prohibits execution.",
            Self::Verified => "Matched currently trusted metadata. Not guaranteed safe.",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    Confirmed,
    Heuristic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Allow,
    Warn,
    Review,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub action: Action,
    // e.g. `PKGBUILD:build():12`
    pub span: String,
    pub excerpt: String,
    pub url: Option<String>,
    pub why: String,
    pub recommendation: String,
    pub static_detection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub package: String,
    pub verdict: Verdict,
    // ordering only, never the decision itself
    pub score: u32,
    pub findings: Vec<Finding>,
    pub reputation_consulted: bool,
    // hash of the exact input analyzed, re-checked before build
    pub input_hash: String,
}

impl AnalysisReport {
    // Any Block latch wins, regardless of score.
    #[must_use]
    pub fn decide(package: &str, mut findings: Vec<Finding>, input_hash: &str) -> Self {
        findings.sort_by_key(|a| std::cmp::Reverse(a.severity));
        let mut score: u32 = 0;
        let mut blocked = false;
        let mut suspicious = false;
        for f in &findings {
            score = score.saturating_add(match f.severity {
                Severity::Info => 1,
                Severity::Low => 5,
                Severity::Medium => 20,
                Severity::High => 50,
                Severity::Critical => 100,
            });
            match f.action {
                Action::Block => blocked = true,
                Action::Review | Action::Warn => suspicious = true,
                Action::Allow => {}
            }
        }
        let verdict = if blocked {
            Verdict::Blocked
        } else if suspicious {
            Verdict::Suspicious
        } else {
            Verdict::Analyzed
        };
        Self {
            package: package.to_owned(),
            verdict,
            score,
            findings,
            reputation_consulted: false,
            input_hash: input_hash.to_owned(),
        }
    }
}
