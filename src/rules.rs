use crate::security::{Action, Confidence, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchKind {
    Regex,
    Behavior,
    Composite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub action: Action,
    pub kind: MatchKind,
    pub behavior: String,
    pub recommendation: String,
    pub version: String,
    pub enabled: bool,
    pub weight: u32,
    // true = BLOCK no matter the total score
    pub latch_block: bool,
}

impl Rule {
    #[allow(clippy::too_many_arguments, reason = "rule rows are declarative")]
    fn mk(
        id: &str,
        name: &str,
        title: &str,
        description: &str,
        category: &str,
        severity: Severity,
        confidence: Confidence,
        action: Action,
        kind: MatchKind,
        behavior: &str,
        recommendation: &str,
        latch_block: bool,
    ) -> Self {
        Self {
            id: id.to_owned(),
            name: name.to_owned(),
            title: title.to_owned(),
            description: description.to_owned(),
            category: category.to_owned(),
            severity,
            confidence,
            action,
            kind,
            behavior: behavior.to_owned(),
            recommendation: recommendation.to_owned(),
            version: "1.0.0".to_owned(),
            enabled: true,
            weight: match severity {
                Severity::Info => 1,
                Severity::Low => 5,
                Severity::Medium => 20,
                Severity::High => 50,
                Severity::Critical => 100,
            },
            latch_block,
        }
    }
}

#[must_use]
pub fn builtin_rules() -> Vec<Rule> {
    vec![
        Rule::mk(
            "LAR-NET-001", "remote-script-execution",
            "Remote content piped directly to shell",
            "Remote resource fetched and piped to sh/bash without verification.",
            "network-exec", Severity::Critical, Confidence::Confirmed,
            Action::Block, MatchKind::Behavior, "download_to_shell",
            "Vendor the script or pin hash + review. Never pipe remote content to shell.", true,
        ),
        Rule::mk(
            "LAR-NET-002", "download-chmod-exec",
            "Downloaded file made executable and run",
            "File fetched then chmod +x and executed (incl. /tmp).",
            "network-exec", Severity::Critical, Confidence::Confirmed,
            Action::Block, MatchKind::Behavior, "download_chmod_exec",
            "Verify hash/signature of the file and inspect before executing.", true,
        ),
        Rule::mk(
            "LAR-OBF-001", "decode-and-exec",
            "Encoded payload decoded then executed",
            "base64/hex/xxd/openssl decode piped or eval'd into execution.",
            "obfuscation", Severity::High, Confidence::Heuristic,
            Action::Block, MatchKind::Behavior, "decode_exec",
            "Decode offline, inspect the payload, then decide.", true,
        ),
        Rule::mk(
            "LAR-OBF-002", "eval-obfuscation",
            "Dynamic eval of constructed command",
            "eval of variable-built or nested $() command hides intent.",
            "obfuscation", Severity::High, Confidence::Heuristic,
            Action::Review, MatchKind::Behavior, "eval_dynamic",
            "Expand the constructed command and review before building.", false,
        ),
        Rule::mk(
            "LAR-PRIV-001", "privilege-escalation",
            "Privilege manipulation in build/install",
            "sudo/su/chmod +s/setuid/polkit/ssh-key modification.",
            "priv-escalation", Severity::Critical, Confidence::Confirmed,
            Action::Block, MatchKind::Behavior, "priv_escalation",
            "Builds must not escalate privilege. Inspect and override only if intended.", true,
        ),
        Rule::mk(
            "LAR-PERS-001", "persistence-install",
            "Persistence mechanism installed",
            "systemd unit, autostart, shell rc edit, cron, udev rule.",
            "persistence", Severity::High, Confidence::Heuristic,
            Action::Review, MatchKind::Behavior, "persistence",
            "Confirm the service/startup entry is expected for this package.", false,
        ),
        Rule::mk(
            "LAR-EXFIL-001", "credential-access",
            "Credential directory accessed",
            "Reads ~/.ssh, ~/.gnupg, browser cookies, or ships env to network.",
            "exfil", Severity::Critical, Confidence::Heuristic,
            Action::Block, MatchKind::Behavior, "credential_access",
            "Do not build; exfiltration of secrets is never routine.", true,
        ),
        Rule::mk(
            "LAR-SUPPLY-001", "lifecycle-exec",
            "Package-manager lifecycle script execution",
            "npm/bun/pip/cargo install hooks (preinstall/postinstall, build.rs) may run arbitrary code.",
            "supply-chain", Severity::Medium, Confidence::Heuristic,
            Action::Review, MatchKind::Behavior, "lifecycle_exec",
            "Prefer --ignore-scripts or pinned, reviewed dependencies.", false,
        ),
        Rule::mk(
            "LAR-NET-003", "dynamic-url-exec",
            "Dynamically constructed URL executed",
            "URL built from variables ($pkgver, env) then fetched and executed.",
            "network-exec", Severity::High, Confidence::Heuristic,
            Action::Review, MatchKind::Behavior, "dynamic_url_exec",
            "Pin the URL/tag and verify hash before executing.", false,
        ),
        Rule::mk(
            "LAR-PARSE-001", "parse-unreliable",
            "Parser could not fully model input",
            "Fallback scanner used; treat as REVIEW, never silent ANALYZED.",
            "evasion", Severity::Medium, Confidence::Heuristic,
            Action::Review, MatchKind::Behavior, "parse_unreliable",
            "Manually review the PKGBUILD before building.", false,
        ),
    ]
}
