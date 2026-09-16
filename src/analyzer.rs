// Takes PKGBUILD text, returns a verdict. Reads only, runs nothing.
use crate::pkgbuild::{normalize, Pkgbuild};
use crate::rules::builtin_rules;
use crate::security::{Action, AnalysisReport, Confidence, Finding, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Behavior {
    DownloadToShell,
    DownloadChmodExec,
    DecodeExec,
    EvalDynamic,
    PrivEscalation,
    Persistence,
    CredentialAccess,
    LifecycleExec,
    DynamicUrlExec,
}

#[must_use]
pub fn analyze(package: &str, raw: &str) -> AnalysisReport {
    let input_hash = short_hash(raw);
    let parsed = match Pkgbuild::parse(raw) {
        Ok(p) => p,
        Err(e) => {
            let f = Finding {
                rule_id: "LAR-PARSE-001".to_owned(),
                title: "Parser could not fully model input".to_owned(),
                severity: Severity::Medium,
                confidence: Confidence::Heuristic,
                action: Action::Review,
                span: "PKGBUILD:global".to_owned(),
                excerpt: truncate(raw, 200),
                url: None,
                why: format!("Fail-closed parse error: {e}. Treated as REVIEW."),
                recommendation: "Manually review the PKGBUILD before building.".to_owned(),
                static_detection: true,
            };
            return AnalysisReport::decide(package, vec![f], &input_hash);
        }
    };

    let rules = builtin_rules();
    let by_behavior: std::collections::HashMap<&str, &crate::rules::Rule> =
        rules.iter().map(|r| (r.behavior.as_str(), r)).collect();

    let mut findings: Vec<Finding> = Vec::new();
    for (span, body) in parsed.units() {
        let norm = normalize(&body);
        for b in detect_behaviors(&norm) {
            let key = behavior_key(&b);
            if let Some(rule) = by_behavior.get(key) {
                if !rule.enabled {
                    continue;
                }
                findings.push(Finding {
                    rule_id: rule.id.clone(),
                    title: rule.title.clone(),
                    severity: rule.severity,
                    confidence: rule.confidence,
                    action: rule.action,
                    span: span.clone(),
                    excerpt: excerpt_for(&norm),
                    url: first_url(&norm),
                    why: rule.description.clone(),
                    recommendation: rule.recommendation.clone(),
                    static_detection: true,
                });
            }
        }
    }
    findings.sort_by_key(|a| (a.rule_id.clone(), a.span.clone()));
    findings.dedup_by(|a, b| a.rule_id == b.rule_id && a.span == b.span);
    AnalysisReport::decide(package, findings, &input_hash)
}

// Same engine over a helper file (.install etc). Spans carry the filename.
#[must_use]
pub fn analyze_file(package: &str, filename: &str, raw: &str) -> AnalysisReport {
    let mut report = analyze(package, raw);
    for f in &mut report.findings {
        if let Some(rest) = f.span.strip_prefix("PKGBUILD") {
            f.span = format!("{filename}{rest}");
        }
    }
    report
}

fn behavior_key(b: &Behavior) -> &'static str {
    match b {
        Behavior::DownloadToShell => "download_to_shell",
        Behavior::DownloadChmodExec => "download_chmod_exec",
        Behavior::DecodeExec => "decode_exec",
        Behavior::EvalDynamic => "eval_dynamic",
        Behavior::PrivEscalation => "priv_escalation",
        Behavior::Persistence => "persistence",
        Behavior::CredentialAccess => "credential_access",
        Behavior::LifecycleExec => "lifecycle_exec",
        Behavior::DynamicUrlExec => "dynamic_url_exec",
    }
}

fn detect_behaviors(norm: &str) -> Vec<Behavior> {
    let mut out = Vec::new();
    let lower = norm.to_lowercase();

    if is_download_to_shell(&lower) {
        out.push(Behavior::DownloadToShell);
    }
    if is_download_chmod_exec(&lower) {
        out.push(Behavior::DownloadChmodExec);
    }
    if is_decode_exec(&lower) {
        out.push(Behavior::DecodeExec);
    }
    if is_eval_dynamic(&lower) {
        out.push(Behavior::EvalDynamic);
    }
    if is_priv_escalation(&lower) {
        out.push(Behavior::PrivEscalation);
    }
    if is_persistence(&lower) {
        out.push(Behavior::Persistence);
    }
    if is_credential_access(&lower) {
        out.push(Behavior::CredentialAccess);
    }
    if is_lifecycle_exec(&lower) {
        out.push(Behavior::LifecycleExec);
    }
    if is_dynamic_url_exec(&lower) {
        out.push(Behavior::DynamicUrlExec);
    }
    out
}

fn is_download_to_shell(l: &str) -> bool {
    let fetchers = ["curl", "wget", "aria2c"];
    let shells = [
        "| bash", "|bash", "| sh", "|sh", "| zsh", "| fish", "| dash",
    ];
    if !(fetchers.iter().any(|f| l.contains(f)) && shells.iter().any(|s| l.contains(s))) {
        return false;
    }
    // fetch must come before the pipe, not just appear nearby
    let fetch_pos = fetchers
        .iter()
        .filter_map(|f| l.find(f))
        .min()
        .unwrap_or(usize::MAX);
    let pipe_pos = l.find('|').unwrap_or(usize::MAX);
    fetch_pos < pipe_pos
}

fn is_download_chmod_exec(l: &str) -> bool {
    let fetched = ["curl -", "curl ", "wget ", "aria2c "]
        .iter()
        .any(|f| l.contains(f));
    let chmoded = l.contains("chmod +x") || l.contains("chmod 777") || l.contains("chmod 755");
    let executed_tmp = l.contains("/tmp/") && (l.contains("chmod") || has_exec_after_tmp(l));
    let hidden_exec = l.contains("/dev/shm/") || l.contains("$HOME/.cache");
    (fetched && chmoded) || executed_tmp || (fetched && hidden_exec && has_exec_verb(l))
}

fn has_exec_after_tmp(l: &str) -> bool {
    l.contains("/tmp/") && has_exec_verb(l)
}

fn has_exec_verb(l: &str) -> bool {
    l.contains("./")
        || l.contains("bash /tmp")
        || l.contains("sh /tmp")
        || l.contains("python /tmp")
}

fn is_decode_exec(l: &str) -> bool {
    let decoders = [
        "base64 -d",
        "base64 --decode",
        "xxd -r",
        "openssl enc -d",
        "base64 -di",
    ];
    let has_decoder = decoders.iter().any(|d| l.contains(d));
    let to_exec = l.contains("| bash")
        || l.contains("| sh")
        || l.contains("eval $(")
        || l.contains("eval \"$(")
        || (l.contains("$(") && l.contains("bash"));
    let hex_exec = l.contains("\\x") && (l.contains("eval") || l.contains("bash -c"));
    has_decoder && (to_exec || l.contains("chmod +x")) || hex_exec
}

fn is_eval_dynamic(l: &str) -> bool {
    (l.contains("eval ") || l.contains("eval\"") || l.contains("eval$("))
        && (l.contains("${") || l.contains("$(") || l.contains("eval $"))
}

fn is_priv_escalation(l: &str) -> bool {
    l.contains("sudo ")
        || l.contains(" su ")
        || l.contains("chmod +s")
        || l.contains("chmod u+s")
        || l.contains("setuid")
        || l.contains("polkit")
        || l.contains("authorized_keys")
        || l.contains("/etc/sudoers")
        || l.contains("chmod 4755")
        || l.contains("chmod 4777")
}

fn is_persistence(l: &str) -> bool {
    l.contains("systemctl enable")
        || l.contains("/etc/systemd/system")
        || l.contains("~/.config/autostart")
        || l.contains("/etc/cron")
        || l.contains("crontab")
        || l.contains(".bashrc")
        || l.contains(".zshrc")
        || l.contains("/etc/udev/rules")
        || l.contains("systemd --user")
}

fn is_credential_access(l: &str) -> bool {
    l.contains("~/.ssh")
        || l.contains("$HOME/.ssh")
        || l.contains("~/.gnupg")
        || l.contains(".aws/credentials")
        || l.contains("browser") && l.contains("cookies")
        || l.contains("/etc/shadow")
        || (l.contains("env") && l.contains("curl") && l.contains(" -d "))
}

fn is_lifecycle_exec(l: &str) -> bool {
    (l.contains("npm install") || l.contains("npm ci") || l.contains("bun install"))
        && !l.contains("--ignore-scripts")
        || l.contains("preinstall")
        || l.contains("postinstall")
        || l.contains("pip install")
            && (l.contains("--no-build-isolation") || l.contains("setup.py"))
        || l.contains("build.rs") && l.contains("Command::new")
}

fn is_dynamic_url_exec(l: &str) -> bool {
    let dynamic_markers = ["${", "$(", "`", "env "];
    let is_dynamic = dynamic_markers.iter().any(|m| l.contains(m));
    let fetch_exec = (l.contains("curl") || l.contains("wget"))
        && (l.contains("bash") || l.contains("chmod +x"));
    is_dynamic && fetch_exec
}

fn first_url(norm: &str) -> Option<String> {
    for tok in norm.split_whitespace() {
        let t = tok.trim_matches(|c| c == '"' || c == '\'' || c == ';' || c == ')');
        if t.starts_with("https://") || t.starts_with("http://") {
            let short = t.split('?').next().unwrap_or(t);
            return Some(short.chars().take(160).collect());
        }
    }
    None
}

fn excerpt_for(norm: &str) -> String {
    for line in norm.lines() {
        let l = line.to_lowercase();
        if l.contains("curl")
            || l.contains("wget")
            || l.contains("eval")
            || l.contains("base64")
            || l.contains("chmod")
            || l.contains("sudo")
            || l.contains("systemctl")
        {
            return truncate(line.trim(), 220);
        }
    }
    truncate(norm.lines().next().unwrap_or(""), 220)
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_owned()
    } else {
        format!("{}…", &s[..n])
    }
}

// FNV-1a pin so build refuses if the file changed since analysis.
// Real source verification (sha256/pgp) happens at build time.
fn short_hash(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}
