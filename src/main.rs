//! lar: run once per command, then exit. No daemon.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "CLI output is the product"
)]
use clap::Parser as _;
use lar_lib::{
    analyzer, aur,
    cli::{Cli, Command},
    config::Config,
    logging::{redact, SecurityEvent},
    security::Verdict,
};

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let cli = match yay_args() {
        Some(cli) => cli,
        None => Cli::parse(),
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async_main(cli))
        .map_err(|e| color_eyre::eyre::eyre!("{e}"))
}

// yay-shaped shortcuts, rewritten to lar commands before clap sees them.
fn yay_args() -> Option<Cli> {
    use lar_lib::cli::{PackageArg, SearchArgs, UpdateArgs};
    let mut args = std::env::args().skip(1);
    let first = args.next()?;
    let rest: Vec<String> = args.collect();
    let json = rest.iter().any(|a| a == "--json");
    let noconfirm = rest.iter().any(|a| a == "--noconfirm");
    let pos: Vec<String> = rest.into_iter().filter(|a| !a.starts_with("--")).collect();
    let command = match first.as_str() {
        "-S" => match pos.as_slice() {
            [pkg] => Command::Install(PackageArg {
                package: pkg.clone(),
            }),
            _ => return None,
        },
        "-Ss" => match pos.as_slice() {
            [q] => Command::Search(SearchArgs { query: q.clone() }),
            _ => return None,
        },
        "-Syu" | "-Suy" => Command::Update(UpdateArgs { aur_only: true }),
        _ => return None,
    };
    Some(Cli {
        json,
        noconfirm,
        command,
    })
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    let cfg = Config::load().unwrap_or_default();
    let json = cli.json;
    let noconfirm = cli.noconfirm;
    match cli.command {
        Command::Search(a) => {
            let pkgs = aur::search(&a.query)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&pkgs)?);
            } else {
                for p in pkgs.iter().take(30) {
                    println!(
                        "{} {} — {}",
                        p.name,
                        p.version,
                        p.description.as_deref().unwrap_or("")
                    );
                }
            }
        }
        Command::Info(a) => {
            let pkg = aur::info(&a.package)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&pkg)?);
            } else {
                println!("Name: {}", pkg.name);
                println!("Version: {}", pkg.version);
                println!("Maintainer: {}", pkg.maintainer.as_deref().unwrap_or("—"));
                println!("Description: {}", pkg.description.as_deref().unwrap_or("—"));
            }
        }
        Command::Inspect(a) => {
            let report = inspect_package(&a.package, &cfg).await?;
            print_report(&report, json)?;
            log_report(&a.package, "", &report, None);
            if matches!(report.verdict, Verdict::Blocked) && cfg.security.block_critical {
                std::process::exit(10);
            }
        }
        Command::Build(a) => {
            build_flow(&a.package, false, &cfg, json, noconfirm).await?;
        }
        Command::Install(a) => {
            build_flow(&a.package, true, &cfg, json, noconfirm).await?;
        }
        Command::Update(u) => {
            update_flow(u.aur_only, json, &cfg).await?;
        }
        Command::Audit(a) => {
            if let Some(pkg) = a.package.as_deref() {
                let report = inspect_package(pkg, &cfg).await?;
                print_report(&report, json)?;
            } else {
                println!("audit: pass a package name in MVP");
            }
        }
        Command::Rules(r) => {
            if r.action == "list" {
                for rule in lar_lib::rules::builtin_rules() {
                    println!(
                        "{} [{}] {} — {}",
                        rule.id,
                        format!("{:?}", rule.severity).to_lowercase(),
                        rule.title,
                        format!("{:?}", rule.action).to_lowercase()
                    );
                }
            }
        }
        Command::Config(c) => {
            let action = c.action.as_deref().unwrap_or("path");
            match action {
                "path" => println!("{}", Config::user_path().display()),
                "get" => {
                    let key = c.key.unwrap_or_default();
                    let cfg = Config::load().unwrap_or_default();
                    println!("{} = {}", key, config_get(&cfg, &key));
                }
                "set" => {
                    let (Some(key), Some(value)) = (c.key, c.value) else {
                        anyhow::bail!("usage: lar config set <section.key> <value>");
                    };
                    if key == "security.allow_malware_sources" && value == "true" {
                        eprintln!("WARNING: SUSPICIOUS packages will build without asking. BLOCKED still needs overrides.");
                        if !confirm("Type yes to confirm you understand [y/N] ") {
                            return Ok(());
                        }
                    }
                    let mut cfg = Config::load().unwrap_or_default();
                    lar_lib::config::apply_set(&mut cfg, &key, &value)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    cfg.save().map_err(|e| anyhow::anyhow!("{e}"))?;
                    println!("{key} = {value}");
                }
                _ => println!("config: use `get <key>`, `set <key> <v>`, or `path`"),
            }
        }
        Command::Override(o) => {
            let scope_count = usize::from(o.once)
                + usize::from(o.version.is_some())
                + usize::from(o.hash.is_some());
            if scope_count != 1 {
                anyhow::bail!("pick exactly one scope: --once, --version <v>, or --hash <h>");
            }
            let scope = if o.once {
                "once"
            } else if o.version.is_some() {
                "version"
            } else {
                "hash"
            };
            if scope != "once"
                && !confirm(
                    format!("Override {} for {} ({scope})? [y/N] ", o.rule, o.package).as_str(),
                )
            {
                return Ok(());
            }
            lar_lib::overrides::add(lar_lib::overrides::Override {
                package: o.package.clone(),
                rule: o.rule.clone(),
                scope: scope.to_owned(),
                version: o.version.clone(),
                hash: o.hash.clone(),
            });
            let ev = SecurityEvent {
                ts: "0".to_owned(),
                package: o.package,
                version: o.version.unwrap_or_default(),
                verdict: "override".to_owned(),
                rules: vec![o.rule],
                score: 0,
                override_scope: Some(scope.to_owned()),
                build: None,
                install: None,
            };
            ev.append();
            println!("override recorded ({scope})");
        }
    }
    Ok(())
}

async fn build_flow(
    pkg: &str,
    install: bool,
    cfg: &Config,
    json: bool,
    noconfirm: bool,
) -> anyhow::Result<()> {
    if !cfg.security.enabled {
        anyhow::bail!("security disabled in config; refusing to build (fail-closed)");
    }
    let raw = aur::fetch_pkgbuild(pkg)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let local = analyze_with_helpers(pkg, &raw).await?;
    let report = consult_reputation(pkg, &raw, local, cfg).await;
    print_report(&report, json)?;
    log_report(pkg, "", &report, None);
    match report.verdict {
        Verdict::Blocked => {
            let blocked_ids: Vec<&str> = report
                .findings
                .iter()
                .filter(|f| f.action == lar_lib::security::Action::Block)
                .map(|f| f.rule_id.as_str())
                .collect();
            let version = aur::info(pkg).await.map(|p| p.version).unwrap_or_default();
            let mut cleared = true;
            for id in &blocked_ids {
                let list = lar_lib::overrides::load();
                let hit = list
                    .iter()
                    .any(|o| lar_lib::overrides::matches(o, pkg, id, &version, &report.input_hash));
                if hit {
                    lar_lib::overrides::consume_once(pkg, id);
                } else {
                    cleared = false;
                }
            }
            if !cleared {
                eprintln!("BLOCKED: use `lar override {pkg} --rule <id> --once|--version|--hash` after review.");
                std::process::exit(10);
            }
            if !noconfirm && !confirm("Proceed with overridden BLOCK findings? [y/N] ") {
                return Ok(());
            }
        }
        Verdict::Suspicious => {
            if !cfg.security.allow_malware_sources
                && !noconfirm
                && !confirm("Proceed despite SUSPICIOUS findings? [y/N] ")
            {
                std::process::exit(11);
            }
        }
        Verdict::Unknown => {
            eprintln!("UNKNOWN: analysis unreliable; refusing (fail-closed).");
            std::process::exit(20);
        }
        Verdict::Analyzed | Verdict::Verified => {
            if !noconfirm && !confirm("Build this package? [y/N] ") {
                return Ok(());
            }
        }
    }
    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("PKGBUILD"), &raw)?;
    // TOCTOU: the file changed under us, the analysis is void.
    let staged = std::fs::read_to_string(dir.path().join("PKGBUILD"))?;
    if staged != raw {
        anyhow::bail!("PKGBUILD changed between analysis and build; refusing (fail-closed)");
    }
    aur::cache_pkgbuild(pkg, &raw);
    let backend = lar_lib::sandbox::Backend::from_config(&cfg.build);
    let artifacts = lar_lib::makepkg::build(dir.path(), &backend)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let summary = lar_lib::package::inspect_dir(dir.path())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    for w in &summary.warnings {
        eprintln!("artifact warning: {}", redact(w));
    }
    if install {
        lar_lib::pacman::install(&artifacts)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok(())
}

// PKGBUILD plus its .install file if it declares one. Findings merge.
async fn inspect_package(
    package: &str,
    cfg: &Config,
) -> anyhow::Result<lar_lib::security::AnalysisReport> {
    let raw = aur::fetch_pkgbuild(package)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let report = analyze_with_helpers(package, &raw).await?;
    aur::cache_pkgbuild(package, &raw);
    Ok(consult_reputation(package, &raw, report, cfg).await)
}

// Remote input only when the user configured a trust root. Failures stay local.
async fn consult_reputation(
    package: &str,
    raw: &str,
    report: lar_lib::security::AnalysisReport,
    cfg: &Config,
) -> lar_lib::security::AnalysisReport {
    if !cfg.network.online_checks || cfg.network.trust_root.is_empty() {
        return report;
    }
    let version = aur::info(package)
        .await
        .map(|p| p.version)
        .unwrap_or_default();
    let hash = lar_lib::reputation::sha256_hex(raw);
    let view = match lar_lib::reputation::fetch_verified(
        &cfg.network.reputation_url,
        &cfg.network.trust_root,
        package,
        &version,
        &hash,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("reputation unavailable: {e}");
            return report;
        }
    };
    let merged = lar_lib::reputation::merge(report, &view);
    lar_lib::reputation::confirm_hash(merged, &view, &hash)
}

async fn analyze_with_helpers(
    package: &str,
    raw: &str,
) -> anyhow::Result<lar_lib::security::AnalysisReport> {
    let main = analyzer::analyze(package, raw);
    let parsed = match lar_lib::pkgbuild::Pkgbuild::parse(raw) {
        Ok(p) => p,
        Err(_) => return Ok(main),
    };
    let Some(install) = parsed.install_ref else {
        return Ok(main);
    };
    let helper = match aur::fetch_file(package, &install).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("warning: could not fetch {install}: {e}");
            return Ok(main);
        }
    };
    let Some(text) = helper else { return Ok(main) };
    let mut extra = analyzer::analyze_file(package, &install, &text);
    let mut findings = main.findings;
    findings.append(&mut extra.findings);
    Ok(lar_lib::security::AnalysisReport::decide(
        package,
        findings,
        &main.input_hash,
    ))
}

fn installed_foreign_packages() -> anyhow::Result<Vec<(String, String)>> {
    let out = std::process::Command::new("pacman").arg("-Qm").output()?;
    if !out.status.success() {
        anyhow::bail!("pacman -Qm failed");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text.lines().filter_map(aur::parse_qm_line).collect())
}

async fn update_flow(_aur_only: bool, json: bool, cfg: &Config) -> anyhow::Result<()> {
    let installed = installed_foreign_packages()?;
    if installed.is_empty() {
        println!("no foreign packages installed");
        return Ok(());
    }
    let names: Vec<String> = installed.iter().map(|(n, _)| n.clone()).collect();
    // debt: batches of 50 keep URLs short; pacman -Qm lists are small
    let mut remote: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for chunk in names.chunks(50) {
        let pkgs = aur::info_many(chunk)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        for p in pkgs {
            remote.insert(p.name.clone(), p.version.clone());
        }
    }
    let mut outdated = 0;
    for (name, ver) in &installed {
        match remote.get(name) {
            None => println!("{name} {ver} — not in AUR, skipping"),
            Some(rv) if !aur::needs_update(ver, rv) => {}
            Some(rv) => {
                outdated += 1;
                println!("{name} {ver} -> {rv}");
                match diff_cached(name).await {
                    Ok(Some(diff)) => println!("{diff}"),
                    Ok(None) => {}
                    Err(e) => eprintln!("warning: diff failed for {name}: {e}"),
                }
                let report = inspect_package(name, cfg).await?;
                print_report(&report, json)?;
            }
        }
    }
    if outdated == 0 {
        println!("everything up to date");
    }
    Ok(())
}

// Line diff of cached vs fresh PKGBUILD. None = no cached copy yet.
async fn diff_cached(package: &str) -> anyhow::Result<Option<String>> {
    let old = aur::read_cached_pkgbuild(package);
    let fresh = aur::fetch_pkgbuild(package)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let Some(old) = old else {
        aur::cache_pkgbuild(package, &fresh);
        return Ok(None);
    };
    if old == fresh {
        return Ok(None);
    }
    let old_lines: Vec<&str> = old.lines().collect();
    let fresh_lines: Vec<&str> = fresh.lines().collect();
    let mut out = String::from("--- cached\n+++ aur\n");
    let max = old_lines.len().max(fresh_lines.len());
    for i in 0..max {
        let o = old_lines.get(i).copied().unwrap_or("");
        let n = fresh_lines.get(i).copied().unwrap_or("");
        if o != n {
            out.push_str(&format!("-{o}\n+{n}\n"));
        }
    }
    aur::cache_pkgbuild(package, &fresh);
    Ok(Some(out))
}

fn print_report(report: &lar_lib::security::AnalysisReport, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    println!("Package: {}", report.package);
    println!(
        "Verdict: {:?} — {}",
        report.verdict,
        report.verdict.subtitle()
    );
    println!("Score: {} (ordering only)", report.score);
    for f in &report.findings {
        println!(
            "  [{}] {:?} {} @ {} — {}",
            f.rule_id,
            f.severity,
            f.title,
            f.span,
            redact(&f.excerpt)
        );
        if let Some(u) = &f.url {
            println!("       url: {}", redact(u));
        }
        println!("       why: {}", f.why);
        println!("       fix: {}", f.recommendation);
    }
    Ok(())
}

fn log_report(
    pkg: &str,
    ver: &str,
    report: &lar_lib::security::AnalysisReport,
    override_scope: Option<String>,
) {
    let rules: Vec<String> = report.findings.iter().map(|f| f.rule_id.clone()).collect();
    let mut ev = SecurityEvent::new(
        pkg,
        ver,
        &format!("{:?}", report.verdict),
        &rules,
        report.score,
    );
    ev.override_scope = override_scope;
    ev.append();
}

fn confirm(prompt: &str) -> bool {
    use std::io::Write as _;
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap_or(0);
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

fn config_get(cfg: &Config, key: &str) -> String {
    match key {
        "security.enabled" => cfg.security.enabled.to_string(),
        "security.block_critical" => cfg.security.block_critical.to_string(),
        "security.allow_malware_sources" => cfg.security.allow_malware_sources.to_string(),
        "network.online_checks" => cfg.network.online_checks.to_string(),
        "network.trust_root" => cfg.network.trust_root.clone(),
        "network.reputation_url" => cfg.network.reputation_url.clone(),
        "build.backend" => cfg.build.backend.clone(),
        "ui.theme" => cfg.ui.theme.clone(),
        _ => "unknown key".to_owned(),
    }
}
