use crate::error::{LarError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub security: SecurityConfig,
    pub network: NetworkConfig,
    pub build: BuildConfig,
    pub ui: UiConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            security: SecurityConfig {
                enabled: true,
                block_critical: true,
                allow_malware_sources: false,
                require_confirm_on_review: true,
            },
            network: NetworkConfig {
                online_checks: true,
                timeout_secs: 5,
                trust_root: String::new(),
                reputation_url: "https://reputation.lar.example/v1".to_owned(),
            },
            build: BuildConfig {
                backend: "makepkg".to_owned(),
                sandbox: false,
            },
            ui: UiConfig {
                theme: "default".to_owned(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enabled: bool,
    pub block_critical: bool,
    // hard to turn on by design: cli requires explicit typed confirm
    pub allow_malware_sources: bool,
    pub require_confirm_on_review: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub online_checks: bool,
    pub timeout_secs: u64,
    // empty = reputation off. Set to the service's ed25519 pubkey hex to enable.
    pub trust_root: String,
    pub reputation_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildConfig {
    // makepkg today, sandbox backends later
    pub backend: String,
    pub sandbox: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    pub theme: String,
}

impl Config {
    // defaults < /etc/lar/config.toml < ~/.config/lar/config.toml.
    // Missing files are fine. Bad TOML is an error, not a silent default.
    pub fn load() -> Result<Self> {
        let mut cfg = Self::default();
        for path in Self::paths() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                let parsed: Self = toml::from_str(&text)
                    .map_err(|e| LarError::Config(format!("{}: {e}", path.display())))?;
                cfg = parsed;
            }
        }
        Ok(cfg)
    }

    #[must_use]
    pub fn paths() -> Vec<PathBuf> {
        let mut v = vec![PathBuf::from("/etc/lar/config.toml")];
        if let Some(home) = dirs::home_dir() {
            v.push(home.join(".config/lar/config.toml"));
        }
        v
    }

    #[must_use]
    pub fn user_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".config/lar/config.toml")
    }

    pub fn save(&self) -> crate::error::Result<()> {
        let path = Self::user_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(crate::error::LarError::from)?;
        }
        let text =
            toml::to_string(self).map_err(|e| crate::error::LarError::Config(e.to_string()))?;
        std::fs::write(&path, text).map_err(crate::error::LarError::from)?;
        Ok(())
    }
}

// Sets one `section.key` from `lar config set`. Err on unknown keys.
pub fn apply_set(cfg: &mut Config, key: &str, value: &str) -> crate::error::Result<()> {
    let bad = || crate::error::LarError::Config(format!("unknown key: {key}"));
    let boolean = |v: &str| match v {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(crate::error::LarError::Config(format!(
            "want true/false, got: {v}"
        ))),
    };
    match key {
        "security.enabled" => cfg.security.enabled = boolean(value)?,
        "security.block_critical" => cfg.security.block_critical = boolean(value)?,
        "security.allow_malware_sources" => cfg.security.allow_malware_sources = boolean(value)?,
        "security.require_confirm_on_review" => {
            cfg.security.require_confirm_on_review = boolean(value)?
        }
        "network.online_checks" => cfg.network.online_checks = boolean(value)?,
        "network.trust_root" => cfg.network.trust_root = value.to_owned(),
        "network.reputation_url" => cfg.network.reputation_url = value.to_owned(),
        "network.timeout_secs" => {
            cfg.network.timeout_secs = value.parse().map_err(|_| {
                crate::error::LarError::Config(format!("want number, got: {value}"))
            })?;
        }
        "build.backend" => cfg.build.backend = value.to_owned(),
        "build.sandbox" => cfg.build.sandbox = boolean(value)?,
        "ui.theme" => cfg.ui.theme = value.to_owned(),
        _ => return Err(bad()),
    }
    Ok(())
}
