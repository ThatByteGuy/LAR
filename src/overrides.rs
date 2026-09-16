use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Override {
    pub package: String,
    pub rule: String,
    pub scope: String,
    pub version: Option<String>,
    pub hash: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    overrides: Vec<Override>,
}

pub fn path() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("LAR_STATE_DIR") {
        return std::path::PathBuf::from(dir).join("overrides.toml");
    }
    dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".local/share/lar/overrides.toml")
}

// Bad TOML = no overrides. Blocks stay on. Fail closed.
#[must_use]
pub fn load() -> Vec<Override> {
    std::fs::read_to_string(path())
        .ok()
        .and_then(|t| toml::from_str::<Store>(&t).ok())
        .map(|s| s.overrides)
        .unwrap_or_default()
}

pub fn add(o: Override) {
    let mut list = load();
    list.push(o);
    let _ = save(&list);
}

fn save(list: &[Override]) -> std::io::Result<()> {
    let path = path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = toml::to_string(&Store {
        overrides: list.to_vec(),
    })
    .unwrap_or_default();
    std::fs::write(&path, text)
}

#[must_use]
pub fn matches(o: &Override, package: &str, rule: &str, version: &str, hash: &str) -> bool {
    if o.package != package || o.rule != rule {
        return false;
    }
    match o.scope.as_str() {
        "once" => true,
        "version" => o.version.as_deref() == Some(version),
        "hash" => o.hash.as_deref() == Some(hash),
        _ => false,
    }
}

// A used-up "once" is deleted. Returns true if one was found.
pub fn consume_once(package: &str, rule: &str) -> bool {
    let mut list = load();
    let before = list.len();
    list.retain(|o| !(o.scope == "once" && o.package == package && o.rule == rule));
    let used = list.len() < before;
    if used {
        let _ = save(&list);
    }
    used
}
