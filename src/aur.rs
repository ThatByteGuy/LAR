// All network lives here. The analyzer never touches the net.
use crate::error::{LarError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AurPackage {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Maintainer")]
    pub maintainer: Option<String>,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "NumVotes")]
    pub votes: Option<u32>,
    #[serde(rename = "Popularity")]
    pub popularity: Option<f64>,
    #[serde(rename = "Depends")]
    pub depends: Option<Vec<String>>,
    #[serde(rename = "MakeDepends")]
    pub make_depends: Option<Vec<String>>,
    #[serde(rename = "PackageBase")]
    pub base: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    results: T,
}

const AUR_RPC: &str = "https://aur.archlinux.org/rpc/v5";
const AUR_CGIT_ROOT: &str = "https://aur.archlinux.org/cgit/aur.git/plain";

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("lar/0.1.0")
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

pub async fn search(query: &str) -> Result<Vec<AurPackage>> {
    // v5 path form ignores the query. Legacy query form actually filters.
    let url = format!(
        "https://aur.archlinux.org/rpc/?v=5&type=search&arg={}",
        urlencoding(query)
    );
    let resp = client()
        .get(&url)
        .send()
        .await
        .map_err(|e| LarError::Fetch("aur-search".to_owned(), e.to_string()))?;
    let body: RpcResponse<Vec<AurPackage>> = resp
        .json()
        .await
        .map_err(|e| LarError::Fetch("aur-search".to_owned(), e.to_string()))?;
    Ok(body.results)
}

pub async fn info(package: &str) -> Result<AurPackage> {
    let pkgs = info_many(&[package.to_owned()]).await?;
    pkgs.into_iter()
        .next()
        .ok_or_else(|| LarError::Fetch(package.to_owned(), "not found".to_owned()))
}

// Batch lookup. One request for many packages instead of one per package.
pub async fn info_many(packages: &[String]) -> Result<Vec<AurPackage>> {
    let mut url = format!("{AUR_RPC}/info");
    for p in packages {
        url.push_str(&format!("?arg[]={}&", urlencoding(p)));
    }
    // debt: naive query build is fine under ~200 pkgs; batch above that
    let resp = client()
        .get(url.trim_end_matches('&'))
        .send()
        .await
        .map_err(|e| LarError::Fetch("aur-info".to_owned(), e.to_string()))?;
    let body: RpcResponse<Vec<AurPackage>> = resp
        .json()
        .await
        .map_err(|e| LarError::Fetch("aur-info".to_owned(), e.to_string()))?;
    Ok(body.results)
}

// Any repo file via cgit plain. None = absent (404), not an error.
pub async fn fetch_file(package: &str, filename: &str) -> Result<Option<String>> {
    let url = format!("{AUR_CGIT_ROOT}/{filename}?h={}", urlencoding(package));
    let resp = client()
        .get(&url)
        .send()
        .await
        .map_err(|e| LarError::Fetch(package.to_owned(), e.to_string()))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(LarError::Fetch(
            package.to_owned(),
            format!("http {}", resp.status()),
        ));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| LarError::Fetch(package.to_owned(), e.to_string()))?;
    if bytes.len() > 512_000 {
        return Err(LarError::Fetch(
            package.to_owned(),
            format!("{filename} too large"),
        ));
    }
    String::from_utf8(bytes.to_vec())
        .map(Some)
        .map_err(|e| LarError::Fetch(package.to_owned(), format!("non-utf8: {e}")))
}

// Plain cgit endpoint, read-only, capped at 512k.
pub async fn fetch_pkgbuild(package: &str) -> Result<String> {
    fetch_file(package, "PKGBUILD")
        .await?
        .ok_or_else(|| LarError::Fetch(package.to_owned(), "PKGBUILD not found".to_owned()))
}

// `pacman -Qm` line: "name version". None on garbage.
#[must_use]
pub fn parse_qm_line(line: &str) -> Option<(String, String)> {
    let (name, ver) = line.split_once(' ')?;
    if name.is_empty() || ver.is_empty() || ver.contains(' ') {
        return None;
    }
    Some((name.to_owned(), ver.to_owned()))
}

// String compare only. Real vercmp needs alpm; same string = same version.
#[must_use]
pub fn needs_update(installed: &str, aur: &str) -> bool {
    installed != aur
}

fn cache_path(package: &str) -> std::path::PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("lar/pkgbuild")
        .join(format!("{package}.PKGBUILD"))
}

pub fn cache_pkgbuild(package: &str, raw: &str) {
    let path = cache_path(package);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, raw);
}

#[must_use]
pub fn read_cached_pkgbuild(package: &str) -> Option<String> {
    std::fs::read_to_string(cache_path(package)).ok()
}

// Small path-segment encoder so we don't pull another dep.
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
