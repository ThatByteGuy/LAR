// MVP heuristic: list build outputs, flag names that smell like persistence.
use crate::error::Result;

#[derive(Debug, Clone)]
pub struct ArtifactSummary {
    pub files: Vec<String>,
    pub warnings: Vec<String>,
}

pub async fn inspect_dir(dir: &std::path::Path) -> Result<ArtifactSummary> {
    let mut files = Vec::new();
    let mut warnings = Vec::new();
    let mut rd = tokio::fs::read_dir(dir).await?;
    while let Some(ent) = rd.next_entry().await? {
        let name = ent.file_name().to_string_lossy().into_owned();
        files.push(name.clone());
        let lower = name.to_lowercase();
        if lower.contains("setuid") || lower.contains(".service") {
            warnings.push(format!("artifact hints at privilege/persistence: {name}"));
        }
    }
    Ok(ArtifactSummary { files, warnings })
}
