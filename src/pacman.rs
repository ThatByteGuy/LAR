// Installs local packages through the normal pacman path. Nothing else.
use crate::error::{LarError, Result};

pub async fn install(files: &[std::path::PathBuf]) -> Result<()> {
    if files.is_empty() {
        return Err(LarError::Io("no artifacts to install".to_owned()));
    }
    let escalator = escalator();
    let mut cmd = tokio::process::Command::new(&escalator);
    if escalator == "sudo" {
        cmd.arg("-n").arg("pacman").arg("-U").arg("--noconfirm");
    } else {
        cmd.arg("pacman").arg("-U").arg("--noconfirm");
    }
    for f in files {
        cmd.arg(f);
    }
    let status = cmd
        .status()
        .await
        .map_err(|e| LarError::Io(format!("spawn {escalator}: {e}")))?;
    if !status.success() {
        return Err(LarError::Io(format!(
            "{escalator} pacman -U exited {status}"
        )));
    }
    Ok(())
}

fn escalator() -> String {
    if let Ok(v) = std::env::var("LAR_ESCALATOR") {
        v
    } else if which("sudo") {
        "sudo".to_owned()
    } else {
        "doas".to_owned()
    }
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|p| p.join(bin).exists()))
}
