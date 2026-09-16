// Runs makepkg. Structured argv only, no shell. Never as root.
use crate::error::{LarError, Result};
use crate::sandbox::Backend;

pub fn refuse_root() -> Result<()> {
    // SAFETY: geteuid takes no args, returns the uid. Cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return Err(LarError::Refused("do not run makepkg as root".to_owned()));
    }
    Ok(())
}

pub async fn build(dir: &std::path::Path, backend: &Backend) -> Result<Vec<std::path::PathBuf>> {
    refuse_root()?;
    let status = match backend {
        Backend::Direct => tokio::process::Command::new("makepkg")
            .arg("-s")
            .arg("--noconfirm")
            .current_dir(dir)
            .status()
            .await
            .map_err(|e| LarError::Io(format!("spawn makepkg: {e}")))?,
        Backend::Bwrap => {
            let Some(dir_str) = dir.to_str() else {
                return Err(LarError::Io("build dir is not utf-8".to_owned()));
            };
            let argv = crate::sandbox::bwrap_argv(dir_str);
            let status = tokio::process::Command::new(&argv[0])
                .args(&argv[1..])
                .status()
                .await
                .map_err(|e| LarError::Io(format!("spawn bwrap: {e}")))?;
            if !status.success() {
                let code = status.code().unwrap_or(-1);
                if code == 127 {
                    return Err(LarError::Io(
                        "bwrap not found; install bubblewrap or use build.backend=makepkg"
                            .to_owned(),
                    ));
                }
            }
            status
        }
    };
    if !status.success() {
        return Err(LarError::Io(format!("makepkg exited {status}")));
    }
    let mut out = Vec::new();
    let mut rd = tokio::fs::read_dir(dir).await.map_err(LarError::from)?;
    while let Some(ent) = rd.next_entry().await.map_err(LarError::from)? {
        let p = ent.path();
        if p.extension().is_some_and(|e| e == "zst") {
            out.push(p);
        }
    }
    Ok(out)
}
