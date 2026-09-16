use crate::config::BuildConfig;

pub enum Backend {
    Direct,
    Bwrap,
}

impl Backend {
    #[must_use]
    pub fn from_config(build: &BuildConfig) -> Self {
        if build.sandbox || build.backend == "bwrap" {
            Self::Bwrap
        } else {
            Self::Direct
        }
    }
}

// debt: net stays shared so makepkg can fetch sources. Full isolation
// needs source prefetch first; fs is locked down now.
#[must_use]
pub fn bwrap_argv(build_dir: &str) -> Vec<String> {
    vec![
        "bwrap".to_owned(),
        "--unshare-pid".to_owned(),
        "--unshare-uts".to_owned(),
        "--unshare-ipc".to_owned(),
        "--unshare-cgroup".to_owned(),
        "--die-with-parent".to_owned(),
        "--new-session".to_owned(),
        "--ro-bind".to_owned(),
        "/".to_owned(),
        "/".to_owned(),
        "--tmpfs".to_owned(),
        "/tmp".to_owned(),
        "--tmpfs".to_owned(),
        "/run".to_owned(),
        "--dir".to_owned(),
        "/tmp/lar-home".to_owned(),
        "--proc".to_owned(),
        "/proc".to_owned(),
        "--dev".to_owned(),
        "/dev".to_owned(),
        "--bind".to_owned(),
        build_dir.to_owned(),
        build_dir.to_owned(),
        "--setenv".to_owned(),
        "HOME".to_owned(),
        "/tmp/lar-home".to_owned(),
        "--chdir".to_owned(),
        build_dir.to_owned(),
        "makepkg".to_owned(),
        "-s".to_owned(),
        "--noconfirm".to_owned(),
    ]
}
