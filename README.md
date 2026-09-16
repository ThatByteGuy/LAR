# LAR

Security-first AUR helper. Looks at what a package does before letting it run.

The AUR is untrusted. LAR reads the PKGBUILD and related files, flags shady
behavior, and only then builds. No blind `makepkg`.

## Status

Early MVP. CLI works, TUI not started yet.

## Install

```
cargo build --release
```

## Use

```
lar search <query>
lar info <pkg>
lar inspect <pkg>     # fetch + analyze, no build
lar build <pkg>       # analyze, then makepkg
lar install <pkg>     # analyze, build, install via pacman
lar update            # re-check installed AUR packages, diff + re-analyze
lar rules list
lar config path
lar config set <key> <value>

Same thing yay-style: `lar -S <pkg>`, `lar -Ss <query>`, `lar -Syu`.
```

Blocked packages exit 10. Suspicious ones ask first. There is no `--force`.
If you reviewed a finding and want to proceed:

```
lar override <pkg> --rule <id> --once
lar override <pkg> --rule <id> --version <v>
lar override <pkg> --rule <id> --hash <h>
```

## How it works

Fetch PKGBUILD -> parse (no exec) -> normalize -> behavior checks ->
rules -> verdict -> ask user -> makepkg as your user -> pacman -U via sudo.

Verdicts: `UNKNOWN`, `ANALYZED`, `SUSPICIOUS`, `BLOCKED`, `VERIFIED`.
`ANALYZED` means "nothing known-bad found", not "safe".
`VERIFIED` means "matched trusted metadata", not "guaranteed safe".
A local `BLOCKED` is never cleared by the network.

## Rules

Builtin rules live in `src/rules.rs`. Examples:

- `LAR-NET-001` pipe download into shell
- `LAR-NET-002` download, chmod +x, run
- `LAR-OBF-001` decode then run
- `LAR-PRIV-001` sudo/suid/ssh meddling
- `LAR-EXFIL-001` touching `~/.ssh` etc.

`curl` alone is fine. `curl ... | bash` is not.

## Config

`~/.config/lar/config.toml`, fallback `/etc/lar/config.toml`.
Logs go to `~/.local/share/lar/security.log` (no secrets in there).

Builds run direct by default. For filesystem isolation:
`lar config set build.backend bwrap` (needs bubblewrap; network stays on
so makepkg can fetch sources).

## Dev

```
cargo test
cargo clippy --all-targets -- -D warnings
```

Tests in `tests/analyzer_tests.rs` cover legit, malicious, and evasion samples.
Legit packages using curl/git/npm must not get blocked.

## Layout

```
src/
  main.rs      cli wiring
  cli.rs       arg shapes
  lib.rs       module list
  analyzer.rs  parse -> findings -> verdict
  pkgbuild.rs  shell parse + normalize, no exec
  rules.rs     builtin rules
  security.rs  verdict/finding types
  aur.rs       rpc + pkgbuild fetch
  makepkg.rs   build as non-root, argv only
  pacman.rs    install via sudo/doas
  package.rs   artifact peek
  config.rs    toml config
  logging.rs   jsonl log + redaction
  error.rs     error enum
```

Upstream: https://github.com/ThatByteGuy/LAR.git
