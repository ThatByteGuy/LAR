// Arg shapes. Decisions live in the engine, never here.
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "lar",
    version,
    about = "Security-first AUR helper",
    arg_required_else_help = true
)]
pub struct Cli {
    #[arg(long, global = true)]
    pub json: bool,
    // never bypasses BLOCK
    #[arg(long, global = true)]
    pub noconfirm: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Search(SearchArgs),
    Info(PackageArg),
    Inspect(PackageArg),
    Build(PackageArg),
    Install(PackageArg),
    Update(UpdateArgs),
    Audit(AuditArgs),
    Rules(RulesArgs),
    Config(ConfigArgs),
    // scoped, logged. there is no --force.
    Override(OverrideArgs),
}

#[derive(Debug, Args)]
pub struct PackageArg {
    pub package: String,
}

#[derive(Debug, Args)]
pub struct SearchArgs {
    pub query: String,
}

#[derive(Debug, Args)]
pub struct UpdateArgs {
    #[arg(long, default_value_t = true)]
    pub aur_only: bool,
}

#[derive(Debug, Args)]
pub struct AuditArgs {
    pub package: Option<String>,
}

#[derive(Debug, Args)]
pub struct RulesArgs {
    #[arg(default_value = "list")]
    pub action: String,
}

#[derive(Debug, Args)]
pub struct ConfigArgs {
    pub action: Option<String>,
    pub key: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Args)]
pub struct OverrideArgs {
    pub package: String,
    #[arg(long)]
    pub rule: String,
    #[arg(long, default_value_t = false)]
    pub once: bool,
    #[arg(long)]
    pub version: Option<String>,
    #[arg(long)]
    pub hash: Option<String>,
}
