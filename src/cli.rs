use clap::Parser;

#[derive(Parser)]
#[command(name = "dott", version, about = "private domain search. no middlemen.")]
#[command(group(clap::ArgGroup::new("action").args(["name", "suggest", "update", "watch", "unwatch", "watching", "background_check"]).multiple(false)))]
pub struct Cli {
    pub name: Option<String>,
    #[arg(short, long, conflicts_with_all = ["watch", "unwatch", "watching", "background_check"])]
    pub tlds: Option<String>,
    #[arg(short, long, num_args = 1..)]
    pub suggest: Option<Vec<String>>,
    #[arg(long, conflicts_with_all = ["watch", "unwatch", "watching", "background_check"])]
    pub plain: bool,
    /// Update dott using Homebrew or the standalone installer
    #[arg(long, conflicts_with_all = ["name", "suggest", "tlds", "plain", "watch", "unwatch", "watching", "background_check"])]
    pub update: bool,
    #[arg(long, value_name = "DOMAIN")]
    pub watch: Option<String>,
    #[arg(long, value_name = "DOMAIN")]
    pub unwatch: Option<String>,
    #[arg(long)]
    pub watching: bool,
    #[arg(long, hide = true)]
    pub background_check: bool,
}
