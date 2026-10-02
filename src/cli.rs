use clap::Parser;

#[derive(Parser)]
#[command(name = "dott", version, about = "private domain search. no middlemen.")]
#[command(group(clap::ArgGroup::new("action").args(["name", "suggest", "update", "watch", "unwatch", "watching", "background_check", "notify", "pending", "shell_notice"]).multiple(false)))]
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
    /// Show watchlist updates in new zsh windows (adds or removes one line in ~/.zshrc)
    #[arg(long, value_name = "on|off", value_parser = ["on", "off"])]
    pub shell_notice: Option<String>,
    /// Internal: print unseen watchlist updates (run from ~/.zshrc).
    #[arg(long, hide = true)]
    pub pending: bool,
    /// Internal: post a notification from inside ~/.dott/dott.app (macOS).
    #[arg(long, hide = true, num_args = 2, value_names = ["TITLE", "BODY"])]
    pub notify: Option<Vec<String>>,
}
