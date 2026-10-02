// Watchlist changes waiting to be seen, plus the optional ~/.zshrc line that shows them in every
// new terminal window. Notices are shown until the user opens dott or runs `dott --watching`.
use colored::*;
use serde::{Deserialize, Serialize};
use std::{fs, io::{self, Write}, path::{Path, PathBuf}};

use crate::utils::epoch_days_to_date;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Notice {
    pub domain: String,
    pub status: String,
    pub at: u64,
}

fn notices_path(dir: &Path) -> PathBuf { dir.join("notices.json") }

// Missing or unreadable notices only mean nothing to show; they never block a check.
pub fn load(dir: &Path) -> Vec<Notice> {
    fs::read(notices_path(dir)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// Records a change; the latest change per domain replaces older ones. Call under the watchlist lock.
pub fn record(dir: &Path, domain: &str, status: &str, at: u64) -> io::Result<()> {
    let mut notices = load(dir);
    notices.retain(|n| n.domain != domain);
    notices.push(Notice { domain: domain.into(), status: status.into(), at });
    write_atomic(&notices_path(dir), &serde_json::to_vec_pretty(&notices).map_err(io::Error::other)?)
}

/// Marks everything as seen. Call under the watchlist lock.
pub fn clear(dir: &Path) {
    let _ = fs::remove_file(notices_path(dir));
}

pub fn line(notice: &Notice) -> String {
    let (mark, what) = match notice.status.as_str() {
        "available" => ("✓".bright_green().bold(), "became available"),
        "taken" => ("✗".truecolor(110, 100, 150), "was registered"),
        "protected" => ("★".bright_yellow(), "is now reserved"),
        _ => ("?".bright_yellow(), "changed status"),
    };
    let date = epoch_days_to_date((notice.at / 86_400) as i64);
    format!("{mark} {} {what} {}", notice.domain.bright_white().bold(), format!("· {date}").truecolor(80, 80, 100))
}

// ── ~/.zshrc line ──────────────────────────────────────────────

const MARK: &str = "# added by dott";
pub const HOOK: &str = "command -v dott >/dev/null && dott --pending 2>/dev/null  # added by dott (dott --shell-notice off to remove)";

pub fn uses_zsh() -> bool {
    std::env::var("SHELL").is_ok_and(|s| s.ends_with("/zsh"))
}

pub fn zshrc_path() -> Option<PathBuf> {
    let dir = std::env::var_os("ZDOTDIR").or_else(|| std::env::var_os("HOME"))?;
    Some(PathBuf::from(dir).join(".zshrc"))
}

// Dotfile managers often symlink ~/.zshrc; edit the real file instead of replacing the link.
fn real(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn read_or_empty(path: &Path) -> io::Result<String> {
    match fs::read_to_string(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        other => other,
    }
}

pub fn has_hook(path: &Path) -> bool {
    fs::read_to_string(real(path)).is_ok_and(|text| text.contains(MARK))
}

/// Appends the line, creating the file if needed. Leaves every other byte untouched.
pub fn add_hook(path: &Path) -> io::Result<()> {
    let path = real(path);
    let mut text = read_or_empty(&path)?;
    if text.contains(MARK) { return Ok(()); }
    if !text.is_empty() && !text.ends_with('\n') { text.push('\n'); }
    text.push_str(HOOK);
    text.push('\n');
    write_atomic(&path, text.as_bytes())
}

/// Removes only dott's line; deletes the file when nothing else is left in it.
pub fn remove_hook(path: &Path) -> io::Result<bool> {
    let path = real(path);
    let text = read_or_empty(&path)?;
    if !text.contains(MARK) { return Ok(false); }
    let kept: String = text.split_inclusive('\n').filter(|l| !l.contains(MARK)).collect();
    if kept.trim().is_empty() {
        fs::remove_file(&path)?;
    } else {
        write_atomic(&path, kept.as_bytes())?;
    }
    Ok(true)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| io::Error::other("Missing parent directory"))?;
    fs::create_dir_all(parent)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let temporary = parent.join(format!(".{name}.dott-{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if let Ok(meta) = fs::metadata(path) { fs::set_permissions(&temporary, meta.permissions())?; }
        fs::rename(&temporary, path)
    })();
    let _ = fs::remove_file(temporary);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("dott-notices-{}-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn notices_keep_latest_change_per_domain_and_clear() {
        let dir = temp();
        assert!(load(&dir).is_empty());
        record(&dir, "a.com", "available", 100).unwrap();
        record(&dir, "b.io", "taken", 200).unwrap();
        record(&dir, "a.com", "taken", 300).unwrap();
        assert_eq!(load(&dir), vec![
            Notice { domain: "b.io".into(), status: "taken".into(), at: 200 },
            Notice { domain: "a.com".into(), status: "taken".into(), at: 300 },
        ]);
        fs::write(notices_path(&dir), "not json").unwrap();
        assert!(load(&dir).is_empty());
        record(&dir, "c.dev", "available", 1_791_000_000).unwrap();
        assert!(line(&load(&dir)[0]).contains("2026-10-03"));
        clear(&dir);
        assert!(load(&dir).is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn hook_preserves_existing_zshrc_and_removes_cleanly() {
        let dir = temp();
        let rc = dir.join(".zshrc");
        let original = "export PATH=\"$HOME/bin:$PATH\"\r\nalias ll='ls -l'"; // CRLF, no final newline
        fs::write(&rc, original).unwrap();
        add_hook(&rc).unwrap();
        add_hook(&rc).unwrap();
        let text = fs::read_to_string(&rc).unwrap();
        assert!(text.starts_with(original) && text.matches(MARK).count() == 1);
        assert!(remove_hook(&rc).unwrap());
        assert_eq!(fs::read_to_string(&rc).unwrap(), format!("{original}\n"));
        assert!(!remove_hook(&rc).unwrap());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn hook_created_file_is_deleted_and_symlinks_are_kept() {
        let dir = temp();
        let rc = dir.join(".zshrc");
        add_hook(&rc).unwrap();
        assert_eq!(fs::read_to_string(&rc).unwrap(), format!("{HOOK}\n"));
        assert!(has_hook(&rc));
        assert!(remove_hook(&rc).unwrap());
        assert!(!rc.exists());

        let real_rc = dir.join("dotfiles-zshrc");
        fs::write(&real_rc, "setopt autocd\n").unwrap();
        std::os::unix::fs::symlink(&real_rc, &rc).unwrap();
        add_hook(&rc).unwrap();
        assert!(fs::symlink_metadata(&rc).unwrap().file_type().is_symlink());
        assert!(fs::read_to_string(&real_rc).unwrap().contains(MARK));
        remove_hook(&rc).unwrap();
        assert_eq!(fs::read_to_string(&real_rc).unwrap(), "setopt autocd\n");
        fs::remove_dir_all(dir).unwrap();
    }
}
