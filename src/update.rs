use reqwest::Client;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::{fs, path::{Path, PathBuf}, process::Command, time::{Duration, SystemTime, UNIX_EPOCH}};

const REPO: &str = "yodatosh/dott";
pub const BREW_UPDATE: &str = "brew update && brew upgrade dott";
const RECEIPT: &str = ".dott-install";

pub fn installed_via_brew(path: &Path) -> bool {
    let parts: Vec<_> = path.components().collect();
    parts.windows(2).any(|p| p[0].as_os_str() == "Cellar" && p[1].as_os_str() == "dott")
}

fn standalone(path: &Path) -> bool {
    let receipt = path.parent().map(|p| p.join(RECEIPT));
    receipt.and_then(|p| fs::read_to_string(p).ok())
        .is_some_and(|s| Path::new(s.trim()) == path)
        // Compatibility with the original curl installer, which had no receipt.
        || path == Path::new("/usr/local/bin/dott")
        || path == Path::new("/opt/homebrew/bin/dott")
}

pub fn update_hint() -> &'static str {
    let path = std::env::current_exe().and_then(fs::canonicalize).unwrap_or_default();
    if installed_via_brew(&path) {
        BREW_UPDATE
    } else if cfg!(feature = "self-update") && standalone(&path) && target().is_some() {
        "dott --update"
    } else {
        "github.com/yodatosh/dott#updates"
    }
}

fn target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("linux", "aarch64") if cfg!(target_env = "gnu") => Some("aarch64-unknown-linux-gnu"),
        ("linux", "x86_64") if cfg!(target_env = "gnu") => Some("x86_64-unknown-linux-gnu"),
        _ => None,
    }
}

fn newer(latest: &str, current: &str) -> bool {
    let (Ok(latest), Ok(current)) = (Version::parse(latest), Version::parse(current)) else {
        return false;
    };
    latest.pre.is_empty() && latest.cmp_precedence(&current).is_gt()
}

async fn latest(client: &Client, timeout: Duration) -> Result<String, String> {
    let json: serde_json::Value = client
        .get(format!("https://api.github.com/repos/{REPO}/releases/latest"))
        .header("User-Agent", concat!("dott/", env!("CARGO_PKG_VERSION")))
        .timeout(timeout).send().await.map_err(|e| e.to_string())?
        .error_for_status().map_err(|e| e.to_string())?
        .json().await.map_err(|e| e.to_string())?;
    if json["draft"].as_bool() != Some(false) || json["prerelease"].as_bool() != Some(false) {
        return Err("GitHub did not return a stable published release".into());
    }
    let version = json["tag_name"].as_str().and_then(|s| s.strip_prefix('v'))
        .ok_or("Release tag must be vX.Y.Z")?;
    let parsed = Version::parse(version).map_err(|e| e.to_string())?;
    if !parsed.pre.is_empty() || !parsed.build.is_empty() {
        return Err("Release tag must be a stable vX.Y.Z version".into());
    }
    Ok(version.to_string())
}

#[derive(Deserialize, Serialize)]
struct Cache {
    checked_at: u64,
    latest: Option<String>,
}

fn cached_update(path: &Path, now: u64) -> Option<Option<String>> {
    let cache: Cache = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    if cache.checked_at > now || now - cache.checked_at >= 86400 { return None; }
    Some(cache.latest.filter(|v| newer(v, env!("CARGO_PKG_VERSION"))))
}

pub async fn check_for_update(client: Client) -> Option<String> {
    if std::env::var_os("DOTT_NO_UPDATE_CHECK").is_some() { return None; }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    let path = PathBuf::from(home).join(".dott/update-check.json");
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    if let Some(version) = cached_update(&path, now) { return version; }
    // Cache unsuccessful attempts too, so offline usage doesn't retry every invocation.
    let version = latest(&client, Duration::from_secs(3)).await.ok();
    let cache = Cache { checked_at: now, latest: version.clone() };
    if let Some(parent) = path.parent()
        && fs::create_dir_all(parent).is_ok()
        && let Ok(bytes) = serde_json::to_vec(&cache)
    {
        let _ = fs::write(path, bytes);
    }
    version.filter(|v| newer(v, env!("CARGO_PKG_VERSION")))
}

struct Staging(PathBuf);

impl Staging {
    fn new(parent: &Path) -> Result<Self, String> {
        let id = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_nanos();
        let path = parent.join(format!(".dott-update-{}-{id}", std::process::id()));
        fs::create_dir(&path).map_err(|e| format!("Cannot stage update in {}: {e}. Use a writable install directory or rerun the installer with DOTT_INSTALL_DIR set to this directory.", parent.display()))?;
        Ok(Self(path))
    }
}

impl Drop for Staging {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn verify_checksum(archive: &Path, sidecar: &str) -> Result<(), String> {
    let fields: Vec<_> = sidecar.split_whitespace().collect();
    let expected = fields.first().ok_or("Empty checksum file")?;
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) || fields.len() != 2 {
        return Err("Malformed SHA256 checksum file".into());
    }
    let output = match Command::new("sha256sum").arg(archive).output() {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Command::new("shasum")
            .args(["-a", "256"]).arg(archive).output().map_err(|e| e.to_string())?,
        Err(e) => return Err(e.to_string()),
    };
    let actual = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() || actual.split_whitespace().next() != Some(*expected) {
        return Err("SHA256 mismatch — the installed binary was not changed".into());
    }
    Ok(())
}

fn replace_binary(staging: &Staging, destination: &Path, version: &str) -> Result<(), String> {
    let archive = staging.0.join("dott.tar.gz");
    let output = Command::new("tar").arg("tzf").arg(&archive).output().map_err(|e| e.to_string())?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != "dott" {
        return Err("Release archive must contain exactly one file named dott".into());
    }
    let output = Command::new("tar").arg("xzf").arg(&archive).arg("-C").arg(&staging.0)
        .arg("dott").output().map_err(|e| e.to_string())?;
    if !output.status.success() { return Err("Could not extract the release binary".into()); }
    let binary = staging.0.join("dott");
    if !fs::symlink_metadata(&binary).map_err(|e| e.to_string())?.file_type().is_file() {
        return Err("Release binary must be a regular file".into());
    }
    let output = Command::new(&binary).arg("--version").output().map_err(|e| format!("New binary cannot run on this system: {e}"))?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != format!("dott {version}") {
        return Err("Downloaded binary version does not match the release".into());
    }
    fs::rename(binary, destination).map_err(|e| format!("Cannot replace {}: {e}", destination.display()))
}

pub async fn run(client: &Client) -> Result<(), String> {
    let path = std::env::current_exe().and_then(fs::canonicalize).map_err(|e| e.to_string())?;
    if installed_via_brew(&path) {
        run_brew(Path::new("brew"))?;
        return Ok(());
    }
    if !cfg!(feature = "self-update") {
        return Err("Self-updating is disabled in this build. Use your package manager to update dott.".into());
    }
    let target = target().ok_or("Standalone updates support macOS and GNU Linux on Intel/ARM64. Update this installation from source; see README.md.")?;
    if !standalone(&path) {
        return Err("This installation is not managed by the standalone installer. Update it using its original installation method; see github.com/yodatosh/dott#updates.".into());
    }
    let version = latest(client, Duration::from_secs(15)).await?;
    if !newer(&version, env!("CARGO_PKG_VERSION")) {
        println!("dott {} is up to date.", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let staging = Staging::new(path.parent().ok_or("Executable has no parent directory")?)?;
    let base = format!("https://github.com/{REPO}/releases/download/v{version}/dott-{target}.tar.gz");
    println!("Updating dott {} → {version}...", env!("CARGO_PKG_VERSION"));
    let bytes = client.get(&base).timeout(Duration::from_secs(120)).send().await.map_err(|e| e.to_string())?
        .error_for_status().map_err(|e| e.to_string())?.bytes().await.map_err(|e| e.to_string())?;
    let sidecar = client.get(format!("{base}.sha256")).timeout(Duration::from_secs(15))
        .send().await.map_err(|e| e.to_string())?.error_for_status().map_err(|e| e.to_string())?
        .text().await.map_err(|e| e.to_string())?;
    let archive = staging.0.join("dott.tar.gz");
    fs::write(&archive, bytes).map_err(|e| e.to_string())?;
    verify_checksum(&archive, &sidecar)?;
    replace_binary(&staging, &path, &version)?;
    println!("Updated to dott {version}. Restart any other running dott sessions.");
    Ok(())
}

fn run_brew(program: &Path) -> Result<(), String> {
    println!("Updating dott through Homebrew...");
    for args in [&["update"][..], &["upgrade", "dott"][..]] {
        let status = Command::new(program).args(args).status()
            .map_err(|e| format!("Could not run Homebrew: {e}. Run {BREW_UPDATE}"))?;
        if !status.success() {
            return Err(format!("brew {} failed ({status}). Resolve the Homebrew error and retry.", args.join(" ")));
        }
    }
    println!("Homebrew update finished. Restart dott to use the installed version.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brew_detection_distinguishes_standalone_and_cellar() {
        assert!(installed_via_brew(Path::new("/opt/homebrew/Cellar/dott/0.7.0/bin/dott")));
        assert!(installed_via_brew(Path::new("/home/linuxbrew/.linuxbrew/Cellar/dott/0.7.0/bin/dott")));
        assert!(!installed_via_brew(Path::new("/opt/homebrew/bin/dott")));
        assert!(!installed_via_brew(Path::new("/usr/local/bin/dott")));
        assert!(!installed_via_brew(Path::new("/tmp/Cellar/another-tool/bin/dott")));
    }

    #[test]
    fn stable_versions_compare_by_semver_precedence() {
        assert!(newer("0.7.0", "0.6.9"));
        assert!(newer("0.10.0", "0.9.0"));
        assert!(newer("0.7.0", "0.7.0-rc.1"));
        for version in ["0.6.9", "0.5.0", "0.7.0-rc.1", "0.7", "0.7.0.1", "v0.7.0"] {
            assert!(!newer(version, "0.6.9"), "{version}");
        }
        assert!(!newer("0.7.0+new", "0.7.0+old"));
    }

    #[test]
    fn bad_checksum_leaves_existing_binary_untouched() {
        let staging = Staging::new(&std::env::temp_dir()).unwrap();
        let destination = staging.0.join("installed");
        fs::write(&destination, b"old binary").unwrap();
        let archive = staging.0.join("dott.tar.gz");
        fs::write(&archive, b"corrupt archive").unwrap();
        assert!(verify_checksum(&archive, &format!("{}  dott.tar.gz", "0".repeat(64))).is_err());
        assert!(verify_checksum(&archive, "bad checksum").is_err());
        assert_eq!(fs::read(destination).unwrap(), b"old binary");
    }

    #[test]
    fn daily_cache_throttles_successes_and_failures_but_expires() {
        let staging = Staging::new(&std::env::temp_dir()).unwrap();
        let path = staging.0.join("cache.json");
        fs::write(&path, br#"{"checked_at":1000,"latest":"1.0.0"}"#).unwrap();
        assert_eq!(cached_update(&path, 1001), Some(Some("1.0.0".into())));
        assert_eq!(cached_update(&path, 1000 + 86400), None);
        assert_eq!(cached_update(&path, 999), None);
        fs::write(&path, br#"{"checked_at":1000,"latest":null}"#).unwrap();
        assert_eq!(cached_update(&path, 1001), Some(None));
        fs::write(&path, br#"{"checked_at":1000,"latest":"0.7.0.1"}"#).unwrap();
        assert_eq!(cached_update(&path, 1001), Some(None));
    }

    #[cfg(unix)]
    #[test]
    fn replacement_checks_version_and_preserves_installation_on_failure() {
        use std::os::unix::fs::PermissionsExt;
        let staging = Staging::new(&std::env::temp_dir()).unwrap();
        let destination = staging.0.join("installed");
        fs::write(&destination, b"old binary").unwrap();
        let source = staging.0.join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("dott"), b"#!/bin/sh\necho 'dott 0.7.0'\n").unwrap();
        fs::set_permissions(source.join("dott"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Command::new("tar").arg("czf").arg(staging.0.join("dott.tar.gz"))
            .arg("-C").arg(&source).arg("dott").status().unwrap().success());
        assert!(replace_binary(&staging, &destination, "0.8.0").is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"old binary");
        replace_binary(&staging, &destination, "0.7.0").unwrap();
        let output = Command::new(destination).arg("--version").output().unwrap();
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "dott 0.7.0");
    }

    #[cfg(unix)]
    #[test]
    fn brew_updates_before_upgrading_and_stops_on_failure() {
        use std::os::unix::fs::PermissionsExt;
        let staging = Staging::new(&std::env::temp_dir()).unwrap();
        let program = staging.0.join("brew");
        let log = staging.0.join("calls");
        // The fixture writes beside itself; no real Homebrew invocation or env changes.
        fs::write(&program, b"#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$(dirname \"$0\")/calls\"\n").unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
        run_brew(&program).unwrap();
        assert_eq!(fs::read_to_string(&log).unwrap(), "update\nupgrade dott\n");
        fs::remove_file(&log).unwrap();
        fs::write(&program, b"#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$(dirname \"$0\")/calls\"\nexit 1\n").unwrap();
        assert!(run_brew(&program).is_err());
        assert_eq!(fs::read_to_string(log).unwrap(), "update\n");
    }
}
