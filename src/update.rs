use reqwest::Client;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::{fs, path::{Path, PathBuf}, process::Command, time::{Duration, SystemTime, UNIX_EPOCH}};

const REPO: &str = "yodatosh/dott";
const RECEIPT: &str = ".dott-install";

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
    if cfg!(feature = "self-update") && standalone(&path) && target().is_some() {
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

const LATEST: &str = "https://api.github.com/repos/yodatosh/dott/releases/latest";

async fn latest(client: &Client, endpoint: &str, timeout: Duration) -> Result<String, String> {
    let json: serde_json::Value = client
        .get(endpoint)
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

fn save(path: &Path, cache: &Cache) {
    if let Some(parent) = path.parent()
        && fs::create_dir_all(parent).is_ok()
        && let Ok(bytes) = serde_json::to_vec(cache)
    {
        let _ = fs::write(path, bytes);
    }
}

/// Returns the saved notice immediately; a stale check refreshes in the background
/// for the next run, so no command waits on GitHub.
fn start_at(client: Client, path: PathBuf, endpoint: String, now: u64) -> Option<String> {
    let saved: Option<Cache> = fs::read(&path).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let previous = saved.as_ref().and_then(|cache| cache.latest.clone());
    if !saved.as_ref().is_some_and(|cache| cache.checked_at <= now && now - cache.checked_at < 86400) {
        // Stamp before fetching so slow or offline networks still try at most once a day.
        save(&path, &Cache { checked_at: now, latest: previous.clone() });
        // A failed fetch keeps the stamp above, including the previously known release.
        tokio::spawn(async move {
            if let Ok(version) = latest(&client, &endpoint, Duration::from_secs(3)).await {
                save(&path, &Cache { checked_at: now, latest: Some(version) });
            }
        });
    }
    previous.filter(|v| newer(v, env!("CARGO_PKG_VERSION")))
}

pub fn check_for_update(client: Client) -> Option<String> {
    if std::env::var_os("DOTT_NO_UPDATE_CHECK").is_some() { return None; }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    start_at(client, PathBuf::from(home).join(".dott/update-check.json"), LATEST.into(), now)
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
    if !cfg!(feature = "self-update") {
        return Err("Self-updating is disabled in this build. Use your package manager to update dott.".into());
    }
    let target = target().ok_or("Updates support macOS and GNU Linux on Intel/ARM64.")?;
    if !standalone(&path) {
        return Err("This copy of dott wasn't installed by the curl installer. Reinstall with: curl -fsSL https://raw.githubusercontent.com/yodatosh/dott/master/install.sh | sh".into());
    }
    let version = latest(client, LATEST, Duration::from_secs(15)).await?;
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


#[cfg(test)]
mod tests {
    use super::*;

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

    fn read_cache(path: &Path) -> (u64, Option<String>) {
        let cache: Cache = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        (cache.checked_at, cache.latest)
    }

    async fn wait_for(path: &Path, expected: (u64, Option<String>)) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while read_cache(path) != expected {
            assert!(std::time::Instant::now() < deadline, "cache never became {expected:?}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn saved_notice_returns_without_waiting_for_held_github_response() {
        use std::io::{Read, Write};
        let staging = Staging::new(&std::env::temp_dir()).unwrap();
        let path = staging.0.join("update-check.json");
        fs::write(&path, br#"{"checked_at":1000,"latest":"99.0.0"}"#).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/latest", listener.local_addr().unwrap());
        let (release, held) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 2048];
            let size = stream.read(&mut request).unwrap();
            assert!(std::str::from_utf8(&request[..size]).unwrap().starts_with("GET /latest "));
            held.recv_timeout(Duration::from_secs(10)).unwrap();
            let body = r#"{"tag_name":"v100.0.0","draft":false,"prerelease":false}"#;
            let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        });
        let now = 1000 + 86400;
        // Stale cache: the saved notice comes back at once and the attempt is stamped first.
        assert_eq!(start_at(Client::new(), path.clone(), endpoint.clone(), now), Some("99.0.0".into()));
        assert_eq!(read_cache(&path), (now, Some("99.0.0".into())));
        // Fresh stamp: no second request while the first is still held open.
        assert_eq!(start_at(Client::new(), path.clone(), endpoint, now + 1), Some("99.0.0".into()));
        release.send(()).unwrap();
        wait_for(&path, (now, Some("100.0.0".into()))).await;
        server.join().unwrap();
    }

    #[tokio::test]
    async fn failed_or_missing_checks_keep_known_release_and_retry_after_a_day() {
        let staging = Staging::new(&std::env::temp_dir()).unwrap();
        let path = staging.0.join("update-check.json");
        let closed = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}/latest", listener.local_addr().unwrap())
        };
        // First run: nothing saved yet, so no notice; the stamp throttles retries.
        assert_eq!(start_at(Client::new(), path.clone(), closed.clone(), 1000), None);
        assert_eq!(read_cache(&path), (1000, None));
        fs::write(&path, br#"{"checked_at":1000,"latest":"99.0.0"}"#).unwrap();
        assert_eq!(start_at(Client::new(), path.clone(), closed.clone(), 1000 + 86399), Some("99.0.0".into()));
        assert_eq!(read_cache(&path), (1000, Some("99.0.0".into())));
        // A clock that moved backwards counts as stale; a failure keeps the known release.
        assert_eq!(start_at(Client::new(), path.clone(), closed, 999), Some("99.0.0".into()));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(read_cache(&path), (999, Some("99.0.0".into())));
        // Older or malformed saved versions never produce a notice.
        fs::write(&path, br#"{"checked_at":1000,"latest":"0.7.0.1"}"#).unwrap();
        assert_eq!(start_at(Client::new(), path.clone(), String::new(), 1001), None);
        fs::write(&path, br#"{"checked_at":1000,"latest":"0.1.0"}"#).unwrap();
        assert_eq!(start_at(Client::new(), path, String::new(), 1001), None);
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
}
