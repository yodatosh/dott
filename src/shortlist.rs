use std::{fs, io::{self, Write}, path::{Path, PathBuf}};

fn path() -> Result<PathBuf, String> {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))
        .map(|home| PathBuf::from(home).join(".dott/shortlist.json"))
        .ok_or_else(|| "HOME is not set".into())
}

fn valid(domain: &str) -> bool {
    matches!(crate::parse_search(domain), Ok((name, Some(tld))) if domain == format!("{name}.{tld}"))
}

fn load_at(path: &Path) -> Result<Vec<String>, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("Could not read shortlist: {e}")),
    };
    let saved: Vec<String> = serde_json::from_slice(&bytes).map_err(|e| format!("Could not read shortlist: {e}"))?;
    if saved.iter().any(|d| !valid(d)) { return Err("Shortlist contains an invalid domain; the file has been preserved.".into()); }
    Ok(saved)
}

pub fn load() -> Result<Vec<String>, String> { load_at(&path()?) }

fn set_at(path: &Path, domain: &str, save: bool) -> Result<Vec<String>, String> {
    if !valid(domain) { return Err("Use a full supported domain for the shortlist.".into()); }
    let dir = path.parent().ok_or("Shortlist has no parent directory")?;
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let lock = fs::OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .open(path.with_extension("lock")).map_err(|e| e.to_string())?;
    lock.lock().map_err(|e| e.to_string())?;
    let mut saved = load_at(path)?;
    if save {
        if !saved.iter().any(|d| d == domain) { saved.push(domain.into()); }
    } else { saved.retain(|d| d != domain); }
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let result = (|| -> io::Result<()> {
        let mut file = fs::OpenOptions::new().create_new(true).write(true).open(&temporary)?;
        file.write_all(&serde_json::to_vec(&saved)?)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    let _ = fs::remove_file(&temporary);
    result.map_err(|e| format!("Could not save shortlist: {e}"))?;
    Ok(saved)
}

pub fn set(domain: &str, save: bool) -> Result<Vec<String>, String> { set_at(&path()?, domain, save) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shortlist_is_persistent_deduplicated_and_preserves_corruption() {
        let dir = std::env::temp_dir().join(format!("dott-shortlist-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let file = dir.join("shortlist.json");
        assert!(load_at(&file).unwrap().is_empty());
        assert_eq!(set_at(&file, "example.com", true).unwrap(), vec!["example.com"]);
        assert_eq!(set_at(&file, "example.com", true).unwrap(), vec!["example.com"]);
        // Concurrent writers each reload under the same cross-process lock.
        std::thread::scope(|scope| {
            for domain in ["example.io", "example.dev"] {
                let file = &file;
                scope.spawn(move || { set_at(file, domain, true).unwrap(); });
            }
        });
        assert_eq!(load_at(&file).unwrap().len(), 3);
        assert_eq!(set_at(&file, "example.com", false).unwrap().len(), 2);
        fs::write(&file, "bad json").unwrap();
        assert!(set_at(&file, "example.com", true).is_err());
        assert_eq!(fs::read_to_string(&file).unwrap(), "bad json");
        assert!(set_at(&file, "example.invalid", true).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
