use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io::{self, Read, Write}, path::Path, time::{SystemTime, UNIX_EPOCH}};

const MAX_DOMAINS: usize = 2_000;
const RETENTION: u64 = 90 * 86_400;
const MAX_BYTES: u64 = 512 * 1024;

#[derive(Serialize, Deserialize)]
struct Entry { status: String, checked_at: u64 }

#[derive(Default, Serialize, Deserialize)]
struct History { domains: BTreeMap<String, Entry> }

fn read(path: &Path, now: u64) -> Result<History, String> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(History::default()),
        Err(e) => return Err(format!("Could not read check history: {e}")),
    };
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_BYTES { return Err("Check history is too large; file preserved.".into()); }
    let mut history: History = serde_json::from_slice(&bytes).map_err(|e| format!("Could not read check history: {e}"))?;
    history.domains.retain(|domain, entry| {
        matches!(crate::parse_search(domain), Ok((name, Some(tld))) if *domain == format!("{name}.{tld}"))
            && matches!(entry.status.as_str(), "available" | "taken" | "protected")
            && entry.checked_at <= now && now - entry.checked_at < RETENTION
    });
    Ok(history)
}

fn record_at(path: &Path, results: &crate::ui::Results, now: u64) -> Result<Vec<String>, String> {
    let parent = path.parent().ok_or("Check history has no parent directory")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let lock = fs::OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .open(path.with_extension("lock")).map_err(|e| e.to_string())?;
    lock.lock().map_err(|e| e.to_string())?;
    let mut history = read(path, now)?;
    let mut taken = Vec::new();
    for (domain, status) in results {
        if matches!(status, crate::model::Availability::Unknown(_)) { continue; }
        if !matches!(crate::parse_search(domain), Ok((name, Some(tld))) if *domain == format!("{name}.{tld}")) { continue; }
        if matches!(status, crate::model::Availability::Taken(_))
            && history.domains.get(domain).is_some_and(|entry| entry.status == "available") {
            taken.push(domain.clone());
        }
        history.domains.insert(domain.clone(), Entry { status: status.as_str().into(), checked_at: now });
    }
    if history.domains.len() > MAX_DOMAINS {
        let mut recent: Vec<_> = history.domains.into_iter().collect();
        recent.sort_by(|a, b| b.1.checked_at.cmp(&a.1.checked_at).then_with(|| a.0.cmp(&b.0)));
        history.domains = recent.into_iter().take(MAX_DOMAINS).collect();
    }
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let result = (|| -> io::Result<()> {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        file.write_all(&serde_json::to_vec(&history)?)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    let _ = fs::remove_file(&temporary);
    result.map_err(|e| format!("Could not save check history: {e}"))?;
    Ok(taken)
}

pub fn record(results: &crate::ui::Results) -> Result<Vec<String>, String> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).ok_or("HOME is not set")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    record_at(&std::path::PathBuf::from(home).join(".dott/checks.json"), results, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Availability, DomainDates, UnknownReason};

    #[test]
    fn remembers_conclusive_checks_across_runs_without_false_transitions() {
        let dir = std::env::temp_dir().join(format!("dott-history-{}-{}", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        let path = dir.join("checks.json");
        let check = |status| vec![("example.com".into(), status)];
        assert!(record_at(&path, &check(Availability::Available), 100).unwrap().is_empty());
        assert!(record_at(&path, &check(Availability::Unknown(UnknownReason::Inconclusive)), 101).unwrap().is_empty());
        assert_eq!(read(&path, 102).unwrap().domains["example.com"].checked_at, 100);
        assert_eq!(record_at(&path, &check(Availability::Taken(DomainDates::default())), 102).unwrap(), vec!["example.com"]);
        assert!(record_at(&path, &check(Availability::Taken(DomainDates::default())), 103).unwrap().is_empty());
        record_at(&path, &check(Availability::Available), 104).unwrap();
        // An expired baseline must not imply a recent change.
        assert!(record_at(&path, &check(Availability::Taken(DomainDates::default())), 104 + RETENTION).unwrap().is_empty());
        fs::write(&path, b"broken").unwrap();
        assert!(record_at(&path, &check(Availability::Available), 200).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"broken");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn history_is_bounded_and_concurrent_writers_preserve_each_other() {
        let dir = std::env::temp_dir().join(format!("dott-history-limit-{}-{}", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        let path = dir.join("checks.json");
        let results = (0..MAX_DOMAINS + 20).map(|i| (format!("{}-{i}.computer", "x".repeat(55)), Availability::Available)).collect();
        record_at(&path, &results, 100).unwrap();
        assert_eq!(read(&path, 100).unwrap().domains.len(), MAX_DOMAINS);
        assert!(fs::metadata(&path).unwrap().len() < 300 * 1024);
        std::thread::scope(|scope| {
            for name in ["one.com", "two.com"] {
                let path = &path;
                scope.spawn(move || record_at(path, &vec![(name.into(), Availability::Available)], 101).unwrap());
            }
        });
        let saved = read(&path, 101).unwrap();
        assert_eq!(saved.domains.len(), MAX_DOMAINS);
        assert!(saved.domains.contains_key("one.com") && saved.domains.contains_key("two.com"));
        fs::remove_dir_all(dir).unwrap();
    }
}
