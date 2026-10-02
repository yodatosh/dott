use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io::Write, path::{Path, PathBuf}, time::{Duration, SystemTime, UNIX_EPOCH}};

const ENDPOINT: &str = "https://api.porkbun.com/api/json/v3/pricing/get";
const DAY: u64 = 86_400;
const MAX_BYTES: usize = 2_000_000;

#[derive(Clone, Deserialize, Serialize)]
struct Price {
    registration_cents: u64,
    renewal_cents: u64,
    fetched_at: u64,
}

#[derive(Clone, Deserialize, Serialize)]
struct Cache {
    schema: u8,
    attempted_at: Option<u64>,
    prices: BTreeMap<String, Price>,
}

impl Default for Cache {
    fn default() -> Self { Self { schema: 1, attempted_at: None, prices: BTreeMap::new() } }
}

#[derive(Clone)]
pub struct Catalog {
    cache: Cache,
    now: u64,
}

impl Catalog {
    pub fn label(&self, domain: &str) -> String {
        let tld = domain.rsplit('.').next().unwrap_or("");
        match self.cache.prices.get(tld) {
            Some(price) => {
                let cached = if self.now.saturating_sub(price.fetched_at) >= DAY { " · cached" } else { "" };
                format!("  ${} on porkbun{cached}", money(price.registration_cents))
            }
            None => "  price unavailable".into(),
        }
    }
}

fn money(cents: u64) -> String { format!("{}.{:02}", cents / 100, cents % 100) }

fn cents(raw: &str) -> Option<u64> {
    let (whole, fraction) = raw.split_once('.').unwrap_or((raw, ""));
    if whole.is_empty() || whole.len() > 9 || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 2 || !fraction.bytes().all(|b| b.is_ascii_digit()) { return None; }
    let fraction = match fraction.len() {
        0 => 0,
        1 => fraction.parse::<u64>().ok()? * 10,
        _ => fraction.parse::<u64>().ok()?,
    };
    whole.parse::<u64>().ok()?.checked_mul(100)?.checked_add(fraction)
}

fn read_cache(path: &Path, now: u64) -> Cache {
    let mut cache = fs::read(path).ok().filter(|bytes| bytes.len() <= MAX_BYTES)
        .and_then(|bytes| serde_json::from_slice::<Cache>(&bytes).ok())
        .filter(|cache| cache.schema == 1).unwrap_or_default();
    cache.prices.retain(|tld, price| crate::config::ALL_TLDS.contains(&tld.as_str())
        && price.fetched_at <= now && price.registration_cents <= 99_999_999_999
        && price.renewal_cents <= 99_999_999_999);
    cache
}

fn save_cache(path: &Path, cache: &Cache) -> std::io::Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        file.write_all(&serde_json::to_vec(cache)?)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    let _ = fs::remove_file(temporary);
    result
}

async fn fetch(client: &Client, endpoint: &str, now: u64) -> Result<BTreeMap<String, Price>, String> {
    let mut url = reqwest::Url::parse(endpoint).map_err(|e| e.to_string())?;
    url.query_pairs_mut().append_pair("tlds", &crate::config::ALL_TLDS.join(","));
    let mut response = client.get(url)
        .header("User-Agent", concat!("dott/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(4)).send().await.map_err(|e| e.to_string())?
        .error_for_status().map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if bytes.len() + chunk.len() > MAX_BYTES { return Err("Pricing response too large".into()); }
        bytes.extend_from_slice(&chunk);
    }
    let data: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if data["status"] != "SUCCESS" { return Err("Pricing service returned an error".into()); }
    let entries = data["pricing"].as_object().ok_or("Missing pricing catalog")?;
    let mut prices = BTreeMap::new();
    for &tld in crate::config::ALL_TLDS {
        let Some(entry) = entries.get(tld) else { continue; };
        let registration = entry["registration"].as_str().and_then(cents);
        let renewal = entry["renewal"].as_str().and_then(cents);
        if let (Some(registration_cents), Some(renewal_cents)) = (registration, renewal) {
            prices.insert(tld.to_owned(), Price { registration_cents, renewal_cents, fetched_at: now });
        }
    }
    if prices.is_empty() { return Err("No valid supported prices".into()); }
    Ok(prices)
}

fn due(cache: &Cache, now: u64) -> bool {
    cache.attempted_at.is_none_or(|last| last > now || now - last >= DAY)
}

async fn load_at(client: &Client, path: &Path, endpoint: &str, now: u64) -> Catalog {
    let mut cache = read_cache(path, now);
    let snapshot = |cache| Catalog { cache, now };
    if !due(&cache, now) { return snapshot(cache); }
    // A cross-process lock prevents concurrent terminal sessions from refreshing twice.
    let Some(parent) = path.parent() else { return snapshot(cache); };
    if fs::create_dir_all(parent).is_err() { return snapshot(cache); }
    let Ok(lock) = fs::OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .open(path.with_extension("lock")) else { return snapshot(cache); };
    if lock.try_lock().is_err() { return snapshot(cache); }
    cache = read_cache(path, now);
    if !due(&cache, now) { return snapshot(cache); }
    // Persist attempts before networking: failed requests are also limited to once a day.
    cache.attempted_at = Some(now);
    if save_cache(path, &cache).is_err() { return snapshot(cache); }
    if let Ok(prices) = fetch(client, endpoint, now).await {
        // Preserve previously fetched prices for missing or malformed individual entries.
        cache.prices.extend(prices);
        let _ = save_cache(path, &cache);
    }
    snapshot(cache)
}

pub async fn load(client: &Client) -> Catalog {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    match home {
        Some(home) => load_at(client, &PathBuf::from(home).join(".dott/prices.json"), ENDPOINT, now).await,
        None => Catalog { cache: Cache::default(), now },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    // Mock servers give up after 10s instead of waiting forever for a client that never connects.
    fn accept(listener: &std::net::TcpListener) -> std::net::TcpStream {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match listener.accept() {
                Ok((stream, _)) => { stream.set_nonblocking(false).unwrap(); return stream; }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && std::time::Instant::now() < deadline =>
                    std::thread::sleep(Duration::from_millis(10)),
                Err(e) => panic!("mock server got no connection: {e}"),
            }
        }
    }

    struct Temporary(PathBuf);
    impl Temporary {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!("dott-pricing-{}-{}-{}", std::process::id(),
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn file(&self) -> PathBuf { self.0.join("prices.json") }
    }
    impl Drop for Temporary { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

    fn server(status: &str, body: &str) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/pricing/get", listener.local_addr().unwrap());
        let response = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        let thread = std::thread::spawn(move || {
            let mut stream = accept(&listener);
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut request = [0; 4096];
            let size = stream.read(&mut request).unwrap();
            let request = std::str::from_utf8(&request[..size]).unwrap();
            assert!(request.starts_with("GET /pricing/get?tlds="));
            assert!(!request.contains("example.com"));
            stream.write_all(response.as_bytes()).unwrap();
        });
        (url, thread)
    }

    fn seed(path: &Path, now: u64) {
        let mut cache = Cache { attempted_at: Some(now), ..Default::default() };
        cache.prices.insert("com".into(), Price { registration_cents: 1108, renewal_cents: 1200, fetched_at: now });
        save_cache(path, &cache).unwrap();
    }

    #[test]
    fn decimal_prices_are_exact_and_reject_invalid_values() {
        for (raw, expected) in [("11.08", 1108), ("0.01", 1), ("12", 1200), ("1.5", 150), ("0.00", 0)] {
            assert_eq!(cents(raw), Some(expected));
        }
        for raw in ["-1", "NaN", "1e3", "11.081", "", "$11.08", " 11.08", "1.2.3", "10000000000"] {
            assert_eq!(cents(raw), None, "{raw}");
        }
        assert_eq!(money(1108), "11.08");
    }

    #[tokio::test]
    #[ignore = "Explicit live API check; never run by default or in CI"]
    async fn live_porkbun_catalog() {
        let prices = fetch(&Client::new(), ENDPOINT, 100).await.expect("Live Porkbun catalog request failed");
        assert!(prices.contains_key("com"));
        assert!(prices.contains_key("org"));
        println!("Fetched {} supported TLD prices", prices.len());
    }

    #[tokio::test]
    async fn successful_fetch_is_cached_and_refreshes_after_24_hours() {
        let temp = Temporary::new();
        let client = Client::builder().no_proxy().build().unwrap();
        let body = r#"{"status":"SUCCESS","pricing":{"com":{"registration":"11.08","renewal":"12.00"}}}"#;
        let (url, server) = server("200 OK", body);
        let catalog = load_at(&client, &temp.file(), &url, 100).await;
        server.join().unwrap();
        assert_eq!(catalog.label("example.com"), "  $11.08 on porkbun");
        let cached = load_at(&client, &temp.file(), &url, 100 + DAY - 1).await;
        assert_eq!(cached.label("example.com"), catalog.label("example.com"));
        assert_eq!(read_cache(&temp.file(), 100 + DAY).attempted_at, Some(100));
        let (url, server) = self::server("200 OK", &body.replace("11.08", "13.50"));
        let updated = load_at(&client, &temp.file(), &url, 100 + DAY).await;
        server.join().unwrap();
        assert!(updated.label("example.com").contains("$13.50"));
        assert_eq!(read_cache(&temp.file(), 100 + DAY).attempted_at, Some(100 + DAY));
    }

    #[tokio::test]
    async fn failures_keep_old_prices_and_throttle_failed_attempts() {
        let client = Client::builder().no_proxy().build().unwrap();
        for (status, body) in [("503 Unavailable", "outage"), ("429 Too Many Requests", "limited"),
            ("200 OK", "bad json"), ("200 OK", r#"{"status":"ERROR"}"#),
            ("200 OK", r#"{"status":"SUCCESS","pricing":{}}"#),
            ("200 OK", r#"{"status":"SUCCESS","pricing":{"com":{"registration":"NaN","renewal":"12"}}}"#)] {
            let temp = Temporary::new();
            seed(&temp.file(), 100);
            let (url, server) = server(status, body);
            let old = load_at(&client, &temp.file(), &url, 100 + DAY).await;
            server.join().unwrap();
            assert_eq!(old.label("example.com"), "  $11.08 on porkbun · cached");
            let again = load_at(&client, &temp.file(), &url, 101 + DAY).await;
            assert_eq!(again.label("example.com"), old.label("example.com"));
            assert_eq!(read_cache(&temp.file(), 101 + DAY).attempted_at, Some(100 + DAY));
        }
    }

    #[tokio::test]
    async fn partial_catalog_preserves_previous_quotes_and_missing_prices_are_explicit() {
        let temp = Temporary::new();
        seed(&temp.file(), 100);
        let (url, server) = server("200 OK", r#"{"status":"SUCCESS","pricing":{"org":{"registration":"7.98","renewal":"10.74"}}}"#);
        let catalog = load_at(&Client::builder().no_proxy().build().unwrap(), &temp.file(), &url, 100 + DAY).await;
        server.join().unwrap();
        assert!(catalog.label("example.com").ends_with(" · cached"));
        assert_eq!(catalog.label("example.org"), "  $7.98 on porkbun");
        assert_eq!(catalog.label("example.so"), "  price unavailable");
    }

    #[tokio::test]
    async fn cold_outage_and_unwritable_cache_do_not_fail_searches() {
        let temp = Temporary::new();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let client = Client::builder().no_proxy().build().unwrap();
        let missing = load_at(&client, &temp.file(), &url, 100).await;
        assert_eq!(missing.label("example.com"), "  price unavailable");
        assert_eq!(read_cache(&temp.file(), 100).attempted_at, Some(100));
        let blocked = temp.0.join("not-a-directory");
        fs::write(&blocked, "file").unwrap();
        let unavailable = load_at(&client, &blocked.join("prices.json"), &url, 100).await;
        assert_eq!(unavailable.label("example.com"), "  price unavailable");
    }

    #[tokio::test]
    async fn slow_response_body_times_out_and_preserves_saved_prices() {
        let temp = Temporary::new();
        seed(&temp.file(), 100);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/pricing/get", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let mut stream = accept(&listener);
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).unwrap();
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n").unwrap();
            std::thread::sleep(Duration::from_secs(5));
        });
        let catalog = load_at(&Client::builder().no_proxy().build().unwrap(), &temp.file(), &url, 100 + DAY).await;
        assert!(catalog.label("example.com").ends_with(" · cached"));
        assert_eq!(read_cache(&temp.file(), 100 + DAY).attempted_at, Some(100 + DAY));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn refresh_lock_prevents_competing_fetches() {
        let temp = Temporary::new();
        seed(&temp.file(), 100);
        let lock = fs::OpenOptions::new().read(true).write(true).create(true).truncate(false)
            .open(temp.file().with_extension("lock")).unwrap();
        lock.lock().unwrap();
        let catalog = load_at(&Client::new(), &temp.file(), "http://127.0.0.1:9", 100 + DAY).await;
        assert!(catalog.label("example.com").ends_with(" · cached"));
        assert_eq!(read_cache(&temp.file(), 100 + DAY).attempted_at, Some(100));
    }

    #[test]
    fn malformed_cache_and_future_timestamps_are_handled() {
        let temp = Temporary::new();
        fs::write(temp.file(), "bad json").unwrap();
        assert!(read_cache(&temp.file(), 100).prices.is_empty());
        seed(&temp.file(), 200);
        let cache = read_cache(&temp.file(), 100);
        assert!(cache.prices.is_empty());
        assert!(due(&cache, 100));
    }
}
