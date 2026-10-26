use crate::model::{Availability, UnknownReason, ProtectionReason};
use futures::{future::{BoxFuture, Shared}, FutureExt};
use reqwest::Client;
use std::{collections::HashMap, sync::{Arc, LazyLock, Mutex}, time::{Duration, Instant}};
use tokio::sync::Semaphore;

const TTL: Duration = Duration::from_secs(60);
const MAX_ENTRIES: usize = 1024;
const MAX_BYTES: usize = 1_000_000;
type Lookup = Shared<BoxFuture<'static, Availability>>;
static CACHE: LazyLock<Mutex<HashMap<String, (Instant, Lookup)>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

pub(crate) fn parse(body: &[u8], status: u16, expected: &str) -> Availability {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else { return Availability::Unknown(UnknownReason::InvalidResponse); };
    match status {
        404 if json["errorCode"].as_u64() == Some(404) => Availability::Available,
        200 if json["objectClassName"].as_str() == Some("domain")
            && json["ldhName"].as_str().is_some_and(|name| name.eq_ignore_ascii_case(expected)) => {
                // This is protection evidence, not a domain registration. Details
                // describe the per-TLD and premium-name exceptions.
                Availability::Protected(ProtectionReason::Trademark)
            }
        _ => Availability::Unknown(UnknownReason::InvalidResponse),
    }
}

async fn fetch(client: &Client, url: &str, sem: &Semaphore) -> Availability {
    let _permit = sem.acquire().await.unwrap();
    let mut response = match client.get(url).header("Accept", "application/rdap+json")
        .timeout(Duration::from_secs(4)).send().await {
        Ok(response) => response,
        Err(error) => return Availability::Unknown(if error.is_timeout() { UnknownReason::Timeout } else { UnknownReason::Unreachable }),
    };
    let status = response.status().as_u16();
    let reason = match status {
        429 => Some(UnknownReason::RateLimited),
        408 | 504 => Some(UnknownReason::Timeout),
        500..=599 | 401 | 403 => Some(UnknownReason::ServiceUnavailable),
        200 | 404 => None,
        _ => Some(UnknownReason::InvalidResponse),
    };
    if let Some(reason) = reason { return Availability::Unknown(reason); }
    let expected = reqwest::Url::parse(url).ok().and_then(|url| url.path_segments()?.next_back().map(str::to_owned)).unwrap_or_default();
    let mut bytes = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if bytes.len() + chunk.len() <= MAX_BYTES => bytes.extend_from_slice(&chunk),
            Ok(None) => return parse(&bytes, status, &expected),
            Err(error) if error.is_timeout() => return Availability::Unknown(UnknownReason::Timeout),
            _ => return Availability::Unknown(UnknownReason::InvalidResponse),
        }
    }
}

// One request per label, shared across simultaneous .fyi/.live/.computer checks.
// Only successful lookups are retained; a retry can recover from transient errors.
pub async fn check(client: &Client, url: String, sem: Arc<Semaphore>) -> Availability {
    let (created, lookup) = {
        let mut cache = CACHE.lock().unwrap_or_else(|error| error.into_inner());
        cache.retain(|_, (created, _)| created.elapsed() < TTL);
        if !cache.contains_key(&url) && cache.len() >= MAX_ENTRIES {
            if let Some(oldest) = cache.iter().min_by_key(|(_, (created, _))| *created).map(|(key, _)| key.clone()) { cache.remove(&oldest); }
        }
        cache.entry(url.clone()).or_insert_with(|| {
            let client = client.clone();
            let url = url.clone();
            (Instant::now(), async move { fetch(&client, &url, &sem).await }.boxed().shared())
        }).clone()
    };
    let result = lookup.await;
    if matches!(result, Availability::Unknown(_)) {
        let mut cache = CACHE.lock().unwrap_or_else(|error| error.into_inner());
        if cache.get(&url).is_some_and(|(at, _)| *at == created) { cache.remove(&url); }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn server(replies: Vec<(&'static str, &'static str)>) -> (String, std::thread::JoinHandle<std::net::TcpListener>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/rdap/domain/apple.dpml.zone", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            for (status, body) in replies {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
                        Err(error) => panic!("protection mock: {error}"),
                    }
                };
                stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut request = [0; 4096];
                let size = stream.read(&mut request).unwrap();
                assert!(std::str::from_utf8(&request[..size]).unwrap().starts_with("GET /rdap/domain/apple.dpml.zone HTTP/1.1"));
                write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            listener
        });
        (url, handle)
    }

    #[test]
    fn scope_and_reply_validation_do_not_assume_every_rdap_provider_uses_dpml() {
        for tld in ["fyi", "live", "computer"] {
            assert_eq!(crate::config::dpml_url("apple", tld).unwrap(), "https://rdap.identitydigital.services/rdap/domain/apple.dpml.zone");
        }
        for tld in ["io", "ai", "me", "com", "work", "si", "click", "fun"] {
            assert!(crate::config::dpml_url("apple", tld).is_none());
        }
        assert_eq!(crate::config::rdap_url("example", "work").unwrap(), "https://rdap.nic.work/domain/example.work");
        let expected = "apple.dpml.zone";
        assert!(matches!(parse(br#"{"objectClassName":"domain","ldhName":"apple.dpml.zone"}"#, 200, expected), Availability::Protected(ProtectionReason::Trademark)));
        assert!(matches!(parse(br#"{"objectClassName":"domain","ldhName":"other.dpml.zone"}"#, 200, expected), Availability::Unknown(UnknownReason::InvalidResponse)));
        assert!(matches!(parse(br#"{"errorCode":404}"#, 404, expected), Availability::Available));
        assert!(matches!(parse(b"not found", 404, expected), Availability::Unknown(UnknownReason::InvalidResponse)));
    }

    #[tokio::test]
    async fn apple_protection_is_shared_and_never_returns_available() {
        let (url, server) = server(vec![("200 OK", r#"{"objectClassName":"domain","ldhName":"apple.dpml.zone"}"#)]);
        let client = Client::builder().no_proxy().build().unwrap();
        let sem = Arc::new(Semaphore::new(3));
        let results = futures::future::join_all((0..3).map(|_| check(&client, url.clone(), sem.clone()))).await;
        for result in results { assert!(matches!(result, Availability::Protected(ProtectionReason::Trademark))); }
        let listener = server.join().unwrap();
        assert!(matches!(check(&client, url, sem).await, Availability::Protected(ProtectionReason::Trademark)));
        assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }

    #[tokio::test]
    async fn protection_failures_remain_unknown_and_can_be_retried() {
        let (url, server) = server(vec![("429 Too Many Requests", "limited"), ("404 Not Found", r#"{"errorCode":404}"#)]);
        let client = Client::builder().no_proxy().build().unwrap();
        let sem = Arc::new(Semaphore::new(1));
        assert!(matches!(check(&client, url.clone(), sem.clone()).await, Availability::Unknown(UnknownReason::RateLimited)));
        assert!(matches!(check(&client, url, sem).await, Availability::Available));
        server.join().unwrap();
    }
}
