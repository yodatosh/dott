use colored::*;
use futures::{future::join_all, stream::FuturesUnordered};
use reqwest::Client;
use std::{
    fs,
    io::{self, BufRead, IsTerminal, Write},
    path::PathBuf,
    time::Duration,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
mod cli;
mod config;
mod extensions;
#[cfg(target_os = "macos")]
mod notify;
mod model;
mod notices;
mod utils;
mod update;
mod pricing;
mod ui;
mod shortlist;
mod history;
mod protection;
mod commands;
#[cfg(test)]
mod registry_audit;

use clap::Parser;
use cli::Cli;
use config::{ALL_TLDS, rdap_url, tld_rank, whois_server};
use model::{Availability, DomainDates, WatchEntry, UnknownReason, ProtectionReason};
use utils::{parse_date, parse_prose_date};

fn valid_label(name: &str) -> bool {
    !name.is_empty() && name.len() <= 63
        && !name.starts_with('-') && !name.ends_with('-')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn parse_search(raw: &str) -> Result<(String, Option<&'static str>), String> {
    let input = raw.trim().to_ascii_lowercase();
    let (name, tld) = match input.rsplit_once('.') {
        Some((name, suffix)) => {
            let tld = ALL_TLDS.iter().copied().find(|&t| t == suffix)
                .ok_or_else(|| format!("Unsupported TLD: {suffix}"))?;
            (name, Some(tld))
        }
        None => (input.as_str(), None),
    };
    if !valid_label(name) {
        return Err("Use a domain label of 1–63 ASCII letters, digits or hyphens, without a leading/trailing hyphen (use punycode for international names).".into());
    }
    Ok((name.to_string(), tld))
}

// 'name+', 'name+.tld' or 'name.tld+'; an empty name ('+', '+.tld') reuses the last search.
fn parse_suggest(input: &str) -> Option<Result<(Option<String>, Option<&'static str>), String>> {
    let (head, tail) = input.split_once('+')?;
    if !tail.is_empty() && !tail.starts_with('.') { return None; }
    let spec = format!("{head}{tail}");
    Some(match spec.strip_prefix('.') {
        Some(suffix) => ALL_TLDS.iter().copied().find(|&t| t == suffix)
            .map(|tld| (None, Some(tld))).ok_or_else(|| format!("Unsupported TLD: {suffix}")),
        None if spec.is_empty() => Ok((None, None)),
        None => parse_search(&spec).map(|(name, tld)| (Some(name), tld)),
    })
}

fn parse_tlds(raw: &str) -> Result<Vec<&'static str>, String> {
    let mut tlds = Vec::new();
    for suffix in raw.split(',') {
        let suffix = suffix.trim().to_ascii_lowercase();
        let tld = ALL_TLDS.iter().copied().find(|&t| t == suffix)
            .ok_or_else(|| format!("Unsupported TLD: {suffix}"))?;
        if !tlds.contains(&tld) { tlds.push(tld); }
    }
    Ok(tlds)
}

// A full domain in the input checks exactly that domain; --tlds applies to bare names.
fn search_tlds(explicit: Option<&'static str>, selected: Option<&[&'static str]>) -> Vec<&'static str> {
    match (explicit, selected) {
        (Some(tld), _) => vec![tld],
        (None, Some(tlds)) => tlds.to_vec(),
        (None, None) => ALL_TLDS.to_vec(),
    }
}

// Exact suffix splits precede ordinary results and ignore extension selection.
// Explicit domain searches remain exact. Only supported registry routes qualify.
fn search_domains(name: &str, explicit: Option<&'static str>, tlds: &[&'static str]) -> Vec<(String, &'static str)> {
    if let Some(tld) = explicit { return vec![(name.into(), tld)]; }
    let mut matches: Vec<_> = ALL_TLDS.iter().copied().filter_map(|tld| {
        name.strip_suffix(tld).filter(|label| valid_label(label)).map(|label| (label.to_owned(), tld))
    }).collect();
    matches.sort_by_key(|(_, tld)| (std::cmp::Reverse(tld.len()), tld_rank(tld)));
    matches.extend(tlds.iter().map(|tld| (name.to_owned(), *tld)));
    let mut seen = std::collections::HashSet::new();
    matches.retain(|domain| seen.insert(domain.clone()));
    matches
}

async fn whois_check(name: &str, tld: &str) -> Availability {
    let Some(server) = whois_server(tld) else { return Availability::Unknown(UnknownReason::NoRegistryService); };
    let drain_banner = config::whois_needs_banner(tld);
    let connect_secs = if drain_banner { 8 } else { 4 };
    whois_query(&format!("{server}:43"), &format!("{name}.{tld}"), tld,
        drain_banner, Duration::from_secs(connect_secs), Duration::from_secs(8)).await
}

async fn whois_query(addr: &str, domain: &str, tld: &str, drain_banner: bool, connect_timeout: Duration, response_timeout: Duration) -> Availability {
    let mut stream = match tokio::time::timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => return Availability::Unknown(UnknownReason::Unreachable),
        Err(_) => return Availability::Unknown(UnknownReason::Timeout),
    };
    if drain_banner {
        let mut banner = [0; 512];
        let _ = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut banner)).await;
    }
    match tokio::time::timeout(response_timeout, stream.write_all(format!("{domain}\r\n").as_bytes())).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => return Availability::Unknown(UnknownReason::Unreachable),
        Err(_) => return Availability::Unknown(UnknownReason::Timeout),
    }
    let mut response = String::new();
    // Never interpret an interrupted or oversized record as a complete reply.
    let mut reader = stream.take(256 * 1024 + 1);
    match tokio::time::timeout(response_timeout, reader.read_to_string(&mut response)).await {
        Ok(Ok(_)) if response.len() <= 256 * 1024 => parse_whois_for(&response, tld, Some(domain)),
        Ok(Err(error)) if error.kind() != io::ErrorKind::InvalidData => Availability::Unknown(UnknownReason::Unreachable),
        Ok(_) => Availability::Unknown(UnknownReason::InvalidResponse),
        Err(_) => Availability::Unknown(UnknownReason::Timeout),
    }
}

#[cfg(test)]
fn parse_whois(response: &str, tld: &str) -> Availability { parse_whois_for(response, tld, None) }

fn parse_whois_for(response: &str, tld: &str, expected: Option<&str>) -> Availability {
    let lower = response.to_lowercase();
    // Match explicit errors, not registry footers describing their rate policy.
    if lower.lines().any(|line| {
        let line = line.trim().trim_start_matches('%').trim();
        ["whois limit exceeded", "query rate exceeded", "rate limit exceeded", "too many queries",
         "quota exceeded", "maximum query rate exceeded", "error: rate limit", "error: too many queries"]
            .iter().any(|prefix| line.starts_with(prefix))
    }) { return Availability::Unknown(UnknownReason::RateLimited); }
    if lower.lines().any(|line| {
        let line = line.trim().trim_start_matches('%').trim();
        ["whois service not available", "whois service unavailable", "service temporarily unavailable", "access denied"]
            .iter().any(|prefix| line.starts_with(prefix))
    }) { return Availability::Unknown(UnknownReason::ServiceUnavailable); }
    if lower.lines().any(|line| {
        let line = line.trim().trim_start_matches('%').trim();
        line.starts_with("error:") || line.starts_with("error ")
    }) { return Availability::Unknown(UnknownReason::InvalidResponse); }
    let lines: Vec<_> = lower.lines().map(str::trim).collect();
    let valid_domain = |domain: &str| {
        domain.rsplit_once('.').is_some_and(|(name, suffix)| valid_label(name) && suffix == tld)
            && expected.is_none_or(|expected| domain.eq_ignore_ascii_case(expected))
    };
    let mut records = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if let Some(value) = line.strip_prefix("domain name:").or_else(|| line.strip_prefix("domain:")) {
            let value = value.trim();
            let value = if value.is_empty() { lines.get(index + 1).copied().unwrap_or("") } else { value };
            if !valid_domain(value) { return Availability::Unknown(UnknownReason::InvalidResponse); }
            records.push(value);
        }
    }
    let no_object = lines.iter().any(|line| matches!(*line,
        "the queried object does not exist: no object found" | "the queried object does not exist: domain not found" |
        "object does not exist" | "no object found"));
    // .so echoes the queried Domain Name in a missing-object response. Only
    // accept that special case when there is no registration record alongside it.
    if tld == "so" && no_object {
        let has_record = lines.iter().any(|line| line.starts_with("registry domain id:") || line.starts_with("creation date:"));
        return if has_record { Availability::Unknown(UnknownReason::InvalidResponse) } else { Availability::Available };
    }
    let reserved = lines.iter().any(|line| {
        line.starts_with("domain is reserved") || line.starts_with("domain name is reserved") || line.starts_with("this domain is reserved")
            || matches!(*line, "status: reserved" | "domain status: reserved" | "status: not available")
    });
    if reserved { return Availability::Protected(ProtectionReason::Reserved); }
    if !records.is_empty() {
        let dates = if tld == "gg" {
            // whois.gg is "registered until cancelled" — no expiry published.
            // registration date is prose: "Registered on 26th February 2015".
            let registered = response.lines()
                .find(|l| l.to_lowercase().contains("registered on"))
                .and_then(parse_prose_date);
            DomainDates { registered, updated: None, expires: None }
        } else {
            let extract = |keyword: &str| -> Option<String> {
                response.lines()
                    .find(|l| l.to_lowercase().contains(keyword))
                    .and_then(|l| l.find(':').map(|i| &l[i+1..]))
                    .and_then(|s| parse_date(s.trim()))
            };
            DomainDates {
                registered: extract("creat").or_else(|| extract("registered:")),
                updated:    extract("updat").or_else(|| extract("last modified").or_else(|| extract("changed:"))),
                expires:    extract("expir").or_else(|| extract("paid-till")).or_else(|| extract("renewal")),
            }
        };
        Availability::Taken(dates)
    } else {
        let missing = no_object || lines.iter().any(|line| {
            let line = line.trim_start_matches('%').trim();
            if line == "domain not found." || line == "domain not found" { return true; }
            if tld == "gg" && line == "not found" { return true; }
            if tld == "si" && matches!(line, "no entries found for the selected source(s)." | "no entries found") { return true; }
            if let Some(name) = line.strip_prefix("no match for ") {
                return valid_domain(name.trim_end_matches('.').trim_matches('"').trim());
            }
            if matches!(tld, "click" | "fun") {
                if let Some(name) = line.strip_prefix(">>> domain ").and_then(|line| line.strip_suffix(" is available for registration")) {
                    return valid_domain(name);
                }
            }
            matches!(line, "available" | "status: available" | "domain status: available")
        });
        if missing { Availability::Available } else { Availability::Unknown(UnknownReason::InvalidResponse) }
    }

}

async fn dns_check(client: &Client, name: &str, tld: &str) -> Availability {
    let url = format!("https://cloudflare-dns.com/dns-query?name={}.{}&type=NS", name, tld);
    dns_query(client, &url, &format!("{name}.{tld}")).await
}

async fn dns_query(client: &Client, url: &str, domain: &str) -> Availability {
    let res = client
        .get(url)
        .header("Accept", "application/dns-json")
        .timeout(Duration::from_secs(4))
        .send().await;
    match res {
        Ok(response) if response.status().is_success() => response.json::<serde_json::Value>().await
            .map(|json| parse_dns_response(&json, domain)).unwrap_or(Availability::Unknown(UnknownReason::Inconclusive)),
        _ => Availability::Unknown(UnknownReason::Inconclusive),
    }
}

fn parse_dns_response(json: &serde_json::Value, domain: &str) -> Availability {
    let has_ns = json["Answer"].as_array().is_some_and(|answers| answers.iter().any(|record| {
        record["type"].as_u64() == Some(2)
            && record["name"].as_str().is_some_and(|owner| owner.trim_end_matches('.').eq_ignore_ascii_case(domain))
            && record["data"].as_str().is_some_and(|host| !host.trim_end_matches('.').is_empty()
                && host.trim_end_matches('.').split('.').all(valid_label))
    }));
    if json["Status"].as_u64() == Some(0) && has_ns { Availability::Taken(DomainDates::default()) }
    else { Availability::Unknown(UnknownReason::Inconclusive) }
}

// Err means no HTTP response arrived, so a bootstrap retry is allowed.
// An HTTP response with an inconclusive body remains Ok(Unknown(reason)).
async fn http_query(client: &Client, url: &str, sem: &Semaphore) -> Result<Availability, UnknownReason> {
    http_query_with_timeout(client, url, sem, Duration::from_secs(5)).await
}

async fn http_query_with_timeout(client: &Client, url: &str, sem: &Semaphore, timeout: Duration) -> Result<Availability, UnknownReason> {
    let _permit = sem.acquire().await.unwrap();
    let mut response = client.get(url).header("User-Agent", "Mozilla/5.0").header("Accept", "application/json")
        .timeout(timeout).send().await.map_err(|error| if error.is_timeout() { UnknownReason::Timeout } else { UnknownReason::Unreachable })?;
    let status = response.status().as_u16();
    let from_bootstrap = response.url().host_str() == Some("rdap.org");
    // Status codes are useful even if the service sends a broken error body.
    let error = match status {
        429 => Some(UnknownReason::RateLimited),
        408 | 504 => Some(UnknownReason::Timeout),
        401 | 403 | 500..=599 => Some(UnknownReason::ServiceUnavailable),
        200 | 404 => None,
        _ => Some(UnknownReason::InvalidResponse),
    };
    if let Some(reason) = error { return Ok(Availability::Unknown(reason)); }
    let mut bytes = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if bytes.len() + chunk.len() <= 2_000_000 => bytes.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(error) if error.is_timeout() => return Ok(Availability::Unknown(UnknownReason::Timeout)),
            _ => return Ok(Availability::Unknown(UnknownReason::InvalidResponse)),
        }
    }
    let Ok(body) = String::from_utf8(bytes) else { return Ok(Availability::Unknown(UnknownReason::InvalidResponse)); };
    let expected = reqwest::Url::parse(url).ok().and_then(|url| url.path_segments()?.next_back().map(str::to_owned));
    Ok(parse_rdap_response(status, &body, from_bootstrap, expected.as_deref()))
}

fn parse_rdap_response(status: u16, body: &str, from_bootstrap: bool, expected: Option<&str>) -> Availability {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(body) else { return Availability::Unknown(UnknownReason::InvalidResponse); };
    let mut messages = vec![json["title"].as_str().unwrap_or("")];
    if let Some(descriptions) = json["description"].as_array() { messages.extend(descriptions.iter().filter_map(|line| line.as_str())); }
    let messages = messages.into_iter().map(|message| message.to_ascii_lowercase()).collect::<Vec<_>>();
    let no_service = messages.iter().any(|message| ["no rdap service", "unsupported tld", "tld not supported"].iter().any(|phrase| message.contains(phrase)));
    let protected = messages.iter().any(|message| {
        matches!(message.trim(), "blocked" | "reserved" | "domain blocked" | "domain name blocked" | "reserved domain")
            || ["domain is blocked", "domain name is blocked", "domain is reserved", "domain name is reserved"].iter().any(|phrase| message.contains(phrase))
            || expected.is_some_and(|domain| message.strip_prefix(&domain.to_ascii_lowercase()).and_then(|rest| rest.strip_prefix(' '))
                .is_some_and(|rest| matches!(rest, "blocked" | "reserved") || rest.starts_with("blocked by ") || rest.starts_with("reserved by ")))
    });
    match status {
        200 if json["objectClassName"].as_str() == Some("domain") && json.get("errorCode").is_none()
            && json["ldhName"].as_str().is_some_and(|name| name.rsplit_once('.').is_some_and(|(label, _)| valid_label(label))
                && expected.is_none_or(|expected| name.eq_ignore_ascii_case(expected))) => {
            let events = json["events"].as_array();
            let date = |action: &str| events.and_then(|events| events.iter().find(|e| e["eventAction"].as_str() == Some(action)))
                .and_then(|event| event["eventDate"].as_str()).and_then(parse_date);
            let expires = events.and_then(|events| events.iter().find(|event| event["eventAction"].as_str().is_some_and(|action| action.contains("expir"))))
                .and_then(|event| event["eventDate"].as_str()).and_then(parse_date);
            Availability::Taken(DomainDates { registered: date("registration"), updated: date("last changed"), expires })
        }
        404 if json["errorCode"].as_u64() == Some(404)
            && (json.get("objectClassName").is_none() || json["objectClassName"].as_str() == Some("error")) => {
            if from_bootstrap || no_service {
                Availability::Unknown(if no_service { UnknownReason::NoRegistryService } else { UnknownReason::ServiceUnavailable })
            } else if protected { Availability::Protected(ProtectionReason::Reserved) }
            else { Availability::Available }
        }
        _ => Availability::Unknown(UnknownReason::InvalidResponse),
    }
}

async fn rdap_check(client: &Client, primary: &str, fallback: &str, sem: &Semaphore) -> Availability {
    match http_query(client, primary, sem).await {
        Ok(status) => status,
        Err(first) if primary != fallback => match http_query(client, fallback, sem).await {
            Ok(Availability::Unknown(second)) | Err(second) => Availability::Unknown(first.combine(second)),
            Ok(status) => status,
        },
        Err(reason) => Availability::Unknown(reason),
    }
}

fn merge_dates(a: DomainDates, b: DomainDates) -> DomainDates {
    DomainDates {
        registered: a.registered.or(b.registered),
        updated:    a.updated.or(b.updated),
        expires:    a.expires.or(b.expires),
    }
}

fn merge_results(rdap: Availability, whois: Availability, dns: Availability) -> Availability {
    // DNS Taken (active NS records) = definitely registered; pull dates from RDAP/WHOIS if present
    if matches!(dns, Availability::Taken(_)) {
        let dates = match (rdap, whois) {
            (Availability::Taken(a), Availability::Taken(b)) => merge_dates(a, b),
            (Availability::Taken(a), _) => a,
            (_, Availability::Taken(b)) => b,
            _ => DomainDates::default(),
        };
        return Availability::Taken(dates);
    }

    let registry = match (rdap, whois) {
        (Availability::Unknown(a), Availability::Unknown(b)) => Availability::Unknown(a.combine(b)),
        (Availability::Unknown(_), whois) => whois,
        (Availability::Taken(a), Availability::Taken(b)) => Availability::Taken(merge_dates(a, b)),
        (_, Availability::Taken(dates)) => Availability::Taken(dates),
        (Availability::Available, Availability::Protected(reason)) => Availability::Protected(reason),
        (rdap, _) => rdap,
    };
    match (registry, dns) {
        (Availability::Unknown(a), Availability::Unknown(b)) => Availability::Unknown(a.combine(b)),
        (Availability::Unknown(_), dns) => dns,
        (registry, _) => registry,
    }
}

// 60s in-session cache, keyed on (name, tld). Avoids re-fetching when interactive searches overlap
// (e.g. typing `foo` then `foo+` would otherwise re-query foo.com/io/dev/app/co).
type Cache = Arc<std::sync::Mutex<std::collections::HashMap<(String, &'static str), (std::time::Instant, Availability)>>>;

const CACHE_TTL: Duration = Duration::from_secs(60);

fn new_cache() -> Cache {
    Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()))
}

async fn check_domain_cached(
    client: Client,
    name: String,
    tld: &'static str,
    sem: Arc<Semaphore>,
    cache: Option<Cache>,
) -> (String, Availability) {
    if let Some(ref c) = cache
        && let Ok(map) = c.lock()
        && let Some((t, av)) = map.get(&(name.clone(), tld))
        && t.elapsed() < CACHE_TTL
    {
        return (format!("{}.{}", name, tld), av.clone());
    }
    let (domain, av) = check_domain(client, name.clone(), tld, sem).await;
    if let Some(ref c) = cache
        && let Ok(mut map) = c.lock()
    {
        map.insert((name, tld), (std::time::Instant::now(), av.clone()));
    }
    (domain, av)
}

struct WhoisTask(tokio::task::JoinHandle<Availability>);

impl Drop for WhoisTask {
    fn drop(&mut self) { self.0.abort(); }
}

async fn check_domain(client: Client, name: String, tld: &'static str, sem: Arc<Semaphore>) -> (String, Availability) {
    let domain = format!("{}.{}", name, tld);
    if !valid_label(&name) { return (domain, Availability::Unknown(UnknownReason::Inconclusive)); }

    let rdap_fut = async {
        let Some(primary) = rdap_url(&name, tld) else { return Availability::Unknown(UnknownReason::NoRegistryService); };
        let fallback = format!("https://rdap.org/domain/{name}.{tld}");
        rdap_check(&client, &primary, &fallback, &sem).await
    };

    // WHOIS is the slowest source (TCP read can hang up to 8s). Spawn it cancellable
    // and await it for negative or inconclusive RDAP replies.
    let whois_handle = WhoisTask(tokio::spawn({
        let name = name.clone();
        async move { whois_check(&name, tld).await }
    }));

    let mut result = resolve_sources(rdap_fut, dns_check(&client, &name, tld), whois_handle).await;
    if matches!(result, Availability::Available) {
        if let Some(url) = config::dpml_url(&name, tld) {
            result = protection::check(&client, url, sem.clone()).await;
        }
    }
    (domain, result)
}

async fn resolve_sources<R, D>(rdap: R, dns: D, mut whois: WhoisTask) -> Availability
where R: std::future::Future<Output = Availability>, D: std::future::Future<Output = Availability> {
    tokio::pin!(rdap, dns);
    let mut dns_done = None;
    let rdap_result = tokio::select! {
        result = &mut rdap => result,
        result = &mut dns => { dns_done = Some(result); rdap.await }
    };
    let dns_result = match dns_done {
        Some(result) => result,
        None if matches!(rdap_result, Availability::Taken(_)) => Availability::Unknown(UnknownReason::Inconclusive),
        None => dns.await,
    };
    // A negative RDAP lookup must not discard an already-running positive
    // WHOIS record. Registered names do not need a DNS delegation to be taken.
    let whois_result = if matches!(rdap_result, Availability::Unknown(_) | Availability::Available) {
        (&mut whois.0).await.unwrap_or(Availability::Unknown(UnknownReason::Inconclusive))
    } else { Availability::Unknown(UnknownReason::Inconclusive) };
    merge_results(rdap_result, whois_result, dns_result)
}

fn generate_suggestions(keywords: &[String]) -> Vec<String> {
    let prefixes = ["get", "try", "use", "go", "my", "the", "run", "hey"];
    let suffixes = ["hq", "app", "lab", "hub", "base"];
    let mut names = Vec::new();
    names.extend(keywords.iter().cloned());
    if keywords.len() >= 2 {
        names.push(keywords.join(""));
        names.push(keywords.join("-"));
    }
    // Round-robin across keywords, so later words and combinations get a fair
    // share of the result budget instead of truncating after the first keyword.
    for i in 0..prefixes.len().max(suffixes.len()) {
        for kw in keywords {
            if let Some(prefix) = prefixes.get(i) { names.push(format!("{prefix}{kw}")); }
            if let Some(suffix) = suffixes.get(i) { names.push(format!("{kw}{suffix}")); }
        }
    }
    let mut seen = std::collections::HashSet::new();
    names.into_iter().filter(|name| valid_label(name) && seen.insert(name.clone())).take(14).collect()
}

// Server roots for the selected extensions' RDAP and Cloudflare DNS; never a domain path.
fn warm_origins(tlds: &[&'static str]) -> Vec<String> {
    let mut origins = vec!["https://cloudflare-dns.com/".to_string()];
    for tld in tlds {
        let Some(url) = rdap_url("x", tld).and_then(|u| reqwest::Url::parse(&u).ok()) else { continue };
        let origin = format!("{}/", url.origin().ascii_serialization());
        if !origins.contains(&origin) { origins.push(origin); }
    }
    origins
}

// Opens connections while the user types so the first interactive search skips TLS setup.
fn warm_up(client: &Client, tlds: &[&'static str]) {
    for origin in warm_origins(tlds) {
        let client = client.clone();
        tokio::spawn(async move { let _ = client.head(origin).timeout(Duration::from_secs(4)).send().await; });
    }
}

fn farewell() -> String {
    let keys = if cfg!(windows) {
        ["USERNAME", "USER", "LOGNAME"]
    } else {
        ["USER", "LOGNAME", "USERNAME"]
    };
    let username = keys
        .iter()
        .filter_map(|key| std::env::var(key).ok())
        .map(|name| name.trim().to_owned())
        .find(|name| !name.is_empty() && !name.chars().any(char::is_control));
    match username {
        Some(name) => format!("bye {name} 🐱"),
        None => "bye 🐱".to_owned(),
    }
}

fn print_help() {
    let row = |c: &str, desc: &str| {
        println!("    {}{}",
            format!("{:<20}", c).bright_white(),
            desc.truecolor(110, 110, 140)
        );
    };
    println!();
    println!("  {}", "search".truecolor(80, 80, 100));
    row("name",              "check name across all TLDs");
    row("name.tld",          "check a single domain");
    row("name+",             "suggest prefix/suffix variants");
    row("name+.tld",         "suggest variants on one TLD");
    row("+",                 "suggest for last searched name");
    println!();
    println!("  {}", "commands · type / to choose".truecolor(150, 150, 170));
    for command in commands::COMMANDS { row(&command.usage(), command.description); }
    row("exit, q",           "quit (also esc)");
    println!();
}

fn print_cat() {
    println!();
    println!("{}", "   ____       _   _ ".truecolor(255, 155, 0));
    println!("{}", "  |  _ \\  ___| |_| |_".truecolor(255, 60, 90));
    println!("{}", "  | | | |/ _ \\ __| __|".truecolor(180, 50, 230));
    println!("{}", "  | |_| | (_) | |_| |_".truecolor(80, 130, 255));
    println!("{}", format!("  |____/ \\___/ \\__|\\__|  v{}", env!("CARGO_PKG_VERSION")).truecolor(50, 215, 235));
    println!();
    println!("{}", "  private domain search".truecolor(160, 160, 175));
    println!("{}", ui::clip("  type a name · / for commands · esc to quit", ui::width().saturating_sub(1)).truecolor(155, 155, 175));
    println!();
    println!();
}

fn input_prompt() -> String {
    format!("  {} ", ">".truecolor(64, 194, 207).bold())
}

// All terminal searches share the same viewport and cancellation behavior.
async fn check_and_print(client: &Client, domains: Vec<(String, &'static str)>, cache: Option<&Cache>, _interactive: bool, prices: tokio::sync::watch::Receiver<pricing::Catalog>) -> ui::Results {
    let sem = Arc::new(Semaphore::new(10));
    let labels = domains.iter().map(|(name, tld)| format!("{name}.{tld}")).collect();
    let checks: FuturesUnordered<_> = domains.into_iter().enumerate().map(|(i, (name, tld))| {
        let client = client.clone();
        let sem = sem.clone();
        let cache = cache.cloned();
        async move { (i, check_domain_cached(client, name, tld, sem, cache).await) }
    }).collect();
    match ui::live(checks, labels, prices.clone(), io::stdin().is_terminal()).await {
        Ok((report, mut panel)) => {
            let changes = match history::record(&report.results) {
                Ok(changes) => changes,
                Err(error) => { eprintln!("dott: {error}"); Vec::new() }
            };
            if let Err(error) = panel.finish(&report.results, &prices.borrow(), changes, report.cancelled) { eprintln!("dott: {error}"); }
            report.results
        }
        Err(error) => { eprintln!("dott: Cannot render search: {error}"); Vec::new() }
    }
}

async fn search_and_print(client: &Client, name: &str, explicit: Option<&'static str>, mut tld_list: Vec<&'static str>, plain: bool, cache: Option<&Cache>, interactive: bool, prices: Option<tokio::sync::watch::Receiver<pricing::Catalog>>) -> ui::Results {
    if !plain { tld_list.sort_by_key(|t| tld_rank(t)); }
    let domains = search_domains(name, explicit, &tld_list);
    if plain {
        let sem = Arc::new(Semaphore::new(10));
        let tasks: Vec<_> = domains.into_iter().map(|(name, tld)| {
            check_domain_cached(client.clone(), name, tld, sem.clone(), cache.cloned())
        }).collect();
        let results = join_all(tasks).await;
        for (domain, status) in &results { println!("{} {}", domain, status.as_str()); }
        return results;
    }
    check_and_print(client, domains, cache, interactive,
        prices.unwrap_or_else(|| pricing::start(client))).await
}

fn retry_domains(results: &ui::Results) -> Vec<(String, &'static str)> {
    results.iter().filter(|(_, status)| matches!(status, Availability::Unknown(_)))
        .filter_map(|(domain, _)| parse_search(domain).ok().and_then(|(name, tld)| tld.map(|tld| (name, tld))))
        .collect()
}

fn merge_retry(previous: &mut ui::Results, refreshed: ui::Results) {
    for (domain, status) in refreshed {
        if let Some((_, old)) = previous.iter_mut().find(|(d, _)| *d == domain) { *old = status; }
    }
}

async fn print_update(handle: tokio::task::JoinHandle<Option<String>>) {
    if let Ok(Some(version)) = handle.await {
        eprintln!("  update available → {}  (v{})", update::update_hint(), version);
    }
}

async fn try_print_update_if_ready(
    slot: &mut Option<tokio::task::JoinHandle<Option<String>>>,
) {
    if let Some(handle) = slot
        && handle.is_finished()
        && let Some(taken) = slot.take()
    {
        print_update(taken).await;
    }
}

fn watchlist_path() -> PathBuf {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".dott").join("watchlist.json")
}

fn load_watchlist() -> Vec<WatchEntry> {
    match load_watchlist_at(&watchlist_path()) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("dott: Could not read watchlist (the existing file was preserved): {error}");
            std::process::exit(1);
        }
    }
}

fn load_watchlist_at(path: &std::path::Path) -> io::Result<Vec<WatchEntry>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

fn save_watchlist_at(path: &std::path::Path, entries: &[WatchEntry]) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(entries).map_err(io::Error::other)?;
    let parent = path.parent().ok_or_else(|| io::Error::other("Missing watchlist directory"))?;
    fs::create_dir_all(parent)?;
    let id = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?.as_nanos();
    let temporary = parent.join(format!(".watchlist-{}-{id}.tmp", std::process::id()));
    let result = (|| {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    let _ = fs::remove_file(temporary);
    result
}

fn save_watchlist(entries: &[WatchEntry]) -> Result<(), String> {
    save_watchlist_at(&watchlist_path(), entries).map_err(|e| format!("Could not save watchlist: {e}"))
}

fn lock_watchlist_at(path: &std::path::Path) -> io::Result<fs::File> {
    let parent = path.parent().ok_or_else(|| io::Error::other("Missing watchlist directory"))?;
    fs::create_dir_all(parent)?;
    let file = fs::OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .open(path.with_extension("lock"))?;
    file.lock()?;
    Ok(file)
}

async fn lock_watchlist() -> Result<fs::File, String> {
    let path = watchlist_path();
    tokio::task::spawn_blocking(move || lock_watchlist_at(&path)).await
        .map_err(|error| format!("Could not lock watchlist: {error}"))?
        .map_err(|error| format!("Could not lock watchlist: {error}"))
}

fn send_notification(title: &str, body: &str) -> Result<(), String> {
    if !cfg!(target_os = "macos") { return Ok(()); }
    #[cfg(target_os = "macos")]
    if let Ok(binary) = stable_binary()
        && let Some(dir) = watchlist_path().parent()
        && notify::send(dir, &binary, title, body).is_ok()
    {
        return Ok(());
    }
    // Fallback: macOS credits this to Script Editor, but an alert is never lost.
    let script = format!("display notification {} with title {}",
        serde_json::to_string(body).unwrap_or_default(),
        serde_json::to_string(title).unwrap_or_default());
    let output = std::process::Command::new("osascript").arg("-e").arg(&script)
        .output().map_err(|e| format!("Could not send notification: {e}"))?;
    if !output.status.success() {
        return Err(format!("Could not send notification: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(())
}

fn stable_binary() -> Result<PathBuf, String> {
    std::env::current_exe().and_then(fs::canonicalize).map_err(|e| e.to_string())
}

// Sets up dott.app for anyone watching domains, including people who watched before it existed.
// On creation, a short hello makes macOS list dott under Notifications and ask permission now
// rather than on the day a domain frees up. Never fails the caller; the osascript fallback remains.
fn prepare_notifier(hello: bool) {
    #[cfg(target_os = "macos")]
    {
        let path = watchlist_path();
        let Some(dir) = path.parent() else { return };
        if !load_watchlist_at(&path).is_ok_and(|entries| !entries.is_empty()) { return; }
        let Ok(binary) = stable_binary() else { return };
        if notify::ensure(dir, &binary).unwrap_or(false) && hello {
            let _ = notify::send(dir, &binary, "dott", "Watchlist alerts now come from dott.");
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = hello;
}

fn install_launch_agent() -> Result<(), String> {
    if !cfg!(target_os = "macos") { return Ok(()); }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let plist_path = PathBuf::from(&home).join("Library").join("LaunchAgents").join("com.dott.watch.plist");
    let binary = stable_binary()?.to_string_lossy().to_string();

    let binary = binary.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    // if plist exists and already points to the current binary, leave it alone.
    // otherwise it's stale (binary moved or reinstalled elsewhere) — unload and rewrite.
    if let Ok(existing) = fs::read_to_string(&plist_path) {
        if existing.contains(&format!("<string>{binary}</string>")) {
            let loaded = std::process::Command::new("launchctl").args(["list", "com.dott.watch"])
                .output().map_err(|e| e.to_string())?;
            if loaded.status.success() { return Ok(()); }
        }
        let _ = std::process::Command::new("launchctl").arg("unload").arg(&plist_path).output();
    }

    let plist = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.dott.watch</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
        <string>--background-check</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict><key>Hour</key><integer>9</integer><key>Minute</key><integer>0</integer></dict>
</dict>
</plist>"#);
    if let Some(parent) = plist_path.parent() { fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
    fs::write(&plist_path, plist).map_err(|e| e.to_string())?;
    let output = std::process::Command::new("launchctl").arg("load").arg(&plist_path)
        .output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!("launchctl: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(())
}

async fn cmd_watch(client: &Client, domain: &str) -> Result<(), String> {
    let (name, tld) = parse_search(domain)?;
    let tld = tld.ok_or("Please specify a full domain, e.g. myname.com")?;
    let domain = format!("{name}.{tld}");
    let _guard = lock_watchlist().await?;
    let mut entries = load_watchlist();
    let first_domain = entries.is_empty();

    if entries.iter().any(|e| e.domain == domain) {
        install_launch_agent()?;
        println!("\n  {} {} is already being watched\n", "·".truecolor(100, 100, 120), domain.bright_white());
        return Ok(());
    }

    let (_, status) = check_domain(client.clone(), name, tld, Arc::new(Semaphore::new(1))).await;
    let status_str = status.as_str().to_string();

    entries.push(WatchEntry { domain: domain.clone(), last_status: status_str.clone() });
    save_watchlist(&entries)?;
    // A first domain gets the "Now watching" notification below, which serves as the hello.
    prepare_notifier(!first_domain);
    install_launch_agent().map_err(|e| format!("Watchlist saved, but automatic monitoring could not be installed: {e}"))?;

    println!("\n  {} watching {}", "✓".bright_green().bold(), domain.bright_white().bold());
    if status_str == "available" {
        println!("  {} it's available right now — go register it!", "·".bright_green());
    } else if cfg!(target_os = "macos") {
        println!("  {} {}", "·".truecolor(80, 80, 100), "you'll get a notification when it becomes available".truecolor(100, 100, 130));
    }

    if first_domain && cfg!(target_os = "macos") {
        if let Err(error) = send_notification("dott", &format!("Now watching {} — you'll be notified when it's available.", domain)) {
            eprintln!("dott: {error}");
        }
        println!("  {} {}", "·".truecolor(80, 80, 100), "if no notification appeared, allow notifications for dott in:".truecolor(100, 100, 130));
        println!("     {}", "System Settings → Notifications → dott".bright_white());
        let _ = std::process::Command::new("open")
            .arg("x-apple.systempreferences:com.apple.preference.notifications")
            .output();
    }
    if !cfg!(target_os = "macos") {
        println!("  Automatic monitoring is available on macOS. Schedule dott --background-check to refresh the list on this platform.");
    }
    if first_domain { offer_shell_notice(); }
    println!();
    Ok(())
}

fn offer_shell_notice() {
    let Some(rc) = notices::zshrc_path() else { return };
    if !notices::uses_zsh() || notices::has_hook(&rc) || !io::stdin().is_terminal() || !io::stdout().is_terminal() { return; }
    print!("  {} show watchlist updates in new terminal windows? adds one line to {} {} ",
        "·".truecolor(80, 80, 100), rc.display(), "[y/N]".truecolor(100, 100, 130));
    let _ = io::stdout().flush();
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() || !answer.trim().eq_ignore_ascii_case("y") { return; }
    match notices::add_hook(&rc) {
        Ok(()) => println!("  {} added · remove anytime with {}", "✓".bright_green().bold(), "dott --shell-notice off".bright_white()),
        Err(error) => eprintln!("dott: Could not update {}: {error}", rc.display()),
    }
}

fn cmd_shell_notice(on: bool) -> Result<(), String> {
    let rc = notices::zshrc_path().ok_or("HOME is not set")?;
    let failed = |e: io::Error| format!("Could not update {}: {e}", rc.display());
    if on {
        if !notices::uses_zsh() {
            return Err("Terminal notices support zsh only; add `dott --pending` to your shell's startup file instead.".into());
        }
        notices::add_hook(&rc).map_err(failed)?;
        println!("  {} new terminal windows will show watchlist updates ({})", "✓".bright_green().bold(), rc.display());
    } else if notices::remove_hook(&rc).map_err(failed)? {
        println!("  {} removed dott's line from {}", "✓".bright_green().bold(), rc.display());
    } else {
        println!("  {} dott's line is not in {}", "·".truecolor(100, 100, 120), rc.display());
    }
    Ok(())
}

// Runs from ~/.zshrc on every new window: no network, no lock, no errors, silent when there's no news.
fn print_pending() {
    let path = watchlist_path();
    let Some(dir) = path.parent() else { return };
    let list = notices::load(dir);
    if list.is_empty() { return; }
    for notice in &list { println!("{}  {}", "dott".bright_magenta().bold(), notices::line(notice)); }
    println!("      {}", "open dott or run dott --watching to dismiss".truecolor(80, 80, 100));
}

// Shows unseen watchlist changes once, then marks them seen.
fn show_notices() {
    let path = watchlist_path();
    let Some(dir) = path.parent() else { return };
    if notices::load(dir).is_empty() { return; }
    // Lock so a background check can't record a change between showing and clearing.
    let _guard = lock_watchlist_at(&path).ok();
    let list = notices::load(dir);
    if list.is_empty() { return; }
    println!("  {}", "watchlist updates".truecolor(80, 80, 100));
    for notice in &list { println!("  {}", notices::line(notice)); }
    println!();
    notices::clear(dir);
}

async fn cmd_unwatch(domain: &str) -> Result<(), String> {
    let domain = domain.trim().to_ascii_lowercase();
    let _guard = lock_watchlist().await?;
    let mut entries = load_watchlist();
    let before = entries.len();
    entries.retain(|e| e.domain != domain);
    if entries.len() == before {
        println!("\n  {} {} not in watchlist\n", "·".truecolor(100, 100, 120), domain);
        return Ok(());
    }
    save_watchlist(&entries)?;
    println!("\n  {} stopped watching {}", "✓".bright_green().bold(), domain.bright_white().bold());
    // Nothing left to report, so the terminal-window line goes too.
    if entries.is_empty()
        && let Some(rc) = notices::zshrc_path()
        && notices::remove_hook(&rc).unwrap_or(false)
    {
        println!("  {} watchlist empty · removed dott's line from {}", "·".truecolor(80, 80, 100), rc.display());
    }
    println!();
    Ok(())
}

fn cmd_watching_list() {
    let entries = load_watchlist();
    println!();
    show_notices();
    if entries.is_empty() {
        println!("  {} no domains being watched", "·".truecolor(100, 100, 120));
        println!("  {} use {} to start\n", "·".truecolor(80, 80, 100), "dott --watch <domain>".bright_white());
        return;
    }
    println!("  {}\n", "watching:".truecolor(80, 80, 100));
    for e in &entries {
        let status_colored = match e.last_status.as_str() {
            "available"  => e.last_status.bright_green().to_string(),
            "taken"      => e.last_status.truecolor(60, 60, 80).to_string(),
            "protected"  => e.last_status.bright_yellow().to_string(),
            _            => e.last_status.truecolor(100, 100, 80).to_string(),
        };
        println!("  {}  {}  {}", "·".truecolor(100, 100, 120), e.domain.bright_white(), status_colored);
    }
    println!();
}

fn refresh_watch_entry(
    entry: &mut WatchEntry,
    status: &Availability,
    notify: impl FnOnce(&str, &str) -> Result<(), String>,
) -> Result<bool, String> {
    let new_status = status.as_str();
    if new_status == "unknown" || new_status == entry.last_status { return Ok(false); }
    if new_status == "available" {
        notify("dott — available!", &format!("{} is now available to register!", entry.domain))?;
    }
    entry.last_status = new_status.to_string();
    Ok(true)
}

async fn cmd_background_check(client: &Client) -> Result<(), String> {
    let _guard = lock_watchlist().await?;
    let mut entries = load_watchlist();
    if entries.is_empty() { return Ok(()); }
    prepare_notifier(true);
    let sem = Arc::new(Semaphore::new(5));
    // Keep unsupported or malformed legacy entries rather than checking a different domain.
    let domains: Vec<_> = entries.iter().enumerate().filter_map(|(index, e)| {
        let (name, tld) = parse_search(&e.domain).ok()?;
        Some((index, name, tld?))
    }).collect();
    let tasks: Vec<_> = domains.iter().map(|(_, name, tld)| {
        check_domain(client.clone(), name.clone(), tld, sem.clone())
    }).collect();
    let results = join_all(tasks).await;
    let mut changed = false;
    let mut errors = Vec::new();
    let mut news = Vec::new();
    for ((index, _, _), (_, status)) in domains.iter().zip(results.iter()) {
        let entry = &mut entries[*index];
        let before = entry.last_status.clone();
        match refresh_watch_entry(entry, status, send_notification) {
            Ok(updated) => {
                changed |= updated;
                // After "unknown", only availability is news; "taken" may have been true all along.
                if updated && (before != "unknown" || entry.last_status == "available") {
                    news.push((entry.domain.clone(), entry.last_status.clone()));
                }
            }
            Err(error) => errors.push(format!("{}: {error}", entry.domain)),
        }
    }
    if changed { save_watchlist(&entries)?; }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    if let Some(dir) = watchlist_path().parent() {
        for (domain, status) in &news {
            if let Err(error) = notices::record(dir, domain, status, now) {
                errors.push(format!("{domain}: Could not save update notice: {error}"));
            }
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Some(args) = &cli.notify {
        #[cfg(target_os = "macos")]
        finish_command(notify::deliver(&args[0], &args[1]));
        #[cfg(not(target_os = "macos"))]
        { let _ = args; finish_command(Err("notifications are only supported on macOS".into())); }
        return;
    }
    if cli.pending { print_pending(); return; }
    if let Some(ref mode) = cli.shell_notice { finish_command(cmd_shell_notice(mode == "on")); return; }
    let client = Client::new();
    if cli.update {
        if let Err(error) = update::run(&client).await {
            eprintln!("dott: {error}");
            std::process::exit(1);
        }
        return;
    }
    let plain = cli.plain || !io::stdout().is_terminal();
    let selected_tlds = cli.tlds.as_deref().map(parse_tlds).transpose().unwrap_or_else(|error| {
        eprintln!("dott: {error}"); std::process::exit(1);
    });

    if cli.background_check { finish_command(cmd_background_check(&client).await); return; }
    if let Some(ref domain) = cli.watch    { finish_command(cmd_watch(&client, domain).await); return; }
    if let Some(ref domain) = cli.unwatch  { finish_command(cmd_unwatch(domain).await); return; }
    if cli.watching { cmd_watching_list(); return; }

    // ── pipe mode: read names from stdin, always plain output ──
    if cli.name.is_none() && cli.suggest.is_none() && (!io::stdin().is_terminal() || plain) {
        for line in io::stdin().lock().lines() {
            let Ok(line) = line else { continue };
            let line = line.trim();
            if line.is_empty() { continue; }
            let (name, explicit_tld) = match parse_search(line) {
                Ok(search) => search,
                Err(error) => { eprintln!("dott: {error}"); std::process::exit(1); }
            };
            let tlds = search_tlds(explicit_tld, selected_tlds.as_deref());
            search_and_print(&client, &name, explicit_tld, tlds, true, None, false, None).await;
        }
        return;
    }

    let mut update_check: Option<tokio::task::JoinHandle<Option<String>>> =
        if !plain && io::stdin().is_terminal() && std::env::var_os("DOTT_NO_UPDATE_CHECK").is_none() {
            Some(tokio::spawn(update::check_for_update(client.clone())))
        } else { None };

    // Saved /tlds choices apply to terminal searches only; --tlds overrides them for this run.
    let mut active_tlds = selected_tlds.or_else(|| if plain { None } else { extensions::load() });

    // ── one-shot mode ──────────────────────────────────────────
    if let Some(keywords) = cli.suggest {
        let keywords: Vec<String> = keywords.iter().flat_map(|s| s.split_whitespace())
            .map(str::to_ascii_lowercase).collect();
        if keywords.is_empty() || keywords.iter().any(|s| !valid_label(s)) {
            eprintln!("dott: Suggestion keywords must be valid domain labels.");
            std::process::exit(1);
        }
        if !plain {
            println!();
            println!("{}", "  · d o t t ·".bright_magenta().bold());
            println!();
            println!("  {} {}\n", "generating for:".truecolor(80, 80, 100), keywords.join(", ").bright_white());
        }
        let suggestions = generate_suggestions(&keywords);
        let tlds = active_tlds.clone().unwrap_or_else(|| vec!["com", "io", "dev", "app", "co"]);
        let domains: Vec<_> = suggestions.iter().flat_map(|name| tlds.iter().map(move |tld| (name.clone(), *tld))).collect();
        if plain {
            let sem = Arc::new(Semaphore::new(10));
            let tasks = domains.into_iter().map(|(name, tld)| check_domain(client.clone(), name, tld, sem.clone()));
            for (domain, status) in join_all(tasks).await { println!("{} {}", domain, status.as_str()); }
        } else {
            check_and_print(&client, domains, None, false, pricing::start(&client)).await;
        }
        if let Some(h) = update_check.take() { print_update(h).await; }
        return;
    }

    if let Some(raw) = cli.name {
        if !plain {
            println!();
            println!("{}", "  · d o t t ·".bright_magenta().bold());
            println!();
        }
        let (name, explicit_tld) = match parse_search(&raw) {
            Ok(search) => search,
            Err(error) => { eprintln!("dott: {error}"); std::process::exit(1); }
        };
        let tld_list = search_tlds(explicit_tld, active_tlds.as_deref());
        search_and_print(&client, &name, explicit_tld, tld_list, plain, None, false, None).await;
        if let Some(h) = update_check.take() { print_update(h).await; }
        return;
    }

    // ── interactive mode ───────────────────────────────────────
    print_cat();
    show_notices();
    std::thread::spawn(|| prepare_notifier(true));
    warm_up(&client, active_tlds.as_deref().unwrap_or(ALL_TLDS));
    let session_prices = pricing::start(&client);

    let cache = new_cache();
    let mut last_name: Option<String> = None;
    let mut last_results: ui::Results = Vec::new();
    let mut history = Vec::new();

    loop {
        let prompt = input_prompt();
        let input = match ui::read_input(&prompt, &mut history) {
            Ok(input) => input,
            Err(error) => { eprintln!("dott: Cannot read input: {error}"); break; }
        };
        if input.as_ref().is_some_and(|input| input.trim().is_empty()) { continue; }
        match input {
            None => {
                println!("\n  {}\n", farewell().truecolor(180, 140, 200));
                if let Some(h) = update_check.take() { print_update(h).await; }
                break;
            }
            Some(input) => {
                let input = input.trim().to_ascii_lowercase();
                if input.is_empty() { continue; }
                if input == "exit" || input == "quit" || input == "q" {
                    println!("\n  {}\n", farewell().truecolor(180, 140, 200));
                    if let Some(h) = update_check.take() { print_update(h).await; }
                    break;
                }

                if let Some(command) = commands::COMMANDS.iter().find(|command| command.name == input && command.argument.is_some()) {
                    eprintln!("dott: Usage: {}", command.usage());
                    continue;
                }

                if let Some(parsed) = parse_suggest(&input) {
                    let (name, explicit_tld) = match parsed {
                        Ok(suggest) => suggest,
                        Err(error) => { eprintln!("dott: {error}"); continue; }
                    };
                    let Some(name) = name.or_else(|| last_name.clone()) else {
                        println!("  {}\n", "search for a name first".truecolor(100, 100, 120));
                        continue;
                    };
                    println!("  {} {}", "suggesting for:".truecolor(80, 80, 100), name.bright_white());
                    // the name itself was just searched; only show new variants
                    let suggestions: Vec<String> = generate_suggestions(std::slice::from_ref(&name)).into_iter().filter(|n| *n != name).collect();
                    let tlds = match explicit_tld {
                        Some(tld) => vec![tld],
                        None => active_tlds.clone().unwrap_or_else(|| vec!["com", "io", "dev", "app", "co"]),
                    };
                    let domains = suggestions.iter().flat_map(|name| tlds.iter().map(move |tld| (name.clone(), *tld))).collect();
                    last_results = check_and_print(&client, domains, Some(&cache), true, session_prices.clone()).await;
                    try_print_update_if_ready(&mut update_check).await;
                    continue;
                }

                if input == "/results" || input == "/shortlist" || input.starts_with("/details ") {
                    if input == "/shortlist" {
                        match shortlist::load() {
                            Ok(saved) => {
                                if saved.is_empty() { println!("  Your shortlist is empty. Use /save <domain> to add a name.\n"); continue; }
                                last_results = saved.into_iter().map(|domain| {
                                    let status = last_results.iter().find(|(d, _)| *d == domain).map(|(_, s)| s.clone()).unwrap_or(Availability::Unknown(UnknownReason::NotChecked));
                                    (domain, status)
                                }).collect();
                            }
                            Err(error) => { eprintln!("dott: {error}"); continue; }
                        }
                    }
                    if last_results.is_empty() { println!("  Search for a name first.\n"); continue; }
                    if let Some(domain) = input.strip_prefix("/details ") {
                        if let Some((domain, status)) = last_results.iter().find(|(d, _)| d == domain.trim()) {
                            for line in ui::details(domain, status, &session_prices.borrow()) { println!("  {line}"); }
                        } else { eprintln!("dott: That domain is not in the last results."); }
                    } else if let Err(error) = ui::print_results(&last_results, &session_prices.borrow(), &[], false) { eprintln!("dott: {error}"); }
                    continue;
                }
                if input == "/retry" {
                    let domains = retry_domains(&last_results);
                    if domains.is_empty() { println!("  No inconclusive checks to retry.\n"); continue; }
                    if let Ok(mut entries) = cache.lock() {
                        for key in &domains { entries.remove(key); }
                    }
                    let refreshed = check_and_print(&client, domains, Some(&cache), true, session_prices.clone()).await;
                    merge_retry(&mut last_results, refreshed);
                    continue;
                }
                if let Some((save, raw)) = input.strip_prefix("/save ").map(|d| (true, d))
                    .or_else(|| input.strip_prefix("/unsave ").map(|d| (false, d))) {
                    let domain = parse_search(raw).and_then(|(name, tld)| tld.map(|tld| format!("{name}.{tld}")).ok_or_else(|| "Use a full domain.".into()));
                    match domain.and_then(|domain| shortlist::set(&domain, save).map(|_| domain)) {
                        Ok(domain) => println!("  {} {domain}\n", if save { "Saved" } else { "Removed" }),
                        Err(error) => eprintln!("dott: {error}"),
                    }
                    continue;
                }

                // /watch <domain>, /unwatch <domain>, /list
                if let Some(domain) = input.strip_prefix("/watch ") {
                    if let Err(error) = cmd_watch(&client, domain.trim()).await { eprintln!("dott: {error}"); }
                    continue;
                }
                if let Some(domain) = input.strip_prefix("/unwatch ") {
                    if let Err(error) = cmd_unwatch(domain.trim()).await { eprintln!("dott: {error}"); }
                    continue;
                }
                if input == "/list" {
                    cmd_watching_list();
                    continue;
                }
                if input == "/tlds" {
                    match extensions::select(active_tlds.as_deref().unwrap_or(ALL_TLDS)) {
                        Ok(Some(chosen)) => {
                            if let Err(error) = extensions::save(&chosen) { eprintln!("dott: {error}"); }
                            warm_up(&client, &chosen);
                            active_tlds = Some(chosen);
                        }
                        Ok(None) => {}
                        Err(error) => eprintln!("dott: Cannot open extension selector: {error}"),
                    }
                    continue;
                }
                if input == "/help" {
                    print_help();
                    continue;
                }
                if input == "/update" {
                    // Discard the startup notice: an explicit update supersedes it.
                    if let Some(handle) = update_check.take() { handle.abort(); }
                    if let Err(error) = update::run(&client).await {
                        eprintln!("dott: {error}");
                    }
                    continue;
                }

                if input.starts_with('/') {
                    eprintln!("dott: Unknown command. Type / to see the options.");
                    continue;
                }

                let (name, explicit_tld) = match parse_search(&input) {
                    Ok(search) => search,
                    Err(error) => { eprintln!("dott: {error}"); continue; }
                };
                let tlds = search_tlds(explicit_tld, active_tlds.as_deref());
                last_results = search_and_print(&client, &name, explicit_tld, tlds, false, Some(&cache), true, Some(session_prices.clone())).await;
                last_name = Some(name);
                try_print_update_if_ready(&mut update_check).await;
            }
        }
    }
}

fn finish_command(result: Result<(), String>) {
    if let Err(error) = result {
        eprintln!("dott: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::is_likely_premium;

    #[test]
    fn exact_suffix_matches_lead_regardless_of_selected_extensions() {
        assert_eq!(search_domains("phagy", None, &["com", "dev"]),
            vec![("pha".into(), "gy"), ("phagy".into(), "com"), ("phagy".into(), "dev")]);
        assert_eq!(search_domains("phagy", None, &["gy", "com", "gy"]),
            vec![("pha".into(), "gy"), ("phagy".into(), "gy"), ("phagy".into(), "com")]);
        for (query, label, suffix) in [("radio", "rad", "io"), ("family", "fami", "ly"),
            ("getapp", "get", "app"), ("gocomputer", "go", "computer")] {
            assert_eq!(search_domains(query, None, &["com"])[0], (label.into(), suffix));
        }
    }

    #[test]
    fn suffix_matching_requires_a_valid_label_and_keeps_explicit_searches_exact() {
        for query in ["gy", "-gy", "a-gy", "hello"] {
            assert_eq!(search_domains(query, None, &["com"]), vec![(query.into(), "com")]);
        }
        assert_eq!(search_domains("phagy", Some("com"), &["com"]), vec![("phagy".into(), "com")]);
        assert_eq!(search_domains("pha", Some("gy"), &["com"]), vec![("pha".into(), "gy")]);
        let (name, explicit) = parse_search(" PHAGY ").unwrap();
        assert_eq!(search_domains(&name, explicit, &["com"])[0], ("pha".into(), "gy"));
    }

    #[tokio::test]
    async fn suffix_matches_use_the_normal_cached_plain_search_path() {
        let cache = new_cache();
        for (name, tld, status) in [("pha", "gy", Availability::Available),
            ("phagy", "com", Availability::Taken(DomainDates::default()))] {
            cache.lock().unwrap().insert((name.into(), tld), (std::time::Instant::now(), status));
        }
        let results = search_and_print(&Client::new(), "phagy", None, vec!["com"], true, Some(&cache), false, None).await;
        assert_eq!(results.iter().map(|(d, s)| (d.as_str(), s.as_str())).collect::<Vec<_>>(),
            vec![("pha.gy", "available"), ("phagy.com", "taken")]);
    }

    #[tokio::test]
    async fn suffix_match_stays_first_when_regular_result_finishes_first() {
        use futures::FutureExt;
        let domains = search_domains("phagy", None, &["com"]);
        let labels: Vec<_> = domains.iter().map(|(name, tld)| format!("{name}.{tld}")).collect();
        let (url, _, server) = one_response("127.0.0.1", "404 Not Found", r#"{"errorCode":404,"title":"Not Found"}"#);
        let url = url.replace("nic.co", "pha.gy");
        let (send, receive) = tokio::sync::oneshot::channel();
        let checks = FuturesUnordered::new();
        checks.push(async move {
            receive.await.unwrap();
            let status = http_query(&Client::builder().no_proxy().build().unwrap(), &url, &Semaphore::new(1)).await.unwrap();
            (0, ("pha.gy".into(), status))
        }.boxed());
        checks.push(async move {
            send.send(()).unwrap();
            (1, ("phagy.com".into(), Availability::Taken(DomainDates::default())))
        }.boxed());
        let (_, prices) = tokio::sync::watch::channel(pricing::fixture_catalog(false));
        let report = ui::drive(checks, labels, prices, |rows, _| {
            assert_eq!(rows.len(), 2);
            Ok(false)
        }).await.unwrap();
        server.join().unwrap();
        assert_eq!(report.results.iter().map(|(d, s)| (d.as_str(), s.as_str())).collect::<Vec<_>>(),
            vec![("pha.gy", "available"), ("phagy.com", "taken")]);
    }

    #[test]
    fn suggestions_include_later_keywords_and_combinations_within_budget() {
        let names = generate_suggestions(&["cool".into(), "project".into()]);
        for name in ["cool", "project", "coolproject", "cool-project", "getcool", "getproject", "coolhq", "projecthq"] {
            assert!(names.iter().any(|n| n == name), "missing {name}: {names:?}");
        }
        assert_eq!(names.len(), 14);
        assert_eq!(generate_suggestions(&["cool".into()]).len(), 14);
        let names = generate_suggestions(&["cool".into(), "cool".into(), "x".repeat(63)]);
        assert_eq!(names.iter().collect::<std::collections::HashSet<_>>().len(), names.len());
        assert!(names.iter().all(|n| valid_label(n)));
    }

    #[test]
    fn retry_targets_only_unknown_and_preserves_other_results() {
        let mut results = vec![("example.com".into(), Availability::Available), ("example.gg".into(), Availability::Unknown(UnknownReason::Inconclusive)), ("example.io".into(), Availability::Protected(ProtectionReason::Reserved))];
        assert_eq!(retry_domains(&results), vec![("example".into(), "gg")]);
        merge_retry(&mut results, vec![("example.gg".into(), Availability::Taken(DomainDates::default()))]);
        assert_eq!(results.iter().map(|(_, s)| s.as_str()).collect::<Vec<_>>(), vec!["available", "taken", "protected"]);
    }

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

    #[test]
    fn full_domains_and_tld_lists_are_normalized_and_validated() {
        assert_eq!(parse_search(" MyName.IO ").unwrap(), ("myname".into(), Some("io")));
        assert_eq!(parse_search("MyName").unwrap(), ("myname".into(), None));
        assert_eq!(parse_suggest("yoyo+").unwrap().unwrap(), (Some("yoyo".into()), None));
        assert_eq!(parse_suggest("yoyo+.com").unwrap().unwrap(), (Some("yoyo".into()), Some("com")));
        assert_eq!(parse_suggest("yoyo.com+").unwrap().unwrap(), (Some("yoyo".into()), Some("com")));
        assert_eq!(parse_suggest("+").unwrap().unwrap(), (None, None));
        assert_eq!(parse_suggest("+.io").unwrap().unwrap(), (None, Some("io")));
        assert!(parse_suggest("yoyo+.nope").unwrap().is_err());
        assert!(parse_suggest("yo+yo").is_none());
        assert!(parse_suggest("yoyo").is_none());
        assert_eq!(parse_tlds("COM, io,com").unwrap(), vec!["com", "io"]);
        assert!(parse_tlds("com,no-such-tld").is_err());
        assert!(parse_tlds("").is_err());
        for input in ["", "-name", "name-", "name with spaces", "sub.name.com", "name.invalid", "name/com", "💩.com"] {
            assert!(parse_search(input).is_err(), "{input}");
        }
        assert_eq!(search_tlds(Some("bot"), Some(&["com", "io"])), vec!["bot"]);
        assert_eq!(search_tlds(None, Some(&["com", "io"])), vec!["com", "io"]);
        assert_eq!(search_tlds(None, None), ALL_TLDS.to_vec());
        assert!(valid_label(&"a".repeat(63)));
        assert!(!valid_label(&"a".repeat(64)));
    }

    // First lines of real WHOIS replies (2026-10-02): nic.<tld> is registered, the random name is free.
    const WHOIS_REPLIES: &[(&str, &str, bool)] = &[
        ("com", r#"Domain Name: NIC.COM
Registry Domain ID: 91988_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.networksolutions.com
Registrar URL: http://networksolutions.com"#, true),
        ("com", r#"No match for "ZQ7X9K2MVB4TQW1P.COM".
>>> Last update of whois database: 2026-10-02T01:36:43Z <<<
NOTICE: The expiration date displayed in this record is the date the
registrar's sponsorship of the domain name registration in the registry is"#, false),
        ("net", r#"Domain Name: NIC.NET
Registry Domain ID: 2707346_DOMAIN_NET-VRSN
Registrar WHOIS Server: whois.domain.com
Registrar URL: http://www.domain.com"#, true),
        ("net", r#"No match for "ZQ7X9K2MVB4TQW1P.NET".
>>> Last update of whois database: 2026-10-02T01:36:43Z <<<
NOTICE: The expiration date displayed in this record is the date the
registrar's sponsorship of the domain name registration in the registry is"#, false),
        ("org", r#"Domain Name: nic.org
Registry Domain ID: REDACTED
Registrar WHOIS Server: whois.namecheap.com
Registrar URL: http://www.namecheap.com"#, true),
        ("org", r#"Domain not found.
>>> Last update of WHOIS database: 2026-10-02T01:37:00Z <<<
Terms of Use: Access to Public Interest Registry WHOIS information is provided to assist persons in determining the contents of a domain name registration record in the Public Interest Registry registry database. The data in this record is provided by Public Interest Registry for informational purposes only, and Public Interest Registry does not guarantee its accuracy. This service is intended only for query-based access. You agree that you will use this data only for lawful purposes and that, under no circumstances will you use this data to (a) allow, enable, or otherwise support the transmission by e-mail, telephone, or facsimile of mass unsolicited, commercial advertising or solicitations to entities other than the data recipient's own existing customers; or (b) enable high volume, automated, electronic processes that send queries or data to the systems of Registry Operator, a Registrar, or Identity Digital except as reasonably necessary to register domain names or modify existing registrations. All rights reserved. Public Interest Registry reserves the right to modify these terms at any time. By submitting this query, you agree to abide by this policy.  The Registrar of Record identified in this output may have an RDDS service that can be queried for additional information on how to contact the Registrant, Admin, or Tech contact of the queried domain name."#, false),
        ("io", r#"This domain is protected by the Registry Lock service. If you are the registrant and wish to take action on this lock, please contact your registrar.
Domain Name: nic.io
Registry Domain ID: REDACTED
Registrar WHOIS Server: whois.identitydigital.services"#, true),
        ("io", r#"Domain not found.
>>> Last update of WHOIS database: 2026-10-02T01:37:05Z <<<
Terms of Use: Access to WHOIS information is provided to assist persons in determining the contents of a domain name registration record in the registry database. The data in this record is provided by Identity Digital or the Registry Operator for informational purposes only, and accuracy is not guaranteed. This service is intended only for query-based access. You agree that you will use this data only for lawful purposes and that, under no circumstances will you use this data to (a) allow, enable, or otherwise support the transmission by e-mail, telephone, or facsimile of mass unsolicited, commercial advertising or solicitations to entities other than the data recipient's own existing customers; or (b) enable high volume, automated, electronic processes that send queries or data to the systems of Registry Operator, a Registrar, or Identity Digital except as reasonably necessary to register domain names or modify existing registrations. When using the Whois service, please consider the following: The Whois service is not a replacement for standard EPP commands to the SRS service. Whois is not considered authoritative for registered domain objects. The Whois service may be scheduled for downtime during production or OT&E maintenance periods. Queries to the Whois services are throttled. If too many queries are received from a single IP address within a specified time, the service will begin to reject further queries for a period of time to prevent disruption of Whois service access. Abuse of the Whois system through data mining is mitigated by detecting and limiting bulk query access from single sources. Where applicable, the presence of a [Non-Public Data] tag indicates that such data is not made publicly available due to applicable data privacy laws or requirements. Should you wish to contact the registrant, please refer to the Whois records available through the registrar URL listed above. Access to non-public data may be provided, upon request, where it can be reasonably confirmed that the requester holds a specific legitimate interest and a proper legal basis for accessing the withheld data. Access to this data provided by Identity Digital can be requested by submitting a request via the form found at https://www.identity.digital/about/policies/whois-layered-access/. The Registrar of Record identified in this output may have an RDDS service that can be queried for additional information on how to contact the Registrant, Admin, or Tech contact of the queried domain name. Identity Digital Inc. and Registry Operator reserve the right to modify these terms at any time. By submitting this query, you agree to abide by this policy."#, false),
        ("co", r#"Domain Name: NIC.CO
Registry Domain ID: D30230624-CNIC
Registrar WHOIS Server: whois.registry.co
Registrar URL: https://registry.co/"#, true),
        ("co", r#"The queried object does not exist: DOMAIN NOT FOUND
>>> Last update of WHOIS database: 2026-10-02T01:37:14.0Z <<<"#, false),
        ("ai", r#"This domain is protected by the Registry Lock service. If you are the registrant and wish to take action on this lock, please contact your registrar.
Domain Name: nic.ai
Registry Domain ID: 5ff032b7dd2f49d899c246a6937ea818-DONUTS
Registrar WHOIS Server: whois.identitydigital.services"#, true),
        ("ai", r#"Domain not found.
>>> Last update of WHOIS database: 2026-10-02T01:37:19Z <<<
Terms of Use: Access to WHOIS information is provided to assist persons in determining the contents of a domain name registration record in the registry database. The data in this record is provided by Identity Digital or the Registry Operator for informational purposes only, and accuracy is not guaranteed. This service is intended only for query-based access. You agree that you will use this data only for lawful purposes and that, under no circumstances will you use this data to (a) allow, enable, or otherwise support the transmission by e-mail, telephone, or facsimile of mass unsolicited, commercial advertising or solicitations to entities other than the data recipient's own existing customers; or (b) enable high volume, automated, electronic processes that send queries or data to the systems of Registry Operator, a Registrar, or Identity Digital except as reasonably necessary to register domain names or modify existing registrations. When using the Whois service, please consider the following: The Whois service is not a replacement for standard EPP commands to the SRS service. Whois is not considered authoritative for registered domain objects. The Whois service may be scheduled for downtime during production or OT&E maintenance periods. Queries to the Whois services are throttled. If too many queries are received from a single IP address within a specified time, the service will begin to reject further queries for a period of time to prevent disruption of Whois service access. Abuse of the Whois system through data mining is mitigated by detecting and limiting bulk query access from single sources. Where applicable, the presence of a [Non-Public Data] tag indicates that such data is not made publicly available due to applicable data privacy laws or requirements. Should you wish to contact the registrant, please refer to the Whois records available through the registrar URL listed above. Access to non-public data may be provided, upon request, where it can be reasonably confirmed that the requester holds a specific legitimate interest and a proper legal basis for accessing the withheld data. Access to this data provided by Identity Digital can be requested by submitting a request via the form found at https://www.identity.digital/about/policies/whois-layered-access/. The Registrar of Record identified in this output may have an RDDS service that can be queried for additional information on how to contact the Registrant, Admin, or Tech contact of the queried domain name. Identity Digital Inc. and Registry Operator reserve the right to modify these terms at any time. By submitting this query, you agree to abide by this policy."#, false),
        ("me", r#"This domain is protected by the Registry Lock service. If you are the registrant and wish to take action on this lock, please contact your registrar.
Domain Name: nic.me
Registry Domain ID: REDACTED
Registrar WHOIS Server: whois.identitydigital.services"#, true),
        ("me", r#"Domain not found.
>>> Last update of WHOIS database: 2026-10-02T01:37:24Z <<<
Terms of Use: Access to WHOIS information is provided to assist persons in determining the contents of a domain name registration record in the registry database. The data in this record is provided by Identity Digital or the Registry Operator for informational purposes only, and accuracy is not guaranteed. This service is intended only for query-based access. You agree that you will use this data only for lawful purposes and that, under no circumstances will you use this data to (a) allow, enable, or otherwise support the transmission by e-mail, telephone, or facsimile of mass unsolicited, commercial advertising or solicitations to entities other than the data recipient's own existing customers; or (b) enable high volume, automated, electronic processes that send queries or data to the systems of Registry Operator, a Registrar, or Identity Digital except as reasonably necessary to register domain names or modify existing registrations. When using the Whois service, please consider the following: The Whois service is not a replacement for standard EPP commands to the SRS service. Whois is not considered authoritative for registered domain objects. The Whois service may be scheduled for downtime during production or OT&E maintenance periods. Queries to the Whois services are throttled. If too many queries are received from a single IP address within a specified time, the service will begin to reject further queries for a period of time to prevent disruption of Whois service access. Abuse of the Whois system through data mining is mitigated by detecting and limiting bulk query access from single sources. Where applicable, the presence of a [Non-Public Data] tag indicates that such data is not made publicly available due to applicable data privacy laws or requirements. Should you wish to contact the registrant, please refer to the Whois records available through the registrar URL listed above. Access to non-public data may be provided, upon request, where it can be reasonably confirmed that the requester holds a specific legitimate interest and a proper legal basis for accessing the withheld data. Access to this data provided by Identity Digital can be requested by submitting a request via the form found at https://www.identity.digital/about/policies/whois-layered-access/. The Registrar of Record identified in this output may have an RDDS service that can be queried for additional information on how to contact the Registrant, Admin, or Tech contact of the queried domain name. Identity Digital Inc. and Registry Operator reserve the right to modify these terms at any time. By submitting this query, you agree to abide by this policy."#, false),
        ("so", r#"Domain Name: nic.so
Registry Domain ID: 31099-sonic
Updated Date: 2024-07-14T07:04:38Z
Creation Date: 2010-10-31T00:00:00Z"#, true),
        ("so", r#"Domain Name: zq7x9k2mvb4tqw1p.so
The queried object does not exist: No Object Found
>>> Last update of WHOIS database: 2026-10-02T01:32:34.064Z <<<
TERMS OF USE: You are not authorized to access or query our WHOIS database through the use of electronic processes that are high-volume and automated.  This WHOIS database is provided by as a service to the internet community."#, false),
        ("gg", r#"Domain:
nic.gg
Domain Status:
Active"#, true),
        ("gg", r#"NOT FOUND"#, false),
        ("cc", r#"Domain Name: NIC.CC
Registry Domain ID: 86413629_DOMAIN_CC-VRSN
Registrar WHOIS Server: whois.corporatedomains.com
Registrar URL: http://cscdbs.com"#, true),
        ("cc", r#"No match for "ZQ7X9K2MVB4TQW1P.CC".
>>> Last update of WHOIS database: 2026-10-02T01:37:24Z <<<
NOTICE: The expiration date displayed in this record is the date the
registrar's sponsorship of the domain name registration in the registry is"#, false),
        ("xyz", r#"Domain Name: NIC.XYZ
Registry Domain ID: D1465615-CNIC
Registrar WHOIS Server: whois.nic.xyz
Registrar URL: https://gen.xyz/"#, true),
        ("xyz", r#"The queried object does not exist: DOMAIN NOT FOUND
>>> Last update of WHOIS database: 2026-10-02T01:37:42.0Z <<<"#, false),
        ("sh", r#"This domain is protected by the Registry Lock service. If you are the registrant and wish to take action on this lock, please contact your registrar.
Domain Name: nic.sh
Registry Domain ID: REDACTED
Registrar WHOIS Server: whois.identitydigital.services"#, true),
        ("sh", r#"Domain not found.
>>> Last update of WHOIS database: 2026-10-02T01:37:51Z <<<
Terms of Use: Access to WHOIS information is provided to assist persons in determining the contents of a domain name registration record in the registry database. The data in this record is provided by Identity Digital or the Registry Operator for informational purposes only, and accuracy is not guaranteed. This service is intended only for query-based access. You agree that you will use this data only for lawful purposes and that, under no circumstances will you use this data to (a) allow, enable, or otherwise support the transmission by e-mail, telephone, or facsimile of mass unsolicited, commercial advertising or solicitations to entities other than the data recipient's own existing customers; or (b) enable high volume, automated, electronic processes that send queries or data to the systems of Registry Operator, a Registrar, or Identity Digital except as reasonably necessary to register domain names or modify existing registrations. When using the Whois service, please consider the following: The Whois service is not a replacement for standard EPP commands to the SRS service. Whois is not considered authoritative for registered domain objects. The Whois service may be scheduled for downtime during production or OT&E maintenance periods. Queries to the Whois services are throttled. If too many queries are received from a single IP address within a specified time, the service will begin to reject further queries for a period of time to prevent disruption of Whois service access. Abuse of the Whois system through data mining is mitigated by detecting and limiting bulk query access from single sources. Where applicable, the presence of a [Non-Public Data] tag indicates that such data is not made publicly available due to applicable data privacy laws or requirements. Should you wish to contact the registrant, please refer to the Whois records available through the registrar URL listed above. Access to non-public data may be provided, upon request, where it can be reasonably confirmed that the requester holds a specific legitimate interest and a proper legal basis for accessing the withheld data. Access to this data provided by Identity Digital can be requested by submitting a request via the form found at https://www.identity.digital/about/policies/whois-layered-access/. The Registrar of Record identified in this output may have an RDDS service that can be queried for additional information on how to contact the Registrant, Admin, or Tech contact of the queried domain name. Identity Digital Inc. and Registry Operator reserve the right to modify these terms at any time. By submitting this query, you agree to abide by this policy."#, false),
        ("fm", r#"Domain Name: NIC.FM
Registry Domain ID: D34891389-CNIC
Registrar WHOIS Server: whois.nic.fm
Registrar URL: https://brsmedia.fm"#, true),
        ("fm", r#"The queried object does not exist: DOMAIN NOT FOUND
>>> Last update of WHOIS database: 2026-10-02T01:37:55.0Z <<<"#, false),
    ];

    #[test]
    fn real_whois_replies_from_every_server_are_classified_correctly() {
        for (tld, reply, registered) in WHOIS_REPLIES {
            let result = parse_whois(reply, tld);
            if *registered {
                assert!(matches!(result, Availability::Taken(_)), "{tld} registered → {:?}\n{reply}", result.as_str());
            } else {
                assert!(matches!(result, Availability::Available), "{tld} free → {:?}\n{reply}", result.as_str());
            }
        }
    }

    #[test]
    fn whois_text_mentioning_domain_mid_line_is_not_a_record() {
        let limited = "Query rate exceeded for domain: example.io. Try again later.";
        assert!(matches!(parse_whois(limited, "io"), Availability::Unknown(_)));
        assert!(matches!(parse_whois("WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS", "org"), Availability::Unknown(_)));
    }

    // Serves one HTTP response to whatever connects, returning the client-facing URL.
    fn one_response(host: &str, status: &str, body: &'static str) -> (String, std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let response = format!("HTTP/1.1 {status}\r\nContent-Type: application/rdap+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        let server = std::thread::spawn(move || {
            let mut connection = accept(&listener);
            connection.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut request = [0; 1024];
            let _ = connection.read(&mut request);
            connection.write_all(response.as_bytes()).unwrap();
        });
        (format!("http://{host}:{}/domain/nic.co", addr.port()), addr, server)
    }

    #[tokio::test]
    async fn rdap_failure_reasons_stay_unknown_without_bootstrap_retries() {
        let client = Client::builder().no_proxy().build().unwrap();
        for (status, body, expected) in [
            ("429 Too Many Requests", "not found", UnknownReason::RateLimited),
            ("503 Unavailable", "outage", UnknownReason::ServiceUnavailable),
            ("504 Gateway Timeout", "timeout", UnknownReason::Timeout),
            ("200 OK", "{}", UnknownReason::InvalidResponse),
            ("404 Not Found", "<html>blocked</html>", UnknownReason::InvalidResponse),
        ] {
            let (url, _, server) = one_response("127.0.0.1", status, body);
            let fallback = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            fallback.set_nonblocking(true).unwrap();
            let fallback_url = format!("http://{}/fallback", fallback.local_addr().unwrap());
            let result = tokio::time::timeout(Duration::from_secs(2), rdap_check(&client, &url, &fallback_url, &Semaphore::new(1))).await.unwrap();
            server.join().unwrap();
            assert!(matches!(result, Availability::Unknown(reason) if reason == expected));
            assert_eq!(result.as_str(), "unknown");
            assert_eq!(fallback.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        }
    }

    #[tokio::test]
    async fn rdap_transport_failure_uses_fallback_and_keeps_its_reason() {
        let client = Client::builder().no_proxy().build().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let unreachable = format!("http://{}/domain/example.com", listener.local_addr().unwrap());
        drop(listener);
        for (status, body, expected) in [
            ("404 Not Found", r#"{"errorCode":404}"#, "available"),
            ("429 Too Many Requests", "limited", "unknown"),
        ] {
            let (fallback, _, server) = one_response("127.0.0.1", status, body);
            let result = rdap_check(&client, &unreachable, &fallback, &Semaphore::new(1)).await;
            server.join().unwrap();
            assert_eq!(result.as_str(), expected);
            if expected == "unknown" { assert!(matches!(result, Availability::Unknown(UnknownReason::RateLimited))); }
        }
    }

    // Release the reply only after the client has timed out; no sleep races or
    // external registry services are needed to exercise interrupted responses.
    fn held_response(prefix: &'static [u8]) -> (std::net::SocketAddr, std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (release, held) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let mut stream = accept(&listener);
            stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut request = [0; 4096];
            stream.read(&mut request).unwrap();
            stream.write_all(prefix).unwrap();
            held.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        (addr, release, server)
    }

    #[tokio::test]
    async fn interrupted_registry_replies_keep_timeout_reasons() {
        let client = Client::builder().no_proxy().build().unwrap();
        let (addr, release, server) = held_response(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}");
        let url = format!("http://{addr}/domain/example.com");
        let result = http_query_with_timeout(&client, &url, &Semaphore::new(1), Duration::from_millis(200)).await;
        release.send(()).unwrap();
        server.join().unwrap();
        assert!(matches!(result, Ok(Availability::Unknown(UnknownReason::Timeout))));

        // A partial WHOIS not-found reply is not proof of availability.
        let (addr, release, server) = held_response(b"No match for example.com\r\n");
        let result = whois_query(&addr.to_string(), "example.com", "com", false,
            Duration::from_secs(1), Duration::from_millis(200)).await;
        release.send(()).unwrap();
        server.join().unwrap();
        assert!(matches!(result, Availability::Unknown(UnknownReason::Timeout)));
    }

    #[test]
    fn registry_reasons_survive_merging_without_overriding_known_statuses() {
        for reason in [UnknownReason::Timeout, UnknownReason::RateLimited, UnknownReason::InvalidResponse,
            UnknownReason::Unreachable, UnknownReason::ServiceUnavailable, UnknownReason::NoRegistryService] {
            let unknown = || Availability::Unknown(reason);
            let dns = || Availability::Unknown(UnknownReason::Inconclusive);
            let result = merge_results(unknown(), dns(), dns());
            assert!(matches!(result, Availability::Unknown(r) if r == reason));
            assert!(matches!(merge_results(unknown(), Availability::Available, dns()), Availability::Available));
            assert!(matches!(merge_results(Availability::Available, unknown(), dns()), Availability::Available));
            assert!(matches!(merge_results(unknown(), unknown(), Availability::Taken(DomainDates::default())), Availability::Taken(_)));
        }
        let result = merge_results(Availability::Unknown(UnknownReason::InvalidResponse),
            Availability::Unknown(UnknownReason::RateLimited), Availability::Unknown(UnknownReason::Inconclusive));
        assert!(matches!(result, Availability::Unknown(UnknownReason::RateLimited)));
    }

    #[test]
    fn whois_errors_have_reasons_without_matching_rate_policy_footers() {
        for response in ["Query rate exceeded for domain: example.io. Try again later.", "WHOIS LIMIT EXCEEDED", "% Too many queries", "Error: rate limit exceeded"] {
            assert!(matches!(parse_whois(response, "io"), Availability::Unknown(UnknownReason::RateLimited)));
        }
        assert!(matches!(parse_whois("WHOIS service not available", "com"), Availability::Unknown(UnknownReason::ServiceUnavailable)));
        assert!(matches!(parse_whois("", "com"), Availability::Unknown(UnknownReason::InvalidResponse)));
        assert!(matches!(parse_whois("No match for example.com\nTerms: rate limits may apply", "com"), Availability::Available));
        assert!(matches!(parse_whois("Domain Name: example.com\nTerms: rate limits may apply", "com"), Availability::Taken(_)));
    }

    #[tokio::test]
    async fn rdap_org_no_service_404_is_not_availability() {
        // rdap.org's real reply for TLDs it can't route (seen for .co, .so, .gg, .sh, .io).
        let no_service = r#"{"rdapConformance":["rdap_level_0"],"lang":"en","errorCode":404,"title":"No RDAP service is available for this resource"}"#;
        let (url, addr, server) = one_response("rdap.org", "404 Not Found", no_service);
        let client = Client::builder().no_proxy().resolve("rdap.org", addr).build().unwrap();
        let result = http_query(&client, &url, &Semaphore::new(1)).await;
        server.join().unwrap();
        assert!(matches!(result, Ok(Availability::Unknown(_))), "got {:?}", result.map(|r| r.as_str()));

        // The same 404 from a registry's own server does mean the name is free.
        let (url, _, server) = one_response("127.0.0.1", "404 Not Found", r#"{"errorCode":404,"title":"Not Found"}"#);
        let result = http_query(&Client::builder().no_proxy().build().unwrap(), &url, &Semaphore::new(1)).await;
        server.join().unwrap();
        assert!(matches!(result, Ok(Availability::Available)));
    }

    #[test]
    fn extensions_without_working_rdap_use_whois() {
        assert_eq!(rdap_url("nic", "co"), None);
        assert!(whois_server("co").is_some());
        assert_eq!(rdap_url("nic", "so").as_deref(), Some("https://rdap.nic.so/domain/nic.so"));
    }

    #[test]
    fn whois_boilerplate_does_not_mean_available_or_reserved() {
        assert!(matches!(parse_whois("WHOIS service not available", "com"), Availability::Unknown(_)));
        assert!(matches!(parse_whois("No match for example.com\nAll rights reserved", "com"), Availability::Available));
        assert!(matches!(parse_whois("Status: reserved", "com"), Availability::Protected(_)));
        assert!(matches!(parse_whois("Domain Name: EXAMPLE.COM\nNames may be available", "com"), Availability::Taken(_)));
        let so_missing = "Domain Name: zqxdott21.so\nThe queried object does not exist: No Object Found\n";
        assert!(matches!(parse_whois(so_missing, "so"), Availability::Available));
    }

    #[test]
    fn bot_domains_use_the_registry_endpoint_and_supported_tld_selection() {
        assert_eq!(parse_search("Example.BOT").unwrap(), ("example".into(), Some("bot")));
        assert_eq!(parse_tlds("com,bot").unwrap(), vec!["com", "bot"]);
        assert_eq!(rdap_url("example", "bot").unwrap(), "https://rdap.nominet.uk/bot/domain/example.bot");
        assert!(tld_rank("example.bot") < 99);
    }

    #[test]
    fn si_click_and_fun_use_their_registry_endpoints_and_selection() {
        for (tld, endpoint, whois) in [
            ("si", "https://rdap.register.si/domain/example.si", "whois.register.si"),
            ("click", "https://rdap.registry.click/rdap/domain/example.click", "whois.registry.click"),
            ("fun", "https://rdap.radix.host/rdap/domain/example.fun", "whois.nic.fun"),
        ] {
            assert_eq!(parse_search(&format!("Example.{}", tld.to_uppercase())).unwrap(), ("example".into(), Some(tld)));
            assert_eq!(parse_suggest(&format!("example+.{tld}")).unwrap().unwrap(), (Some("example".into()), Some(tld)));
            assert_eq!(rdap_url("example", tld).as_deref(), Some(endpoint));
            assert_eq!(whois_server(tld), Some(whois));
            assert!(tld_rank(&format!("example.{tld}")) < 99);
        }
        assert_eq!(parse_tlds("SI,click,fun,si").unwrap(), vec!["si", "click", "fun"]);
        let ranks: std::collections::HashSet<_> = ALL_TLDS.iter().map(|tld| tld_rank(tld)).collect();
        assert_eq!(ranks.len(), ALL_TLDS.len());
    }

    #[tokio::test]
    async fn new_registry_paths_classify_local_rdap_replies() {
        use std::io::{Read, Write};
        for tld in ALL_TLDS.iter().copied().filter(|tld| rdap_url("example", tld).is_some()) {
            for (status, body, expected) in [
                ("200 OK", r#"{"objectClassName":"domain","ldhName":"PLACEHOLDER","events":[{"eventAction":"expiration","eventDate":"2027-10-28"}]}"#, "taken"),
                ("404 Not Found", r#"{"errorCode":404,"title":"Not Found"}"#, "available"),
                ("200 OK", "{}", "unknown"),
            ] {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let addr = listener.local_addr().unwrap();
                let mut url = reqwest::Url::parse(&rdap_url("example", tld).unwrap()).unwrap();
                let host = url.host_str().unwrap().to_owned();
                let expected_path = url.path().to_owned();
                url.set_scheme("http").unwrap();
                url.set_port(Some(addr.port())).unwrap();
                let body = body.replace("PLACEHOLDER", &format!("example.{tld}"));
                let server = std::thread::spawn(move || {
                    let mut stream = accept(&listener);
                    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                    let mut request = [0; 4096];
                    let size = stream.read(&mut request).unwrap();
                    assert!(std::str::from_utf8(&request[..size]).unwrap().starts_with(&format!("GET {expected_path} HTTP/1.1\r\n")));
                    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/rdap+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                });
                let client = Client::builder().no_proxy().resolve(&host, addr).build().unwrap();
                let result = http_query(&client, url.as_str(), &Semaphore::new(1)).await.unwrap();
                server.join().unwrap();
                assert_eq!(result.as_str(), expected, "{tld}: {status}");
                if let Availability::Taken(dates) = result { assert_eq!(dates.expires.as_deref(), Some("2027-10-28")); }
            }
        }
    }

    #[test]
    fn new_whois_formats_are_recognized_without_matching_boilerplate() {
        let si_record = "domain:\t\tregistry.si\nstatus:\t\tserver_delete_prohibited\ncreated:\t2008-10-28\nexpire:\t\t2027-10-28\n";
        match parse_whois(si_record, "si") {
            Availability::Taken(dates) => {
                assert_eq!(dates.registered.as_deref(), Some("2008-10-28"));
                assert_eq!(dates.expires.as_deref(), Some("2027-10-28"));
            }
            _ => panic!("expected a registered .si record"),
        }
        assert!(matches!(parse_whois("% No entries found for the selected source(s).", "si"), Availability::Available));
        for tld in ["click", "fun"] {
            assert!(matches!(parse_whois(&format!(">>> Domain example.{tld} is available for registration\n\n>>> Please visit the registry for registrars"), tld), Availability::Available));
            assert!(matches!(parse_whois(&format!("Domain Name: nic.{tld}\nCreation Date: 2016-10-25T11:48:07.000Z"), tld), Availability::Taken(_)));
            for body in ["Domains may be available for registration", ">>> Domain example.com is available for registration", ">>> Domain invalid/name.fun is available for registration"] {
                assert!(matches!(parse_whois(body, tld), Availability::Unknown(_)), "{tld}: {body}");
            }
        }
    }

    #[test]
    fn watch_notifications_retry_failures_and_ignore_inconclusive_results() {
        let mut entry = WatchEntry { domain: "example.com".into(), last_status: "taken".into() };
        assert!(!refresh_watch_entry(&mut entry, &Availability::Unknown(UnknownReason::Inconclusive), |_, _| panic!("unknown must not notify")).unwrap());
        assert_eq!(entry.last_status, "taken");
        assert!(!refresh_watch_entry(&mut entry, &Availability::Taken(DomainDates::default()), |_, _| panic!("unchanged must not notify")).unwrap());
        assert!(refresh_watch_entry(&mut entry, &Availability::Available, |_, _| Err("osascript failed".into())).is_err());
        assert_eq!(entry.last_status, "taken", "failed notification must be retried");
        assert!(refresh_watch_entry(&mut entry, &Availability::Available, |title, body| {
            assert_eq!(title, "dott — available!");
            assert!(body.contains("example.com"));
            Ok(())
        }).unwrap());
        assert_eq!(entry.last_status, "available");
        assert!(!refresh_watch_entry(&mut entry, &Availability::Unknown(UnknownReason::Inconclusive), |_, _| panic!("outage must not notify")).unwrap());
        assert!(!refresh_watch_entry(&mut entry, &Availability::Available, |_, _| panic!("must not notify twice")).unwrap());
        assert!(refresh_watch_entry(&mut entry, &Availability::Protected(ProtectionReason::Reserved), |_, _| panic!("protected must not notify")).unwrap());
        assert_eq!(entry.last_status, "protected");
    }

    #[test]
    fn watchlist_persistence_reports_corruption_and_failed_writes() {
        let path = std::env::temp_dir().join(format!("dott-watch-test-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir(&path).unwrap();
        let file = path.join("watchlist.json");
        assert!(load_watchlist_at(&file).unwrap().is_empty());
        let entries = vec![WatchEntry { domain: "example.com".into(), last_status: "taken".into() }];
        save_watchlist_at(&file, &entries).unwrap();
        let loaded = load_watchlist_at(&file).unwrap();
        assert_eq!(loaded[0].domain, "example.com");
        fs::write(&file, b"not json").unwrap();
        assert!(load_watchlist_at(&file).is_err());
        assert_eq!(fs::read(&file).unwrap(), b"not json");
        assert!(save_watchlist_at(&path, &entries).is_err());
        assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
        fs::remove_dir_all(path).unwrap();
    }

    #[tokio::test]
    async fn malformed_rdap_success_is_inconclusive() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/domain/example.com", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let mut connection = accept(&listener);
            connection.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut request = [0; 1024];
            let _ = connection.read(&mut request).unwrap();
            connection.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").unwrap();
        });
        let result = http_query(&Client::builder().no_proxy().build().unwrap(), &url, &Semaphore::new(1)).await;
        server.join().unwrap();
        assert!(matches!(result, Ok(Availability::Unknown(_))), "a response must not trigger the rdap.org retry");
    }

    #[tokio::test]
    async fn only_unreachable_rdap_servers_are_retried() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/domain/example.com", listener.local_addr().unwrap());
        drop(listener);
        let result = http_query(&Client::builder().no_proxy().build().unwrap(), &url, &Semaphore::new(1)).await;
        assert_eq!(result.unwrap_err(), UnknownReason::Unreachable);
    }

    #[test]
    fn parse_date_iso() {
        assert_eq!(parse_date("2026-04-19"), Some("2026-04-19".to_string()));
    }

    #[test]
    fn parse_date_embedded_in_timestamp() {
        assert_eq!(parse_date("Expires: 2027-01-15T00:00:00Z"), Some("2027-01-15".to_string()));
    }

    #[test]
    fn parse_date_returns_first_match() {
        assert_eq!(parse_date("reg 2020-01-01 exp 2030-12-31"), Some("2020-01-01".to_string()));
    }

    #[test]
    fn parse_date_none() {
        assert_eq!(parse_date("no dates here"), None);
        assert_eq!(parse_date(""), None);
        assert_eq!(parse_date("2026-1-1"), None); // non-zero-padded rejected
    }

    fn dates_with_expiry(exp: &str) -> DomainDates {
        DomainDates { registered: None, updated: None, expires: Some(exp.to_string()) }
    }

    #[test]
    fn dns_taken_overrides_all_unknown() {
        let out = merge_results(
            Availability::Unknown(UnknownReason::Inconclusive),
            Availability::Unknown(UnknownReason::Inconclusive),
            Availability::Taken(DomainDates::default()),
        );
        assert!(matches!(out, Availability::Taken(_)));
    }

    #[test]
    fn dns_taken_keeps_whois_expiry() {
        let out = merge_results(
            Availability::Unknown(UnknownReason::Inconclusive),
            Availability::Taken(dates_with_expiry("2027-01-01")),
            Availability::Taken(DomainDates::default()),
        );
        match out {
            Availability::Taken(d) => assert_eq!(d.expires.as_deref(), Some("2027-01-01")),
            _ => panic!("expected Taken with WHOIS expiry preserved"),
        }
    }

    #[test]
    fn rdap_wins_but_whois_fills_gaps() {
        let rdap = DomainDates {
            registered: Some("2020-01-01".into()),
            updated:    None,
            expires:    Some("2026-01-01".into()),
        };
        let whois = DomainDates {
            registered: Some("2019-05-05".into()),
            updated:    Some("2024-06-06".into()),
            expires:    Some("2027-12-31".into()),
        };
        let out = merge_results(
            Availability::Taken(rdap),
            Availability::Taken(whois),
            Availability::Unknown(UnknownReason::Inconclusive),
        );
        match out {
            Availability::Taken(d) => {
                assert_eq!(d.registered.as_deref(), Some("2020-01-01")); // RDAP wins
                assert_eq!(d.updated.as_deref(),    Some("2024-06-06")); // WHOIS fills gap
                assert_eq!(d.expires.as_deref(),    Some("2026-01-01")); // RDAP wins
            }
            _ => panic!("expected Taken"),
        }
    }

    #[test]
    fn warm_up_targets_only_selected_servers_without_domains() {
        assert_eq!(warm_origins(&["com", "net"]), vec!["https://cloudflare-dns.com/", "https://rdap.verisign.com/"]);
        assert_eq!(warm_origins(&["sh", "gg"]), vec!["https://cloudflare-dns.com/"], "WHOIS-only extensions");
        let all = warm_origins(ALL_TLDS);
        assert!(all.contains(&"https://rdap.registry.gy/".to_string()));
        for origin in all {
            let url = reqwest::Url::parse(&origin).unwrap();
            assert_eq!(url.path(), "/", "warm-up must not include a domain query");
            assert!(url.query().is_none() && url.fragment().is_none());
        }
    }

    #[test]
    fn rdap_taken_does_not_depend_on_dns() {
        // check_domain skips waiting for DNS once RDAP says taken; the merge must agree.
        let rdap = || Availability::Taken(dates_with_expiry("2027-01-01"));
        for dns in [Availability::Taken(DomainDates::default()), Availability::Unknown(UnknownReason::Inconclusive)] {
            match merge_results(rdap(), Availability::Unknown(UnknownReason::Inconclusive), dns) {
                Availability::Taken(d) => assert_eq!(d.expires.as_deref(), Some("2027-01-01")),
                _ => panic!("expected Taken with RDAP dates"),
            }
        }
    }

    #[test]
    fn positive_whois_record_overrides_negative_rdap() {
        let out = merge_results(
            Availability::Available,
            Availability::Taken(DomainDates::default()),
            Availability::Unknown(UnknownReason::Inconclusive),
        );
        assert!(matches!(out, Availability::Taken(_)));
    }

    #[test]
    fn whois_fallback_when_rdap_unknown() {
        let out = merge_results(
            Availability::Unknown(UnknownReason::Inconclusive),
            Availability::Taken(dates_with_expiry("2027-01-01")),
            Availability::Unknown(UnknownReason::Inconclusive),
        );
        match out {
            Availability::Taken(d) => assert_eq!(d.expires.as_deref(), Some("2027-01-01")),
            _ => panic!("expected Taken from WHOIS fallback"),
        }
    }

    #[test]
    fn premium_heuristic_flags_short_names_in_premium_tlds() {
        assert!(is_likely_premium("go.ai"));
        assert!(is_likely_premium("x.io"));
        assert!(is_likely_premium("app.dev"));
        assert!(is_likely_premium("four.co"));
        for domain in ["x.me", "go.me", "pos.me", "4g.me"] {
            assert!(is_likely_premium(domain), "{domain}");
        }
    }

    #[test]
    fn premium_heuristic_ignores_long_names_and_other_tlds() {
        assert!(!is_likely_premium("mystartup.ai"));   // too long
        assert!(!is_likely_premium("go.com"));          // not a flagged TLD
        assert!(!is_likely_premium("go.xyz"));          // not a flagged TLD
        assert!(!is_likely_premium("noseparator"));     // no TLD
        assert!(!is_likely_premium("four.me"));         // not a blanket rule for longer .me names
        assert!(!is_likely_premium("myproject.me"));
    }

    #[test]
    fn all_unknown_stays_unknown() {
        let out = merge_results(Availability::Unknown(UnknownReason::Inconclusive), Availability::Unknown(UnknownReason::Inconclusive), Availability::Unknown(UnknownReason::Inconclusive));
        assert!(matches!(out, Availability::Unknown(_)));
    }
}
