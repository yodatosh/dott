use colored::*;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType},
};
use futures::{future::join_all, FutureExt};
use reqwest::Client;
use std::{
    fs,
    io::{self, BufRead, IsTerminal, Write},
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
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

use clap::Parser;
use cli::Cli;
use config::{ALL_TLDS, is_likely_premium, rdap_url, tld_rank, whois_server};
use model::{Availability, DomainDates, WatchEntry};
use utils::{days_until, parse_date, parse_prose_date};

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

async fn whois_check(name: &str, tld: &str) -> Availability {
    let server = match whois_server(tld) {
        Some(s) => s,
        None    => return Availability::Unknown,
    };
    let addr  = format!("{}:43", server);
    let query = format!("{}.{}\r\n", name, tld);

    // some registries (e.g. whois.registry.co) are slow to accept — give them more time
    let connect_secs = match server {
        "whois.registry.co" => 8,
        _ => 4,
    };

    let mut stream = match tokio::time::timeout(
        Duration::from_secs(connect_secs),
        TcpStream::connect(&addr),
    ).await {
        Ok(Ok(s)) => s,
        _         => return Availability::Unknown,
    };

    // CentralNic (whois.registry.co) sends a banner on connect — drain it before querying
    if server == "whois.registry.co" {
        let mut banner = vec![0u8; 512];
        let _ = tokio::time::timeout(
            Duration::from_millis(300),
            stream.read(&mut banner),
        ).await;
    }

    if stream.write_all(query.as_bytes()).await.is_err() {
        return Availability::Unknown;
    }

    let mut response = String::new();
    let _ = tokio::time::timeout(
        Duration::from_secs(8),
        stream.read_to_string(&mut response),
    ).await;

    parse_whois(&response, tld)
}

fn parse_whois(response: &str, tld: &str) -> Availability {
    let lower = response.to_lowercase();
    // whois.nic.so echoes "Domain Name:" in its not-found reply, so this unambiguous
    // phrase must win over the Taken check below.
    if lower.contains("object does not exist") || lower.contains("no object found") {
        return Availability::Available;
    }
    // check Taken first: CentralNic's .co footer contains the word "available"
    // in boilerplate, which otherwise tripped the Available heuristic.
    if lower.contains("domain name:") || lower.contains("domain:") {
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
    } else if lower.contains("domain is reserved") || lower.contains("domain name is reserved")
        || lower.lines().any(|line| matches!(line.trim(), "status: reserved" | "domain status: reserved" | "status: not available")) {
        Availability::Protected
    } else if lower.contains("no match")
        || lower.contains("not found")
        || lower.contains("no entries found")
        || lower.contains("object does not exist")
        || lower.contains("domain not found")
        || lower.lines().any(|line| matches!(line.trim(), "available" | "status: available" | "domain status: available"))
    {
        Availability::Available
    } else {
        Availability::Unknown
    }
}

async fn dns_check(client: &Client, name: &str, tld: &str) -> Availability {
    let url = format!("https://cloudflare-dns.com/dns-query?name={}.{}&type=NS", name, tld);
    let res = client
        .get(&url)
        .header("Accept", "application/dns-json")
        .timeout(Duration::from_secs(4))
        .send().await;
    match res {
        Ok(r) => {
            let json: serde_json::Value = r.json().await.unwrap_or_default();
            // Status=0 alone isn't enough: some registries (e.g. .fm) return NOERROR
            // with empty Answer for non-existent domains. Require actual NS records.
            let has_ns = json["Answer"].as_array().is_some_and(|a| {
                a.iter().any(|record| record["type"].as_u64() == Some(2))
            });
            match json["Status"].as_i64() {
                Some(0) if has_ns => Availability::Taken(DomainDates::default()),
                _ => Availability::Unknown,
            }
        }
        Err(_) => Availability::Unknown,
    }
}

// None means the server never answered; any HTTP response is Some, even when inconclusive.
async fn http_query(client: &Client, url: &str, sem: &Semaphore) -> Option<Availability> {
    let _permit = sem.acquire().await.unwrap();
    match client.get(url).header("User-Agent", "Mozilla/5.0").header("Accept", "application/json").timeout(Duration::from_secs(5)).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Some(match status {
                200 => {
                    let valid_domain = serde_json::from_str::<serde_json::Value>(&body).ok()
                        .is_some_and(|j| j["objectClassName"].as_str() == Some("domain"));
                    if !valid_domain { return Some(Availability::Unknown); }
                    let dates = serde_json::from_str::<serde_json::Value>(&body).ok()
                        .and_then(|j| j["events"].as_array().cloned())
                        .map(|events| {
                            let find = |keyword: &str| -> Option<String> {
                                events.iter()
                                    .find(|e| e["eventAction"].as_str()
                                        .map(|a| a == keyword)
                                        .unwrap_or(false))
                                    .and_then(|e| e["eventDate"].as_str())
                                    .and_then(parse_date)
                            };
                            DomainDates {
                                registered: find("registration"),
                                updated:    find("last changed"),
                                expires:    events.iter()
                                    .find(|e| e["eventAction"].as_str()
                                        .map(|a| a.contains("expir"))
                                        .unwrap_or(false))
                                    .and_then(|e| e["eventDate"].as_str())
                                    .and_then(parse_date),
                            }
                        })
                        .unwrap_or_default();
                    Availability::Taken(dates)
                }
                404 => {
                    if body.to_ascii_lowercase().contains("blocked") {
                        Availability::Protected
                    } else if serde_json::from_str::<serde_json::Value>(&body).ok()
                        .is_some_and(|j| j["errorCode"].as_u64() == Some(404)) {
                        Availability::Available
                    } else {
                        Availability::Unknown
                    }
                }
                _ => Availability::Unknown,
            })
        }
        Err(_) => None,
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

    let rdap_vs_whois = match (rdap, whois) {
        (Availability::Unknown, whois)                     => whois,
        (Availability::Taken(a), Availability::Taken(b))   => Availability::Taken(merge_dates(a, b)),
        (rdap, _)                                          => rdap,
    };

    match rdap_vs_whois {
        Availability::Unknown => dns,
        other => other,
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

async fn check_domain(client: Client, name: String, tld: &'static str, sem: Arc<Semaphore>) -> (String, Availability) {
    let domain = format!("{}.{}", name, tld);
    if !valid_label(&name) { return (domain, Availability::Unknown); }

    let rdap_fut = async {
        let Some(primary) = rdap_url(&name, tld) else {
            return Availability::Unknown;
        };
        // rdap.org only redirects to the registry, so retry through it only when the
        // registry gave no response; an empty 404 or a 429 would just repeat.
        match http_query(&client, &primary, &sem).await {
            Some(result) => result,
            None => {
                let fallback = format!("https://rdap.org/domain/{}.{}", name, tld);
                if fallback != primary { http_query(&client, &fallback, &sem).await.unwrap_or(Availability::Unknown) }
                else { Availability::Unknown }
            }
        }
    };

    // WHOIS is the slowest source (TCP read can hang up to 8s). Spawn it cancellable
    // and only await if RDAP couldn't give us a confident answer.
    let whois_handle = tokio::spawn({
        let name = name.clone();
        async move { whois_check(&name, tld).await }
    });

    // RDAP "taken" is final under DNS > RDAP > WHOIS precedence, so don't wait on a slow
    // DNS answer (Cloudflare can take ~2s on some names).
    let dns_fut = dns_check(&client, &name, tld);
    tokio::pin!(rdap_fut, dns_fut);
    let mut dns_done = None;
    let rdap_result = tokio::select! {
        rdap = &mut rdap_fut => rdap,
        dns = &mut dns_fut => { dns_done = Some(dns); rdap_fut.await }
    };
    let dns_result = match dns_done {
        Some(dns) => dns,
        None if matches!(rdap_result, Availability::Taken(_)) => Availability::Unknown,
        None => dns_fut.await,
    };

    let whois_result = if matches!(rdap_result, Availability::Unknown) {
        whois_handle.await.unwrap_or(Availability::Unknown)
    } else {
        whois_handle.abort();
        Availability::Unknown
    };

    (domain, merge_results(rdap_result, whois_result, dns_result))
}

fn format_result(domain: &str, availability: &Availability, pad: usize, prices: &pricing::Catalog) -> String {
    let padded = format!("{:<width$}", domain, width = pad);
    match availability {
        Availability::Available   => {
            let price_str = prices.label(domain).truecolor(100, 210, 210).to_string();
            let premium_str = if is_likely_premium(domain) {
                "  ⚠ likely premium".truecolor(220, 170, 60).to_string()
            } else {
                String::new()
            };
            format!("  {}  {}{}{}", "✓".bright_green().bold(), padded.bright_white().bold(), price_str, premium_str)
        }
        Availability::Protected   => format!("  {}  {}  {}", "★".bright_yellow().bold(), padded.truecolor(60, 60, 80), "reserved / blocked".truecolor(80, 80, 100)),
        Availability::Unknown     => format!("  {}  {}", "?".bright_yellow(), padded.truecolor(100, 100, 80)),
        Availability::Taken(dates) => {
            let mut info = String::new();
            if let Some(ref d) = dates.registered { info.push_str(&format!("  reg {}", d)); }
            if let Some(ref d) = dates.updated    { info.push_str(&format!("  upd {}", d)); }
            let exp_str = dates.expires.as_ref().map(|d| {
                let label = format!("  exp {}", d);
                match days_until(d) {
                    Some(n) if n < 90  => label.truecolor(220, 100, 60).to_string(),
                    Some(n) if n < 365 => label.truecolor(200, 170, 60).to_string(),
                    _                  => label.truecolor(110, 100, 150).to_string(),
                }
            });
            let meta = info.truecolor(110, 100, 150).to_string()
                + exp_str.as_deref().unwrap_or("");
            if dates.registered.is_none() && dates.updated.is_none() && dates.expires.is_none() {
                format!("  {}  {}", "✗".truecolor(70, 70, 90), padded.truecolor(60, 60, 80))
            } else {
                format!("  {}  {}{}", "✗".truecolor(70, 70, 90), padded.truecolor(60, 60, 80), meta)
            }
        }
    }
}

fn generate_suggestions(keywords: &[String]) -> Vec<String> {
    let prefixes = ["get", "try", "use", "go", "my", "the", "run", "hey"];
    let suffixes = ["hq", "app", "lab", "hub", "base"];
    let mut names = Vec::new();
    for kw in keywords {
        names.push(kw.clone());
        for p in &prefixes { names.push(format!("{}{}", p, kw)); }
        for s in &suffixes { names.push(format!("{}{}", kw, s)); }
    }
    if keywords.len() >= 2 {
        names.push(keywords.join(""));
        names.push(keywords.join("-"));
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

fn print_price_note() {
    println!("  {}", "Porkbun · USD · standard yearly estimates; premium names and checkout totals may differ.".truecolor(80, 80, 100));
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
    row("+",                 "suggest for last searched name");
    row("/tlds",             "choose extensions for name searches");
    println!();
    println!("  {}", "watchlist".truecolor(80, 80, 100));
    row("/watch <domain>",   "get notified when a domain frees up");
    row("/unwatch <domain>", "stop watching");
    row("/list",             "show watchlist");
    println!();
    println!("  {}", "other".truecolor(80, 80, 100));
    row("/update",           "update dott using its installation method");
    row("/help",             "show this help");
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
    println!("{}", "  private domain search..".truecolor(80, 80, 110));
    println!("{}", "  type a name and hit enter. /help for commands · esc to quit.".truecolor(110, 105, 140));
    println!();
    println!();
}

// read a line with raw mode — handles typing, backspace, enter, esc/ctrl-c
fn read_input(prompt: &str) -> Option<String> {
    let mut buf = String::new();

    print!("{}", prompt);
    io::stdout().flush().unwrap();

    if let Err(error) = enable_raw_mode() {
        eprintln!("dott: Cannot open interactive terminal: {error}");
        return None;
    }

    let result = loop {
        let key = match event::read() {
            Ok(Event::Key(key)) if key.kind != event::KeyEventKind::Release => key,
            Ok(_) => continue,
            Err(error) => { eprintln!("dott: Terminal read failed: {error}"); break None; }
        };
        match key.code {
            KeyCode::Esc => break None,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break None,
            KeyCode::Enter => {
                println!();
                break Some(buf.clone());
            }
            KeyCode::Backspace => {
                if !buf.is_empty() {
                    buf.pop();
                    execute!(io::stdout(), cursor::MoveLeft(1), Clear(ClearType::UntilNewLine)).unwrap();
                }
            }
            KeyCode::Char(c) => {
                buf.push(c);
                print!("{}", c);
                io::stdout().flush().unwrap();
            }
            _ => {}
        }
    };

    let _ = disable_raw_mode();
    result
}

async fn search_and_print(client: &Client, name: &str, tld_list: Vec<&'static str>, plain: bool, cache: Option<&Cache>) {
    // One permit per TLD so the whole set can fly in parallel — no second-batch wait.
    let sem = Arc::new(Semaphore::new(tld_list.len().max(1)));

    if plain {
        let tasks: Vec<_> = tld_list.iter().map(|tld| {
            check_domain_cached(client.clone(), name.to_string(), tld, sem.clone(), cache.cloned())
        }).collect();
        let results = join_all(tasks).await;
        for (domain, av) in &results {
            println!("{} {}", domain, av.as_str());
        }
        return;
    }

    // Pin each TLD to a fixed row (tld_rank order, so .com is always on top) and stream
    // results into their slot as each check completes. Each pending row gets its own
    // animated spinner; finished rows hold their result.
    let mut tlds = tld_list;
    tlds.sort_by_key(|t| tld_rank(t));
    let n = tlds.len();
    let pad = tlds.iter().map(|t| name.len() + 1 + t.len()).max().unwrap_or(0);

    const FRAMES: [&str; 10] = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"];

    println!();
    {
        let mut out = io::stdout();
        for tld in &tlds {
            let domain = format!("{}.{}", name, tld);
            let padded = format!("{:<width$}", domain, width = pad);
            let _ = writeln!(
                out,
                "  {}  {}",
                FRAMES[0].truecolor(160, 120, 220),
                padded.truecolor(80, 80, 100)
            );
        }
        let _ = out.flush();
    }

    let io_lock = Arc::new(std::sync::Mutex::new(()));
    let done: Arc<Vec<AtomicBool>> = Arc::new((0..n).map(|_| AtomicBool::new(false)).collect());
    let spinning = Arc::new(AtomicBool::new(true));

    // Tick task: every 80ms, repaint each still-pending row with the next spinner frame.
    // Skips rows that have flipped done[i], so finished rows never flicker.
    let tick_handle = {
        let spinning = spinning.clone();
        let done = done.clone();
        let io_lock = io_lock.clone();
        let tlds_t = tlds.clone();
        let name_t = name.to_string();
        tokio::spawn(async move {
            let mut frame = 0usize;
            while spinning.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(80)).await;
                frame = frame.wrapping_add(1);
                let _g = io_lock.lock().unwrap();
                let mut out = io::stdout();
                for (i, d) in done.iter().enumerate() {
                    if d.load(Ordering::Relaxed) { continue; }
                    let up = (n - i) as u16;
                    let domain = format!("{}.{}", name_t, tlds_t[i]);
                    let padded = format!("{:<width$}", domain, width = pad);
                    let _ = execute!(
                        out,
                        cursor::MoveUp(up),
                        cursor::MoveToColumn(0),
                        Clear(ClearType::CurrentLine),
                    );
                    let _ = write!(
                        out,
                        "  {}  {}",
                        FRAMES[frame % FRAMES.len()].truecolor(160, 120, 220),
                        padded.truecolor(80, 80, 100)
                    );
                    let _ = execute!(out, cursor::MoveToNextLine(up));
                }
                let _ = out.flush();
            }
        })
    };

    let price_client = client.clone();
    let prices = async move { pricing::load(&price_client).await }.boxed().shared();
    let task_handles: Vec<_> = tlds.iter().enumerate().map(|(i, tld)| {
        let tld = *tld;
        let client = client.clone();
        let name_s = name.to_string();
        let sem = sem.clone();
        let cache = cache.cloned();
        let io_lock = io_lock.clone();
        let done = done.clone();
        let prices = prices.clone();
        tokio::spawn(async move {
            let ((domain, av), prices) = tokio::join!(
                check_domain_cached(client, name_s, tld, sem, cache), prices
            );
            let final_line = format_result(&domain, &av, pad, &prices);
            {
                let _g = io_lock.lock().unwrap();
                let mut out = io::stdout();
                let up = (n - i) as u16;
                let _ = execute!(
                    out,
                    cursor::MoveUp(up),
                    cursor::MoveToColumn(0),
                    Clear(ClearType::CurrentLine),
                );
                let _ = write!(out, "{}", final_line);
                let _ = execute!(out, cursor::MoveToNextLine(up));
                let _ = out.flush();
                done[i].store(true, Ordering::Relaxed);
            }
            (domain, av)
        })
    }).collect();

    let mut results: Vec<(String, Availability)> = Vec::with_capacity(n);
    for h in task_handles {
        if let Ok(r) = h.await { results.push(r); }
    }

    spinning.store(false, Ordering::Relaxed);
    let _ = tick_handle.await;

    let available_count = results.iter()
        .filter(|(_, a)| matches!(a, Availability::Available))
        .count();

    println!();
    println!(
        "  {} available  ·  {} checked",
        available_count.to_string().bright_green().bold(),
        n.to_string().truecolor(80, 80, 100),
    );
    if available_count > 0 { print_price_note(); }
    println!("{}", "  ─────────────────────────────────────────────────────".truecolor(38, 36, 52));
    println!(
        "  {}  {}    {}  {}    {}  {}    {}  {}",
        "✓".bright_green(),        "available".truecolor(70, 70, 90),
        "?".bright_yellow(),       "unknown".truecolor(70, 70, 90),
        "✗".truecolor(70, 70, 90), "taken".truecolor(70, 70, 90),
        "esc".truecolor(100, 95, 130), "quit".truecolor(70, 70, 90),
    );
    println!("{}", "  ─────────────────────────────────────────────────────".truecolor(38, 36, 52));
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

// Brew's stable link survives upgrades, which remove versioned Cellar directories.
fn stable_binary() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().and_then(fs::canonicalize).map_err(|e| e.to_string())?;
    Ok(if update::installed_via_brew(&exe) {
        exe.ancestors().find(|p| p.file_name().is_some_and(|n| n == "Cellar"))
            .and_then(|p| p.parent()).map(|p| p.join("bin/dott")).unwrap_or(exe)
    } else { exe })
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
    // otherwise it's stale (binary moved, `brew upgrade`, `cargo install` from a new path) — unload and rewrite.
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
    #[cfg(target_os = "macos")]
    if let Some(args) = &cli.notify {
        finish_command(notify::deliver(&args[0], &args[1]));
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
            search_and_print(&client, &name, tlds, true, None).await;
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
        let sem = Arc::new(Semaphore::new(10));
        let tasks: Vec<_> = suggestions.iter().flat_map(|name| {
            let name = name.clone(); let client = client.clone(); let sem = sem.clone();
            tlds.iter().map(move |tld| check_domain(client.clone(), name.clone(), tld, sem.clone()))
        }).collect();
        let (results, prices) = tokio::join!(join_all(tasks), async {
            if plain { None } else { Some(pricing::load(&client).await) }
        });
        let available: Vec<&str> = results.iter()
            .filter(|(_, a)| matches!(a, Availability::Available))
            .map(|(d, _)| d.as_str()).collect();
        if plain {
            for (domain, av) in &results {
                println!("{} {}", domain, av.as_str());
            }
        } else if available.is_empty() {
            println!("  {} nothing available\n", "✗".truecolor(80, 80, 100));
        } else {
            let prices = prices.as_ref().expect("Terminal output has a pricing catalog");
            for d in &available { println!("{}", format_result(d, &Availability::Available, 0, prices)); }
            print_price_note();
            println!("\n  {} available\n", available.len().to_string().bright_green().bold());
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
        search_and_print(&client, &name, tld_list, plain, None).await;
        if let Some(h) = update_check.take() { print_update(h).await; }
        return;
    }

    // ── interactive mode ───────────────────────────────────────
    print_cat();
    show_notices();
    std::thread::spawn(|| prepare_notifier(true));
    println!("{}\n", extensions::summary(active_tlds.as_deref()));
    warm_up(&client, active_tlds.as_deref().unwrap_or(ALL_TLDS));
    tokio::spawn({
        let client = client.clone();
        async move { pricing::load(&client).await; }
    });

    let cache = new_cache();
    let mut last_name: Option<String> = None;

    loop {
        let prompt = format!("  {} ", "›".bright_magenta().bold());
        match read_input(&prompt) {
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

                // 'name+' → suggest ; bare '+' reuses the last searched name
                if let Some(raw) = input.strip_suffix('+') {
                    let name = if raw.is_empty() {
                        match last_name.clone() {
                            Some(n) => n,
                            None => {
                                println!("  {}\n", "search for a name first".truecolor(100, 100, 120));
                                continue;
                            }
                        }
                    } else {
                        match parse_search(raw) {
                            Ok((name, _)) => name,
                            Err(error) => { eprintln!("dott: {error}"); continue; }
                        }
                    };
                    println!("  {} {}", "suggesting for:".truecolor(80, 80, 100), name.bright_white());
                    let suggestions = generate_suggestions(std::slice::from_ref(&name));
                    let tlds = active_tlds.clone().unwrap_or_else(|| vec!["com", "io", "dev", "app", "co"]);
                    let sem = Arc::new(Semaphore::new(10));
                    let tasks: Vec<_> = suggestions.iter().flat_map(|n| {
                        let n = n.clone();
                        let client = client.clone();
                        let sem = sem.clone();
                        let cache = cache.clone();
                        tlds.iter().map(move |tld| check_domain_cached(client.clone(), n.clone(), tld, sem.clone(), Some(cache.clone())))
                    }).collect();
                    let (results, prices) = tokio::join!(join_all(tasks), pricing::load(&client));
                    let available: Vec<&str> = results.iter()
                        .filter(|(_, a)| matches!(a, Availability::Available))
                        .map(|(d, _)| d.as_str())
                        .collect();
                    println!();
                    if available.is_empty() {
                        println!("  {}  nothing available\n", "✗".truecolor(80, 80, 100));
                    } else {
                        for d in &available {
                            println!("{}", format_result(d, &Availability::Available, 0, &prices));
                        }
                        println!();
                        print_price_note();
                        println!("  {} available\n", available.len().to_string().bright_green().bold());
                    }
                    try_print_update_if_ready(&mut update_check).await;
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
                            println!("{}\n", extensions::summary(active_tlds.as_deref()));
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

                let (name, explicit_tld) = match parse_search(&input) {
                    Ok(search) => search,
                    Err(error) => { eprintln!("dott: {error}"); continue; }
                };
                let tlds = search_tlds(explicit_tld, active_tlds.as_deref());
                search_and_print(&client, &name, tlds, false, Some(&cache)).await;
                last_name = Some(name);

                println!();
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

    #[test]
    fn full_domains_and_tld_lists_are_normalized_and_validated() {
        assert_eq!(parse_search(" MyName.IO ").unwrap(), ("myname".into(), Some("io")));
        assert_eq!(parse_search("MyName").unwrap(), ("myname".into(), None));
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

    #[test]
    fn whois_boilerplate_does_not_mean_available_or_reserved() {
        assert!(matches!(parse_whois("WHOIS service not available", "com"), Availability::Unknown));
        assert!(matches!(parse_whois("No match for example.com\nAll rights reserved", "com"), Availability::Available));
        assert!(matches!(parse_whois("Status: reserved", "com"), Availability::Protected));
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
    fn watch_notifications_retry_failures_and_ignore_inconclusive_results() {
        let mut entry = WatchEntry { domain: "example.com".into(), last_status: "taken".into() };
        assert!(!refresh_watch_entry(&mut entry, &Availability::Unknown, |_, _| panic!("unknown must not notify")).unwrap());
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
        assert!(!refresh_watch_entry(&mut entry, &Availability::Unknown, |_, _| panic!("outage must not notify")).unwrap());
        assert!(!refresh_watch_entry(&mut entry, &Availability::Available, |_, _| panic!("must not notify twice")).unwrap());
        assert!(refresh_watch_entry(&mut entry, &Availability::Protected, |_, _| panic!("protected must not notify")).unwrap());
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
            let (mut connection, _) = listener.accept().unwrap();
            connection.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut request = [0; 1024];
            connection.read(&mut request).unwrap();
            connection.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").unwrap();
        });
        let result = http_query(&Client::builder().no_proxy().build().unwrap(), &url, &Semaphore::new(1)).await;
        server.join().unwrap();
        assert!(matches!(result, Some(Availability::Unknown)), "a response must not trigger the rdap.org retry");
    }

    #[tokio::test]
    async fn only_unreachable_rdap_servers_are_retried() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/domain/example.com", listener.local_addr().unwrap());
        drop(listener);
        let result = http_query(&Client::builder().no_proxy().build().unwrap(), &url, &Semaphore::new(1)).await;
        assert!(result.is_none());
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
            Availability::Unknown,
            Availability::Unknown,
            Availability::Taken(DomainDates::default()),
        );
        assert!(matches!(out, Availability::Taken(_)));
    }

    #[test]
    fn dns_taken_keeps_whois_expiry() {
        let out = merge_results(
            Availability::Unknown,
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
            Availability::Unknown,
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
        assert!(all.iter().all(|o| o.ends_with(".com/") || o.ends_with(".org/") || o.ends_with(".services/")
            || o.ends_with(".google/") || o.ends_with(".cv/") || o.ends_with(".uk/")), "{all:?}");
        assert!(all.iter().all(|o| !o.contains("domain")));
    }

    #[test]
    fn rdap_taken_does_not_depend_on_dns() {
        // check_domain skips waiting for DNS once RDAP says taken; the merge must agree.
        let rdap = || Availability::Taken(dates_with_expiry("2027-01-01"));
        for dns in [Availability::Taken(DomainDates::default()), Availability::Unknown] {
            match merge_results(rdap(), Availability::Unknown, dns) {
                Availability::Taken(d) => assert_eq!(d.expires.as_deref(), Some("2027-01-01")),
                _ => panic!("expected Taken with RDAP dates"),
            }
        }
    }

    #[test]
    fn rdap_available_beats_everything() {
        let out = merge_results(
            Availability::Available,
            Availability::Taken(DomainDates::default()),
            Availability::Unknown,
        );
        assert!(matches!(out, Availability::Available));
    }

    #[test]
    fn whois_fallback_when_rdap_unknown() {
        let out = merge_results(
            Availability::Unknown,
            Availability::Taken(dates_with_expiry("2027-01-01")),
            Availability::Unknown,
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
    }

    #[test]
    fn premium_heuristic_ignores_long_names_and_other_tlds() {
        assert!(!is_likely_premium("mystartup.ai"));   // too long
        assert!(!is_likely_premium("go.com"));          // not a flagged TLD
        assert!(!is_likely_premium("go.xyz"));          // not a flagged TLD
        assert!(!is_likely_premium("noseparator"));     // no TLD
    }

    #[test]
    fn all_unknown_stays_unknown() {
        let out = merge_results(Availability::Unknown, Availability::Unknown, Availability::Unknown);
        assert!(matches!(out, Availability::Unknown));
    }
}
