pub const ALL_TLDS: &[&str] = &[
    "com", "net", "org", "io", "dev", "app", "co", "ai", "me", "so", "gg", "cc", "cv", "xyz",
    "live", "computer", "sh", "fm", "fyi", "work", "bot",
];

pub fn tld_rank(domain: &str) -> u8 {
    let tld = domain.rsplit('.').next().unwrap_or("");
    match tld {
        "com" => 0,
        "io" => 1,
        "dev" => 2,
        "ai" => 3,
        "app" => 4,
        "co" => 5,
        "net" => 6,
        "org" => 7,
        "me" => 8,
        "so" => 9,
        "gg" => 10,
        "cc" => 11,
        "xyz" => 12,
        "cv" => 13,
        "live" => 14,
        "computer" => 15,
        "sh" => 16,
        "fm" => 17,
        "fyi" => 18,
        "work" => 19,
        "bot" => 20,
        _ => 99,
    }
}

// short names in these TLDs are almost always registrar-priced as premium (e.g. go.ai = $20k+).
// heuristic only — RDAP/WHOIS will still say "available", but checkout will hit the user with a surprise.
pub fn is_likely_premium(domain: &str) -> bool {
    let Some((name, tld)) = domain.rsplit_once('.') else {
        return false;
    };
    name.len() <= 4 && matches!(tld, "ai" | "io" | "app" | "dev" | "co" | "cv")
}

pub fn rdap_url(name: &str, tld: &str) -> Option<String> {
    match tld {
        "com" => Some(format!("https://rdap.verisign.com/com/v1/domain/{}.{}", name, tld)),
        "net" => Some(format!("https://rdap.verisign.com/net/v1/domain/{}.{}", name, tld)),
        "org" => Some(format!(
            "https://rdap.publicinterestregistry.org/rdap/domain/{}.{}",
            name, tld
        )),
        "io" | "ai" | "me" | "live" | "computer" | "fyi" | "work" => Some(format!(
            "https://rdap.identitydigital.services/rdap/domain/{}.{}",
            name, tld
        )),
        "dev" | "app" => Some(format!("https://pubapi.registry.google/rdap/domain/{}.{}", name, tld)),
        "cc" => Some(format!("https://tld-rdap.verisign.com/cc/v1/domain/{}.{}", name, tld)),
        "xyz" | "fm" => Some(format!("https://rdap.centralnic.com/{}/domain/{}.{}", tld, name, tld)),
        "cv" => Some(format!("https://rdap.nic.cv/domain/{}.{}", name, tld)),
        "bot" => Some(format!("https://rdap.nominet.uk/bot/domain/{}.{}", name, tld)),
        "so" => Some(format!("https://rdap.nic.so/domain/{}.{}", name, tld)),
        // No working RDAP: rdap.org has no service for these, and CentralNic's .co RDAP
        // answers 404 even for registered names. WHOIS only.
        "sh" | "gg" | "co" => None,
        _ => Some(format!("https://rdap.org/domain/{}.{}", name, tld)),
    }
}

pub fn whois_server(tld: &str) -> Option<&'static str> {
    match tld {
        // only list servers confirmed working — dead servers cause 4s timeouts
        "com" => Some("whois.verisign-grs.com"),
        "net" => Some("whois.verisign-grs.com"),
        "org" => Some("whois.pir.org"),
        "io" => Some("whois.nic.io"),
        "co" => Some("whois.registry.co"),
        "ai" => Some("whois.nic.ai"),
        "me" => Some("whois.nic.me"),
        "so" => Some("whois.nic.so"),
        "cc" => Some("whois.nic.cc"),
        "xyz" => Some("whois.nic.xyz"),
        "gg" => Some("whois.gg"),
        "sh" => Some("whois.nic.sh"),
        "fm" => Some("whois.nic.fm"),
        _ => None,
    }
}
