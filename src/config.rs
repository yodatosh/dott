// Source of truth for supported extensions. Most additions need one Iana row.
#[path = "rdap_bootstrap.rs"]
mod bootstrap;

#[derive(Clone, Copy)]
enum Rdap { Iana, Direct(&'static str), WhoisOnly }
#[derive(Clone, Copy)]
enum Whois { None, Standard(&'static str), Banner(&'static str) }

struct Registry {
    tld: &'static str,
    rank: u8,
    rdap: Rdap,
    whois: Whois,
    dpml: bool,
}

macro_rules! registry_catalog {
    ($(($tld:literal, $rank:literal, $rdap:expr, $whois:expr, $dpml:literal)),* $(,)?) => {
        pub const ALL_TLDS: &[&str] = &[$($tld),*];
        const REGISTRIES: &[Registry] = &[$(Registry {
            tld: $tld, rank: $rank, rdap: $rdap, whois: $whois, dpml: $dpml,
        }),*];
    };
}

use Rdap::{Direct, Iana, WhoisOnly};
use Whois::{Banner, Standard};

// TLD, display rank, RDAP policy, optional WHOIS fallback, DPML coverage.
// IANA omissions and broken services use explicit, audited overrides.
registry_catalog! {
    ("com", 0, Iana, Standard("whois.verisign-grs.com"), false),
    ("net", 6, Iana, Standard("whois.verisign-grs.com"), false),
    ("org", 7, Iana, Standard("whois.pir.org"), false),
    ("io", 1, Direct("https://rdap.identitydigital.services/rdap/"), Standard("whois.nic.io"), false),
    ("dev", 2, Iana, Whois::None, false),
    ("app", 4, Iana, Whois::None, false),
    ("co", 5, WhoisOnly, Banner("whois.registry.co"), false),
    ("ai", 3, Iana, Standard("whois.nic.ai"), false),
    ("me", 8, Direct("https://rdap.identitydigital.services/rdap/"), Standard("whois.nic.me"), false),
    ("so", 9, Direct("https://rdap.nic.so/"), Standard("whois.nic.so"), false),
    ("gg", 10, WhoisOnly, Standard("whois.gg"), false),
    ("cc", 11, Iana, Standard("whois.nic.cc"), false),
    ("cv", 13, Iana, Whois::None, false),
    ("xyz", 12, Iana, Standard("whois.nic.xyz"), false),
    ("live", 14, Iana, Whois::None, true),
    ("computer", 15, Iana, Whois::None, true),
    ("sh", 16, WhoisOnly, Standard("whois.nic.sh"), false),
    ("fm", 17, Iana, Standard("whois.nic.fm"), false),
    ("fyi", 18, Iana, Whois::None, true),
    ("work", 19, Iana, Whois::None, false),
    ("bot", 20, Iana, Whois::None, false),
    ("si", 21, Iana, Standard("whois.register.si"), false),
    ("click", 22, Iana, Standard("whois.registry.click"), false),
    ("fun", 23, Iana, Standard("whois.nic.fun"), false),
    ("gy", 24, Iana, Whois::None, false),
    ("ly", 25, Iana, Whois::None, false),
    ("to", 26, Iana, Whois::None, false),
    ("is", 27, Iana, Whois::None, false),
    ("tv", 28, Iana, Whois::None, false),
    ("in", 29, Iana, Whois::None, false),
    ("id", 30, Iana, Whois::None, false),
    ("fr", 31, Iana, Whois::None, false),
    ("pt", 32, Iana, Standard("whois.dns.pt"), false),
}

fn registry(tld: &str) -> Option<&'static Registry> {
    REGISTRIES.iter().find(|registry| registry.tld == tld)
}

pub fn tld_rank(domain: &str) -> u8 {
    registry(domain.rsplit('.').next().unwrap_or("")).map_or(99, |r| r.rank)
}

// Heuristic only: public registration data cannot establish checkout pricing.
pub fn is_likely_premium(domain: &str) -> bool {
    let Some((name, tld)) = domain.rsplit_once('.') else { return false; };
    match tld {
        // .ME's registry lists one/two-character names and selected short
        // abbreviations as premium. Length is a warning, not confirmation.
        // https://domain.me/almost-3000-premium-me-domains-open-for-registration-at-afternic/
        "me" => !name.is_empty() && name.len() <= 3,
        _ => name.len() <= 4 && matches!(tld, "ai" | "io" | "app" | "dev" | "co" | "cv"),
    }
}

pub fn rdap_url(name: &str, tld: &str) -> Option<String> {
    let base = match registry(tld)?.rdap {
        Iana => bootstrap::base_url(tld)?,
        Direct(base) => base,
        WhoisOnly => return None,
    };
    Some(format!("{}/domain/{name}.{tld}", base.trim_end_matches('/')))
}

pub fn dpml_url(name: &str, tld: &str) -> Option<String> {
    registry(tld)?.dpml.then(|| format!("https://rdap.identitydigital.services/rdap/domain/{name}.dpml.zone"))
}

pub fn whois_server(tld: &str) -> Option<&'static str> {
    match registry(tld)?.whois {
        Standard(server) | Banner(server) => Some(server),
        Whois::None => None,
    }
}

pub fn whois_needs_banner(tld: &str) -> bool {
    registry(tld).is_some_and(|r| matches!(r.whois, Banner(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_unique_ranks_and_usable_registry_routes() {
        let mut tlds = std::collections::HashSet::new();
        let mut ranks = std::collections::HashSet::new();
        for r in REGISTRIES {
            assert!(tlds.insert(r.tld), "duplicate TLD {}", r.tld);
            assert!(ranks.insert(r.rank), "duplicate rank {}", r.rank);
            assert!(rdap_url("example", r.tld).is_some() || whois_server(r.tld).is_some(), "no registry route for {}", r.tld);
            assert_eq!(tld_rank(&format!("example.{}", r.tld)), r.rank);
        }
        assert_eq!(ALL_TLDS.len(), tlds.len());
        assert_eq!(rdap_url("example", "not-supported"), None);
        assert!(!whois_needs_banner("com"));
        assert!(whois_needs_banner("co"));
    }

    #[test]
    fn directory_keeps_registry_paths_and_does_not_enable_unlisted_tlds() {
        assert_eq!(rdap_url("pha", "gy").as_deref(), Some("https://rdap.registry.gy/domain/pha.gy"));
        assert_eq!(rdap_url("go", "to").as_deref(), Some("https://rdap.tonicregistry.to/rdap/domain/go.to"));
        assert!(bootstrap::base_url("zip").is_some());
        assert_eq!(rdap_url("example", "zip"), None);
        let mut seen = std::collections::HashSet::new();
        for (tlds, base) in bootstrap::SERVICES {
            assert!(base.starts_with("https://") || base.starts_with("http://"));
            assert!(base.ends_with('/'));
            for tld in *tlds { assert!(seen.insert(tld)); }
        }
    }
}
