// Read endpoint metadata directly from the project's source of truth.
#[allow(dead_code)]
#[path = "../src/config.rs"]
mod config;

fn main() {
    for tld in config::ALL_TLDS {
        println!("{}\t{}\t{}\t{}", tld,
            config::rdap_url("AUDIT_LABEL", tld).unwrap_or_default(),
            config::whois_server(tld).unwrap_or(""),
            config::dpml_url("AUDIT_LABEL", tld).unwrap_or_default());
    }
}
