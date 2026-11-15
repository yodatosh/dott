//! Offline regression checks against sanitized registry observations.
use super::*;
use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_str(include_str!("../Tests/fixtures/registry_audit.json")).unwrap()
}

fn rdap(reply: &Value, domain: &str) -> Availability {
    let body = reply.get("body").map(Value::to_string).unwrap_or_default();
    parse_rdap_response(reply["http"].as_u64().unwrap_or(0) as u16, &body, false, Some(domain))
}

#[test]
fn captured_replies_cover_every_supported_tld() {
    let fixtures = fixture();
    let targets = fixtures["targets"].as_array().unwrap();
    let covered: std::collections::HashSet<_> = targets.iter().map(|target| target["tld"].as_str().unwrap()).collect();
    assert_eq!(covered, ALL_TLDS.iter().copied().collect());
    for target in targets {
        let tld = target["tld"].as_str().unwrap();
        assert_eq!(rdap_url("AUDIT_LABEL", tld).unwrap_or_default(), target["rdap"].as_str().unwrap(), "audited route changed for {tld}");
        assert_eq!(target["samples"].as_array().unwrap().len(), 2);
        for sample in target["samples"].as_array().unwrap() {
            let domain = sample["domain"].as_str().unwrap();
            let registry = if sample.get("rdap").is_some() {
                let result = rdap(&sample["rdap"], domain);
                assert_eq!(result.as_str(), sample["rdap_expected"].as_str().unwrap(), "RDAP {domain}");
                result
            } else { Availability::Unknown(UnknownReason::NoRegistryService) };
            let whois = if let Some(reply) = sample.get("whois") {
                let result = parse_whois_for(reply["body"].as_str().unwrap(), tld, Some(domain));
                assert_eq!(result.as_str(), sample["whois_expected"].as_str().unwrap(), "WHOIS {domain}");
                result
            } else { Availability::Unknown(UnknownReason::NoRegistryService) };
            let dns = parse_dns_response(&sample["dns"]["body"], domain);
            assert_eq!(dns.as_str(), sample["dns_expected"].as_str().unwrap(), "DNS {domain}");
            // Ensure a valid registration remains taken even if DNS fails later.
            if sample["kind"] == "registry_reference" {
                let result = merge_results(registry.clone(), whois.clone(), Availability::Unknown(UnknownReason::Inconclusive));
                assert_eq!(result.as_str(), "taken", "registration without DNS: {domain}");
            }
            let result = merge_results(registry, whois, dns);
            assert_eq!(result.as_str(), sample["expected"].as_str().unwrap(), "merged {domain}");
        }
    }
}

#[test]
fn live_registered_dns_failure_and_explicit_registry_blocks_are_preserved() {
    let fixtures = fixture();
    for sample in fixtures["extra_references"].as_array().unwrap() {
        let domain = sample["domain"].as_str().unwrap();
        let dns = parse_dns_response(&sample["dns"]["body"], domain);
        assert_eq!(dns.as_str(), sample["dns_expected"].as_str().unwrap(), "DNS {domain}");
        let result = merge_results(rdap(&sample["rdap"], domain), Availability::Unknown(UnknownReason::NoRegistryService), dns);
        assert_eq!(result.as_str(), sample["expected"].as_str().unwrap(), "{domain}");
    }
    let protected = &fixtures["protection"];
    let record = serde_json::to_vec(&protected["body"]).unwrap();
    assert!(matches!(protection::parse(&record, 200, "apple.dpml.zone"), Availability::Protected(ProtectionReason::Trademark)));
    let clear = &fixtures["protection_clear"];
    assert!(matches!(protection::parse(&serde_json::to_vec(&clear["body"]).unwrap(), 404,
        &format!("{}.dpml.zone", fixtures["probe"].as_str().unwrap())), Availability::Available));
}

#[test]
fn rdap_must_match_the_queried_domain_and_reject_malformed_negative_replies() {
    for body in [
        json!({"objectClassName":"domain"}),
        json!({"objectClassName":"domain","ldhName":"other.com"}),
        json!({"objectClassName":"domain","ldhName":"example.com","errorCode":404}),
        json!({"errorCode":404,"objectClassName":"domain","ldhName":"example.com"}),
        Value::Null,
    ] {
        let status = if body.get("errorCode").is_some() { 404 } else { 200 };
        assert!(matches!(parse_rdap_response(status, &body.to_string(), false, Some("example.com")), Availability::Unknown(_)));
    }
    for body in ["", "<html>404 Not Found</html>", "{\"errorCode\":"] {
        assert!(matches!(parse_rdap_response(404, body, false, Some("example.com")), Availability::Unknown(_)));
    }
    let no_service = r#"{"errorCode":404,"title":"No RDAP service is available for this resource"}"#;
    assert!(matches!(parse_rdap_response(404, no_service, false, Some("example.com")), Availability::Unknown(UnknownReason::NoRegistryService)));
}

#[test]
fn rdap_reservation_notices_are_separate_from_boilerplate_and_domain_spelling() {
    for body in [
        json!({"errorCode":404,"title":"Not Found","description":["example.dev blocked by BSA"]}),
        json!({"errorCode":404,"title":"Domain name blocked"}),
        json!({"errorCode":404,"description":["This domain name is reserved"]}),
    ] {
        assert!(matches!(parse_rdap_response(404, &body.to_string(), false, Some("example.dev")), Availability::Protected(_)));
    }
    let missing = json!({"errorCode":404,"title":"Domain 'blocked.dev' not found",
        "notices":[{"description":["Service may be blocked if rate limits are exceeded"]}]});
    assert!(matches!(parse_rdap_response(404, &missing.to_string(), false, Some("blocked.dev")), Availability::Available));
}

#[test]
fn whois_errors_mismatched_records_and_boilerplate_never_mean_available() {
    for tld in ALL_TLDS {
        let domain = format!("example.{tld}");
        for body in ["WHOIS server not found", "Database not found", "No matching server found",
            "Documentation: if the object does not exist, try again", "Footer: no match means available",
            "Domain Name:", "Error: domain not found", "Service temporarily unavailable"] {
            assert!(matches!(parse_whois_for(body, tld, Some(&domain)), Availability::Unknown(_)), "{tld}: {body}");
        }
        assert!(matches!(parse_whois_for(&format!("Domain Name: other.{tld}"), tld, Some(&domain)), Availability::Unknown(_)));
        assert!(matches!(parse_whois_for(&format!("No match for other.{tld}"), tld, Some(&domain)), Availability::Unknown(_)));
    }
    let contradictory = "Domain Name: example.so\nRegistry Domain ID: 123\nThe queried object does not exist: No Object Found";
    assert!(matches!(parse_whois_for(contradictory, "so", Some("example.so")), Availability::Unknown(_)));
}

#[test]
fn dns_requires_a_valid_ns_record_for_the_requested_owner() {
    for body in [
        json!({"Status":0}),
        json!({"Status":3,"Answer":[{"type":2,"name":"example.com","data":"ns.example.net"}]}),
        json!({"Status":0,"Answer":[{"type":2,"name":"other.com","data":"ns.example.net"}]}),
        json!({"Status":0,"Answer":[{"type":2,"name":"example.com"}]}),
        json!({"Status":0,"Answer":[{"type":2,"name":"example.com","data":"bad name"}]}),
        json!({"Status":0,"Answer":[{"type":5,"name":"example.com","data":"other.com"}]}),
    ] { assert!(matches!(parse_dns_response(&body, "example.com"), Availability::Unknown(_))); }
    let valid = json!({"Status":0,"Answer":[{"type":2,"name":"EXAMPLE.COM.","data":"ns.example.net."}]});
    assert!(matches!(parse_dns_response(&valid, "example.com"), Availability::Taken(_)));
}

#[tokio::test]
async fn negative_rdap_waits_for_positive_whois_even_without_dns() {
    use futures::FutureExt;
    let (release, held) = tokio::sync::oneshot::channel();
    let whois = WhoisTask(tokio::spawn(async { held.await.unwrap(); Availability::Taken(DomainDates::default()) }));
    let result = resolve_sources(std::future::ready(Availability::Available),
        std::future::ready(Availability::Unknown(UnknownReason::Inconclusive)), whois);
    tokio::pin!(result);
    assert!((&mut result).now_or_never().is_none(), "a negative RDAP reply must not cancel pending WHOIS evidence");
    release.send(()).unwrap();
    assert!(matches!(result.await, Availability::Taken(_)));
    let result = merge_results(Availability::Available, Availability::Protected(ProtectionReason::Reserved), Availability::Unknown(UnknownReason::Inconclusive));
    assert!(matches!(result, Availability::Protected(_)));
}

#[tokio::test]
async fn positive_rdap_still_returns_without_waiting_for_dns_or_whois() {
    let whois = WhoisTask(tokio::spawn(std::future::pending()));
    let result = resolve_sources(std::future::ready(Availability::Taken(DomainDates::default())), std::future::pending(), whois);
    assert!(matches!(tokio::time::timeout(Duration::from_secs(1), result).await.unwrap(), Availability::Taken(_)));
}

// Exercises transport validation, not just the response parsers, using a local
// server and the exact request headers used by production lookups.
fn response(status: &'static str, body: String, accept_header: &'static str) -> (String, std::thread::JoinHandle<()>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/domain/example.com", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => { stream.set_nonblocking(false).unwrap(); break stream }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock && std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
                Err(error) => panic!("audit mock: {error}"),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut request = [0; 4096];
        let size = stream.read(&mut request).unwrap();
        let request = std::str::from_utf8(&request[..size]).unwrap().to_ascii_lowercase();
        assert!(request.contains(accept_header));
        // Oversized-response tests intentionally stop reading and close early.
        let _ = write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    });
    (url, server)
}

#[tokio::test]
async fn dns_http_errors_never_turn_a_response_body_into_registration_evidence() {
    let client = Client::builder().no_proxy().build().unwrap();
    for (status, expected) in [("200 OK", "taken"), ("429 Too Many Requests", "unknown"), ("503 Unavailable", "unknown")] {
        let body = json!({"Status":0,"Answer":[{"type":2,"name":"example.com","data":"ns.example.net"}]}).to_string();
        let (url, server) = response(status, body, "accept: application/dns-json");
        assert_eq!(dns_query(&client, &url, "example.com").await.as_str(), expected);
        server.join().unwrap();
    }
}

#[tokio::test]
async fn rdap_rejects_wrong_domain_and_oversized_responses_over_http() {
    let client = Client::builder().no_proxy().build().unwrap();
    for body in [json!({"objectClassName":"domain","ldhName":"other.com"}).to_string(),
        format!("{{\"errorCode\":404,\"description\":[\"{}\"]}}", "x".repeat(2_000_000))] {
        let status = if body.contains("errorCode") { "404 Not Found" } else { "200 OK" };
        let (url, server) = response(status, body, "accept: application/json");
        assert!(matches!(http_query(&client, &url, &Semaphore::new(1)).await, Ok(Availability::Unknown(UnknownReason::InvalidResponse))));
        server.join().unwrap();
    }
}
