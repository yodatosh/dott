"""Explicit live registry audit. Saves sanitized replies; never runs in unit tests."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
LOCKS = {}
LOCKS_GUARD = threading.Lock()


def host_lock(host):
    with LOCKS_GUARD:
        return LOCKS.setdefault(host, threading.Lock())


def http(url):
    with host_lock(urlsplit(url).hostname):
        accept = 'application/dns-json' if urlsplit(url).hostname == 'cloudflare-dns.com' else 'application/rdap+json'
        result = subprocess.run(['curl', '-LsS', '--max-time', '12', '--max-filesize', '1048576',
                                 '-H', f'Accept: {accept}',
                                 '-w', '\n%{http_code}\n%{url_effective}', url],
                                capture_output=True, text=True, timeout=15)
        time.sleep(0.25)
    parts = result.stdout.rsplit('\n', 2)
    response = {'url': url, 'http': int(parts[-2] or 0) if len(parts) == 3 else 0}
    if len(parts) == 3:
        response['final_url'] = parts[-1]
    if result.returncode:
        response['error'] = result.stderr.strip()
    try:
        data = json.loads(parts[0])
        # Keep registry evidence, not personal contacts, entities, or legal boilerplate.
        response['body'] = {key: data[key] for key in ['objectClassName', 'ldhName', 'unicodeName',
            'status', 'events', 'errorCode', 'title', 'description', 'Status', 'Answer', 'Authority'] if key in data}
        if 'nameservers' in data:
            response['body']['nameservers'] = [{'ldhName': ns.get('ldhName')} for ns in data['nameservers'] if isinstance(ns, dict)]
    except (ValueError, IndexError):
        response['invalid_json'] = True
    return response


def whois(server, domain):
    try:
        with host_lock(server):
            with socket.create_connection((server, 43), timeout=4) as stream:
                stream.settimeout(6)
                if server == 'whois.registry.co':
                    stream.settimeout(0.3)
                    try:
                        stream.recv(512)
                    except socket.timeout:
                        pass
                    stream.settimeout(6)
                stream.sendall((domain + '\r\n').encode())
                chunks = []
                while True:
                    data = stream.recv(65536)
                    if not data:
                        break
                    chunks.append(data)
                    if sum(map(len, chunks)) > 262144:
                        raise ValueError('response too large')
            time.sleep(0.25)
        text = b''.join(chunks).decode('utf-8')
        kept = []
        prefixes = ('domain:', 'domain name:', 'registry domain id:', 'domain status:', 'status:',
                    'creation date:', 'created:', 'registered:', 'registered on', 'registered until',
                    'updated date:', 'registry expiry date:', 'expiry date:', 'expiration date:',
                    'expire:', 'expires:', 'paid-till:', 'last modified:')
        lines = text.splitlines()
        for index, line in enumerate(lines):
            lower = line.strip().lower()
            if lower.startswith(prefixes):
                kept.append(line)
                if lower in ('domain:', 'domain status:') and index + 1 < len(lines):
                    kept.append(lines[index + 1])
            elif re.match(r'^(?:%\s*)?(?:no match|[a-z0-9.-]+ - no match|not found|domain not found|no entries found|the queried object|>>> domain .* available for registration|whois limit|query rate|error:|access denied|this domain .*reserved|this domain .*blocked)', lower):
                kept.append(line)
        return {'server': server, 'body': '\n'.join(kept), 'raw_bytes': len(text), 'empty_after_sanitizing': not kept}
    except (OSError, ValueError) as error:
        return {'server': server, 'error': str(error)}


def targets():
    rustc = shutil.which('rustc') or str(Path.home() / '.cargo/bin/rustc')
    with tempfile.TemporaryDirectory(prefix='dott-audit-targets-') as folder:
        executable = Path(folder) / 'targets'
        subprocess.run([rustc, '--edition=2024', str(ROOT / 'Tools/audit_targets.rs'), '-o', str(executable)], check=True)
        output = subprocess.check_output([str(executable)], text=True)
    return [dict(zip(['tld', 'rdap', 'whois', 'dpml'], line.split('\t'))) for line in output.splitlines()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collect', action='store_true', help='Explicitly query live registries')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--refresh-dns', action='store_true', help='Refresh only DNS evidence in an existing snapshot')
    parser.add_argument('--tlds', help='Collect only these comma-separated supported extensions')
    args = parser.parse_args()
    if not args.collect:
        parser.error('--collect is required to query live services')
    if args.refresh_dns:
        snapshot = json.loads(args.output.read_text())
        def refresh(target):
            for sample in target['samples']:
                sample['dns'] = http(sample['dns']['url'])
            print(f'.{target["tld"]}: DNS refreshed', flush=True)
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(refresh, snapshot['targets']))
        args.output.write_text(json.dumps(snapshot, indent=2) + '\n')
        return
    items = targets()
    if args.tlds:
        requested = set(args.tlds.split(','))
        supported = {item['tld'] for item in items}
        if requested - supported:
            parser.error(f'Unsupported TLDs: {sorted(requested - supported)}')
        items = [item for item in items if item['tld'] in requested]
    # Bootstrap contains metadata outside the sanitized domain-response fields.
    raw = subprocess.check_output(['curl', '-LsS', '--max-time', '12', 'https://data.iana.org/rdap/dns.json'], text=True)
    iana = json.loads(raw)
    services = {tld: urls for names, urls in iana['services'] for tld in names}
    probe = f'dott-audit-{time.time_ns()}'
    known = {'com': 'example.com', 'net': 'example.net', 'org': 'example.org', 'bot': 'amazon.bot', 'si': 'registry.si',
             'gy': 'registry.gy', 'to': 'tonic.to', 'is': 'isnic.is', 'in': 'registry.in',
             'id': 'pandi.id', 'nl': 'sidn.nl'}

    def audit(item):
        tld = item['tld']
        result = dict(item, iana=services.get(tld, []), samples=[])
        for domain, kind in [(known.get(tld, f'nic.{tld}'), 'registry_reference'), (f'{probe}.{tld}', 'unregistered_probe')]:
            sample = {'domain': domain, 'kind': kind}
            if item['rdap']:
                sample['rdap'] = http(item['rdap'].replace('AUDIT_LABEL', domain.rsplit('.', 1)[0]))
            if services.get(tld):
                official = services[tld][0].rstrip('/') + '/domain/' + domain
                if official != sample.get('rdap', {}).get('url'):
                    sample['iana_rdap'] = http(official)
            if item['whois']:
                sample['whois'] = whois(item['whois'], domain)
            sample['dns'] = http(f'https://cloudflare-dns.com/dns-query?name={domain}&type=NS')
            result['samples'].append(sample)
        print(f'.{tld}: captured', flush=True)
        return result

    rows = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        for future in as_completed([pool.submit(audit, item) for item in items]):
            rows.append(future.result())
    dpml = http('https://rdap.identitydigital.services/rdap/domain/apple.dpml.zone')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({'captured_at': datetime.now(timezone.utc).isoformat(),
        'iana_publication': iana['publication'], 'probe': probe, 'targets': sorted(rows, key=lambda r: r['tld']),
        'protection': dpml}, indent=2) + '\n')
    print(f'Saved {len(rows)} TLDs to {args.output}', flush=True)


if __name__ == '__main__':
    main()
