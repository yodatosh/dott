#!/usr/bin/env python3
"""Exercise llms.txt's agent workflow against live registries (explicit opt-in)."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.request

ROW = re.compile(r'([a-z0-9-]+\.[a-z0-9]+) (available|taken|protected|unknown)')


def query(binary, args, stdin=None):
    completed = subprocess.run([binary, *args, '--plain'], input=stdin,
                               text=True, capture_output=True, timeout=90)
    if completed.returncode or completed.stderr:
        raise RuntimeError(f'Command failed: {completed.stderr}')
    rows = {}
    for line in completed.stdout.splitlines():
        match = ROW.fullmatch(line)
        if not match:
            raise RuntimeError(f'Unexpected agent output: {line!r}')
        domain, status = match.groups()
        if domain in rows:
            raise RuntimeError(f'Duplicate output: {domain}')
        rows[domain] = status
    return rows


def registry(domain):
    tld = domain.rsplit('.', 1)[1]
    endpoints = {
        'com': 'https://rdap.verisign.com/com/v1/',
        'org': 'https://rdap.publicinterestregistry.org/rdap/',
        'dev': 'https://pubapi.registry.google/rdap/',
        'bot': 'https://rdap.nominet.uk/bot/',
    }
    url = endpoints[tld] + 'domain/' + domain
    request = urllib.request.Request(url, headers={'User-Agent': 'dott-agent-smoke',
                                                  'Accept': 'application/rdap+json'})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.load(response)
            if data.get('objectClassName') != 'domain':
                raise RuntimeError(f'Invalid registry object for {domain}')
            return 'taken'
    except urllib.error.HTTPError as error:
        try:
            data = json.load(error)
        except (ValueError, UnicodeError):
            return 'unknown'
        if error.code == 404 and data.get('errorCode') == 404:
            return 'available'
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='/usr/local/bin/dott')
    args = parser.parse_args()
    print('Following llms.txt: --plain, targeted TLDs, piped domains, suggestions.', flush=True)
    registered = ['google.com', 'github.com', 'openai.com', 'example.com',
                  'rust-lang.org', 'python.org', 'google.dev', 'amazon.bot']
    rows = query(args.binary, [], '\n'.join(registered) + '\n')
    if set(rows) != set(registered):
        raise RuntimeError('Full-domain pipe did not preserve the requested domains')
    for domain in registered:
        reference = registry(domain)
        if rows[domain] != reference:
            raise RuntimeError(f'{domain}: dott={rows[domain]}, registry={reference}')
        print(f'{domain}: {rows[domain]} (registry agrees)', flush=True)
    name = f'dott-agent-probe-{int(time.time())}'
    rows = query(args.binary, [name])
    if len(rows) != 21:
        raise RuntimeError(f'Expected 21 TLDs, received {len(rows)}')
    counts = {status: list(rows.values()).count(status) for status in sorted(set(rows.values()))}
    print(f'All-TLD agent command: {len(rows)} clean rows; {counts}', flush=True)
    for tld in ['com', 'org', 'dev', 'bot']:
        domain = f'{name}.{tld}'
        reference = registry(domain)
        if reference == 'unknown':
            print(f'{domain}: {rows[domain]} (independent registry response inconclusive)', flush=True)
            continue
        if rows[domain] != reference:
            raise RuntimeError(f'{domain}: dott={rows[domain]}, registry={reference}')
        print(f'{domain}: {rows[domain]} (registry agrees)', flush=True)
    suggestions = query(args.binary, ['--suggest', name, '--tlds', 'com'])
    if len(suggestions) != 14 or any(not d.endswith('.com') for d in suggestions):
        raise RuntimeError('Suggestion output did not respect --tlds com or contain 14 unique rows')
    print(f'Suggestion command: {len(suggestions)} unique .com rows, no banners or notices.', flush=True)
    print('Agent workflow passed. unknown remains inconclusive; availability is not a purchase guarantee.', flush=True)


if __name__ == '__main__':
    main()
