<p align="center">
  <img src="preview.png" width="800" alt="dott">
</p>

Domain search for the terminal. Checks RDAP, WHOIS, and DNS in parallel — **directly from your machine**. No proxy API or analytics. Terminal sessions check GitHub for new releases at most once a day. Set `DOTT_NO_UPDATE_CHECK=1` to disable automatic update checks. Interactive mode opens connections to the RDAP servers for your selected extensions and to Cloudflare DNS at startup, without sending any domain name, so the first search is as fast as later ones.

## Install

**Homebrew (macOS / Linux, recommended):**
```sh
brew tap yodatosh/dott https://github.com/yodatosh/dott
brew install yodatosh/dott/dott
```

**curl (macOS / Linux):**
```sh
curl -fsSL https://raw.githubusercontent.com/yodatosh/dott/master/install.sh | sh
```

New standalone installations go into `~/.local/bin`. Add that directory to your shell's PATH if prompted. The installer preserves the location of existing standalone installations, including older copies in `/usr/local/bin` or `/opt/homebrew/bin`, and refuses to overwrite a Homebrew-managed copy.

To choose another directory:
```sh
curl -fsSL https://raw.githubusercontent.com/yodatosh/dott/master/install.sh | env DOTT_INSTALL_DIR="$HOME/bin" sh
```

Prebuilt Linux binaries require a compatible GNU/glibc system; Alpine/musl users should build from source.

**From source (including Windows; requires Rust 1.89 or newer):**
```sh
git clone https://github.com/yodatosh/dott
cd dott
cargo install --locked --path .
```

## Updates

**Homebrew:**
```sh
brew update && brew upgrade yodatosh/dott/dott
```

For an existing installation under an older tap name, use `brew update && brew upgrade dott`. The tap must track this repository; GitHub redirects repository URLs after a username change.

**Standalone installer:**
```sh
dott --update
```

In interactive mode, type `/update` to use the same update flow. Homebrew installations run `brew update` followed by `brew upgrade dott`; standalone installations download and verify the new binary. `dott --update` also supports both installation methods. Restart dott after a successful update to run the new version.

Updates verify the release checksum and binary version before replacing the current executable. Your watchlist stays in place. Updates are explicit; dott does not install them automatically. If `dott --update` is unavailable in an older version, rerun the curl install command above. If your installation directory is not writable, the command reports the problem rather than requesting sudo.

**From source:** from your original clone:
```sh
git pull --ff-only
cargo install --locked --path .
```

Check the installed version with `dott --version`. Homebrew installations use Homebrew for updates; source installations use the source workflow above. Automatic release checks are disabled for `--plain`, piped or redirected output, and watchlist/background commands. `DOTT_NO_UPDATE_CHECK` disables automatic checks when set; explicit `--update` still works.

## Usage

```sh
dott                        # interactive mode
dott myname                 # check across all TLDs
dott myname.io              # check this full domain only
dott myname -t com,io,dev   # specific TLDs
dott -s cool project        # suggest names from keywords
dott myname --plain         # machine-readable output
echo myname | dott          # pipe mode
```

Plain output contains one `<domain> <status>` per line, with no banners or update notices. Redirected output also uses this format. Names are case-insensitive; unsupported TLDs and invalid domain labels are rejected. Use punycode for international domain names.

A full domain such as `myname.bot` always checks that exact domain; `--tlds` applies to bare names. Select one action per invocation: search, suggest, update, or a watchlist command.

Sample output:

```text
  ✓  myname.com   est $11.08 reg · $11.08 renew/yr
  ✓  myname.org   est $7.98 reg · $10.74 renew/yr
  ?  myname.gg
  ✗  myname.io     reg 2019-05-02  exp 2026-08-15
  ✗  myname.ai     reg 2021-11-30  exp 2027-03-01

  2 available  ·  14 checked
```

> `✓` available  ·  `✗` taken  ·  `?` unknown

Terminal searches and suggestions show standard USD registration and renewal estimates from [Porkbun's public pricing catalog](https://porkbun.com/api/json/v3/pricing/get). Premium names, minimum registration terms, and checkout totals may differ. These are yearly rates; registration may require multiple years.

Dott refreshes prices at most once every 24 hours across terminal sessions, including failed attempts. Prices are saved in `~/.dott/prices.json` (`%USERPROFILE%\.dott\prices.json` on Windows). If refreshing fails, previously fetched prices remain visible with a `cached` label. Missing prices show `price unavailable`. Pricing has a four-second timeout and runs alongside domain checks; it does not change availability results. Plain/piped output and watch commands do not fetch or display prices.

Inside interactive mode:

| Input               | What it does                         |
|---------------------|--------------------------------------|
| `name`              | check across your chosen extensions  |
| `name+`             | suggest prefix/suffix variants       |
| `+`                 | reuse the last searched name         |
| `/tlds`             | choose extensions to search          |
| `/watch <domain>`   | notify when a domain becomes free    |
| `/unwatch <domain>` | stop watching                        |
| `/list`             | show watchlist                       |
| `/help`             | command reference                    |
| `/update`           | update dott using its install method  |

`/tlds` opens a checklist of supported extensions. Use the arrow keys and Space, or click, then press Enter to apply or Esc to cancel. Your choice is saved in `~/.dott/extensions.json` and applies to bare-name searches and suggestions in the terminal. A full domain such as `myname.bot` still checks only that domain, `--tlds` overrides the saved choice for one run without changing it, and plain or piped output ignores it.

## Watchlist

```sh
dott --watch myname.com      # notify me when it becomes available
dott --watching              # show what you're tracking
dott --unwatch myname.com
```

On macOS, dott installs a LaunchAgent that re-checks the list daily at 9am local time and sends a system notification when a domain becomes available. These are daily checks, not instant alerts; the job runs in your logged-in user session. Notifications must be enabled for Script Editor in System Settings.

Watchlist changes are locked across processes, so watch/unwatch commands wait for an active background check rather than losing concurrent edits.

If you had a watch job before upgrading, rerun `dott --watch <domain>` for an already-watched domain to refresh its executable path or reload an inactive job. Existing Homebrew jobs are moved to the stable Homebrew link so later Brew upgrades keep working. Failed lookups keep the last known status; failed notification commands are reported and retried on the next check.

On other platforms the list can be refreshed by scheduling `dott --background-check`, but automatic desktop notifications are currently macOS-only.

## How it works

Three checks run in parallel for each domain:

| Source | Method             | What it tells you                   |
|--------|--------------------|-------------------------------------|
| RDAP   | HTTPS to registry  | Status + registration/expiry dates  |
| WHOIS  | TCP port 43        | Status + registration/expiry dates  |
| DNS    | Cloudflare DoH     | Whether NS records exist            |

Results are merged (DNS > RDAP > WHOIS priority). WHOIS runs in parallel and is awaited when RDAP is inconclusive. Expiring domains are highlighted — orange under 90 days, yellow under a year. An availability result is a registry lookup, not a guarantee that a registrar will sell the name at the displayed price; `unknown` is inconclusive.

## Supported TLDs

com, net, org, io, dev, app, co, ai, me, so, gg, cc, cv, xyz, live, computer, sh, fm, fyi, work, bot

## License

[MIT](LICENSE)
