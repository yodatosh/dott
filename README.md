<p align="center">
  <img src="preview.png" width="800" alt="dott">
</p>

Domain search for the terminal. Checks RDAP, WHOIS and DNS in parallel, **directly from your machine** — no proxy API, no analytics.

## Install

```sh
# Homebrew (macOS / Linux)
brew tap yodatosh/dott https://github.com/yodatosh/dott
brew install yodatosh/dott/dott

# curl (macOS / GNU Linux) — installs to ~/.local/bin, or set DOTT_INSTALL_DIR
curl -fsSL https://raw.githubusercontent.com/yodatosh/dott/master/install.sh | sh

# From source (any OS, Rust 1.89+)
cargo install --locked --git https://github.com/yodatosh/dott
```

Alpine/musl users should build from source.

## Update

`dott --update` (or `/update` in interactive mode) runs `brew update && brew upgrade dott` for Homebrew installs, or downloads and verifies the new binary for curl installs. Source installs: rerun `cargo install`.

Terminal sessions check GitHub for a new release at most once a day; set `DOTT_NO_UPDATE_CHECK=1` to turn that off.

## Usage

```sh
dott                        # interactive mode
dott myname                 # check your chosen extensions (all by default)
dott myname.io              # check this exact domain
dott myname -t com,io,dev   # check these extensions, this run only
dott -s cool project        # suggest names from keywords
dott myname --plain         # one "<domain> <status>" per line, for scripts
echo myname | dott          # pipe mode (plain)
```

```text
  ✓  myname.com   $11.08 on porkbun
  ✓  myname.org   $7.98 on porkbun
  ★  myname.dev   reserved / blocked
  ?  myname.gg
  ✗  myname.io    reg 2019-05-02  exp 2026-08-15

  2 available  ·  5 checked
```

`✓` available · `✗` taken · `★` reserved · `?` unknown (inconclusive). Expiry dates turn orange under 90 days, yellow under a year.

Plain statuses are `available`, `taken`, `protected` and `unknown`; scripts and agents should treat only `available` as available. Invalid input exits nonzero with a message on stderr.

Interactive commands:

| Input               | What it does                            |
|---------------------|-----------------------------------------|
| `name` / `name.tld` | check your chosen extensions / one domain |
| `name+`, `+`        | suggest variants (of the last name)     |
| `/tlds`             | choose extensions (keyboard or mouse)   |
| `/watch <domain>`   | notify when a domain becomes free       |
| `/unwatch <domain>` | stop watching                           |
| `/list`             | show watchlist                          |
| `/update`, `/help`  | update dott, show commands              |

Your `/tlds` choice is saved in `~/.dott/extensions.json`. `--tlds` overrides it for one run, a full domain always checks just that domain, and plain/piped output ignores it.

## Prices

Available names show standard USD yearly estimates from [Porkbun's public catalog](https://porkbun.com/api/json/v3/pricing/get). Premium names and checkout totals may differ. Prices are refreshed at most once a day and saved in `~/.dott/prices.json`; plain output never includes them.

## Watchlist

```sh
dott --watch myname.com
dott --watching
dott --unwatch myname.com
```

On macOS a LaunchAgent re-checks the list daily at 9am and sends a notification from **dott** when a domain becomes available (dott keeps a tiny helper app at `~/.dott/dott.app` for this; allow it in System Settings → Notifications). Elsewhere, schedule `dott --background-check` yourself.

Changes (became available, was registered, now reserved) also show when you open dott. With zsh, `dott --shell-notice on` adds one marked line to `~/.zshrc` so every new terminal window shows them too; `dott --shell-notice off` removes it, and so does unwatching your last domain. Running `dott --watching` or opening dott marks them as seen.

## How it works

Each domain is checked against the registry's RDAP server, WHOIS (port 43) and Cloudflare DNS-over-HTTPS. Results merge with DNS > RDAP > WHOIS priority. Interactive mode pre-opens connections to the servers for your chosen extensions at startup (no domain names sent) so the first search is fast. "Available" means no registration was found — not a guarantee a registrar will sell it.

## Supported TLDs

com, net, org, io, dev, app, co, ai, me, so, gg, cc, cv, xyz, live, computer, sh, fm, fyi, work, bot

## License

[MIT](LICENSE)
