# Changelog

## 0.9.0 — 2026-11-15

**New**
- Interactive mode opens on a clean window with the logo and a prompt on the bottom row.
  Live rows scroll with ↑/↓ and Page Up/Down when they don't fit; Esc cancels.
  Finished results stay in normal scrollback for selecting and copying.
- Typing `/` opens a filtered command menu; Tab completes, Enter runs it.
- Input history, cursor editing, Ctrl+W/Ctrl+U, and editable multiline paste.
  Esc clears typed text first, then quits.
- `/details <domain>` (full dates, renewal estimate), `/results`, `/retry`
  (inconclusive checks only), and saved shortlists (`/save`, `/unsave`, `/shortlist`).
- `.si`, `.click`, `.fun`, `.gy`, `.ly`, `.to`, `.is`, `.tv`, `.in`, `.id`, `.fr`, `.pt`.
- Bare names check exact suffix splits first (`phagy` → `pha.gy`).
- Searches flag names that were available at your last check and are now taken.
- Short `.me` names show a possible-premium hint.

**Changed**
- Results appear as each check finishes; pricing never delays them.
- Rows show the Porkbun price for available names and registered, updated and
  expiry dates for taken ones; narrow terminals keep only the expiry.
- Inconclusive results say why (timeout, rate limit, malformed reply).
- Suggestions include later keywords and combinations.
- Registry routing uses a bundled IANA RDAP directory.
- Update checks never delay a command; a new release shows on the next run.

**Fixed**
- Trademark-protected (DPML) `.live`, `.computer` and `.fyi` labels no longer
  appear available.
- Audited all 33 registries: stricter WHOIS matching and error detection, DNS
  validation, and conflicting-result handling. Corrected the `.work` endpoint.
- WHOIS tries IPv4 first, so networks with broken IPv6 no longer time out.

## 0.8.0 — 2026-10-02

**New**
- `/tlds`: choose which extensions bare-name searches and suggestions check, with
  keyboard and mouse. Saved across sessions; `--tlds` overrides it for one run.
- `.bot` extension.
- Porkbun registration prices ("$11.08 on porkbun"), refreshed at most daily, with
  saved prices kept when a refresh fails. Never shown in plain output.
- `dott --update` and `/update`: download, verify checksum and version, and
  replace the binary atomically.
- Daily release check in terminal sessions; `DOTT_NO_UPDATE_CHECK` disables it.
- Farewell uses your username.
- New `❯❯❯` prompt in the logo colors; input is held until results finish.
- macOS watchlist notifications come from "dott" instead of Script Editor, via a
  small `~/.dott/dott.app` helper; falls back to Script Editor if it can't be used.
- Watchlist changes show when opening dott, and optionally in every new zsh
  window (`--shell-notice on|off`, offered on first watch).

**Faster**
- Taken results return as soon as RDAP confirms them, without waiting for DNS.
- No redundant rdap.org retry when the registry already answered.
- Interactive mode pre-opens connections for your extensions and loads prices
  at startup, so the first search is as fast as later ones.

**Changed**
- Homebrew is no longer supported; install with curl. Brew users: `brew uninstall
  dott && brew untap yodatosh/dott`, then run the curl installer.
- A full domain always checks exactly that domain, even with `--tlds`.
- Invalid names and unsupported extensions are rejected; names are case-insensitive.
- Plain and redirected output contain only `<domain> <status>` lines.
- curl installs go to `~/.local/bin` (or `DOTT_INSTALL_DIR`); existing install
  locations are kept.

**Fixed**
- False "available" when rdap.org has no RDAP service for an extension (its own 404
  is now inconclusive). `.co` now uses WHOIS only and `.so` the registry's RDAP.
- `name+` no longer repeats the name you just searched.
- `.so` names reported as taken from the WHOIS "object does not exist" reply.
- WHOIS "taken" requires a record field, not "domain:" anywhere in the text.
- Taken now requires real NS records or a valid RDAP domain object.
- Watchlist: saved atomically, locked across processes, corrupt files reported,
  unsupported domains rejected, known status kept on inconclusive checks, and
  failed notifications retried.
- macOS watch job reloads when inactive.
- Malformed expiry dates no longer panic.
- Releases publish only after every build passes and all archives verify.

## 0.6.9

Previous published release. See GitHub Releases for earlier history.
