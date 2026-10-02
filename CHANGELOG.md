# Changelog

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
