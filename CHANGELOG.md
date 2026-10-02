# Changelog

## 0.8.0 — Unreleased

- Add interactive `/tlds` to choose which extensions bare-name searches and
  suggestions check, with keyboard and mouse support. The choice is saved across
  sessions; `--tlds` overrides it for one run, and plain/piped output ignores it.
- Return a taken result as soon as the registry's RDAP confirms it instead of
  waiting for a slow DNS lookup.
- Skip the rdap.org retry when the registry already answered; it only redirects
  back to the same server. It still runs when the registry is unreachable.
- Speed up the first interactive search: at startup and after `/tlds`, open
  connections to the selected extensions' RDAP servers and Cloudflare DNS (no
  domain names sent) and load prices in the background.
- Fix `.so` names being reported as taken when the WHOIS fallback answered
  "object does not exist".

- Add `.bot` to supported extensions using Nominet's registry RDAP service and
  the same cached Porkbun pricing flow.

- Replace hardcoded prices with Porkbun standard registration and renewal estimates,
  cached across sessions for 24 hours, with saved-price fallback after failed refreshes.
  Keep pricing out of plain output and watch commands.

- Personalize the interactive farewell with the local username from `USER`,
  `LOGNAME`, or Windows `USERNAME`, falling back to `bye 🐱` when unavailable.

- Add `dott --update` and interactive `/update` for standalone macOS and GNU Linux installations, with
  checksum and version verification before atomic replacement.
- Delegate Homebrew updates to `brew update` / `brew upgrade dott`; correct installation detection.
- Install new standalone copies into `~/.local/bin`, support `DOTT_INSTALL_DIR`,
  and preserve existing standalone installation locations.
- Check for releases at most daily in terminal sessions, with
  `DOTT_NO_UPDATE_CHECK` to disable automatic checks.
- Keep banners and update notices out of plain and redirected output.
- Honor full-domain TLDs, normalize name casing, reject invalid labels and
  unsupported TLDs, and honor `--tlds` in suggestion mode.
- A full domain in the input now always checks that exact domain, even with `--tlds`;
  `--tlds` applies to bare names.
- Require actual DNS NS records and valid RDAP domain objects for taken results.
- Reject unsupported watchlist domains instead of silently querying `.com`;
  retain known status during inconclusive background checks.
- Save watchlists atomically and report corrupt files instead of silently resetting them.
- Lock watchlist changes across processes so background checks and watch/unwatch
  commands cannot overwrite each other's changes.
- Keep the macOS watch job pointing at Homebrew's stable executable link.
- Reload inactive watch jobs when watching an existing domain, and report/retry
  failed notification commands instead of silently losing availability alerts.
- Handle malformed expiry dates without panicking.
- Validate release versions and archives, publish after all builds finish,
  and generate the tap formula from verified release artifacts.

## 0.6.9

Previous published release. See GitHub Releases for earlier release history.
