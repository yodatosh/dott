#!/bin/sh
set -eu

REPO="yodatosh/dott"
BIN="dott"

for tool in curl tar awk; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Required command not found: $tool" >&2; exit 1; }
done

OS=$(uname -s)
ARCH=$(uname -m)
case "$OS/$ARCH" in
  Darwin/arm64) TARGET="aarch64-apple-darwin" ;;
  Darwin/x86_64) TARGET="x86_64-apple-darwin" ;;
  Linux/x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
  Linux/aarch64|Linux/arm64) TARGET="aarch64-unknown-linux-gnu" ;;
  *) echo "Unsupported platform: $OS/$ARCH" >&2; exit 1 ;;
esac

# Preserve existing standalone installations; new installs use a user-owned directory.
EXISTING=$(command -v "$BIN" || true)
if [ -n "${DOTT_INSTALL_DIR:-}" ]; then
  INSTALL_DIR=$DOTT_INSTALL_DIR
elif [ -n "$EXISTING" ]; then
  LINK=$(readlink "$EXISTING" || true)
  case "$EXISTING/$LINK" in
    */Cellar/dott/*)
      echo "dott is no longer on Homebrew. Remove that copy, then rerun this installer:" >&2
      echo "  brew uninstall dott && brew untap yodatosh/dott" >&2
      exit 1
      ;;
  esac
  INSTALL_DIR=$(dirname "$EXISTING")
  if [ ! -f "$INSTALL_DIR/.dott-install" ]; then
    case "$EXISTING" in
      /usr/local/bin/dott|/opt/homebrew/bin/dott) ;;
      *) echo "Existing dott was installed by another method. Update it using that method, or set DOTT_INSTALL_DIR explicitly." >&2; exit 1 ;;
    esac
  fi
else
  INSTALL_DIR="${HOME:?HOME must be set}/.local/bin"
fi

mkdir -p "$INSTALL_DIR"
INSTALL_DIR=$(cd "$INSTALL_DIR" && pwd -P)
if [ ! -w "$INSTALL_DIR" ]; then
  echo "Cannot write to $INSTALL_DIR. Choose a writable directory with DOTT_INSTALL_DIR." >&2
  exit 1
fi
if [ -L "$INSTALL_DIR/$BIN" ]; then
  echo "Refusing to replace a symlink at $INSTALL_DIR/$BIN. Use the original installation method." >&2
  exit 1
fi

# Keep the staged binary on the same filesystem for atomic replacement.
TMP=$(mktemp -d "$INSTALL_DIR/.dott-install.XXXXXXXX")
trap 'rm -rf "$TMP"' 0
trap 'exit 1' HUP INT TERM

curl -fsSL --connect-timeout 10 --max-time 30 \
  "https://api.github.com/repos/$REPO/releases/latest" -o "$TMP/release.json"
VERSION=$(sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"v\([^"]*\)".*/\1/p' "$TMP/release.json")
if ! printf '%s\n' "$VERSION" | awk -F. '
  NF != 3 { exit 1 }
  { for (i = 1; i <= 3; i++) if ($i !~ /^(0|[1-9][0-9]*)$/) exit 1 }
'; then
  echo "Could not determine a stable release version" >&2
  exit 1
fi

URL="https://github.com/$REPO/releases/download/v${VERSION}/${BIN}-${TARGET}.tar.gz"
echo "Installing dott v${VERSION} (${TARGET})..."
curl -fsSL --connect-timeout 10 --max-time 120 "$URL" -o "$TMP/dott.tar.gz"
curl -fsSL --connect-timeout 10 --max-time 30 "$URL.sha256" -o "$TMP/dott.tar.gz.sha256"
EXPECTED=$(awk 'NF == 2 {print $1}' "$TMP/dott.tar.gz.sha256")
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "$TMP/dott.tar.gz" | awk '{print $1}')
else
  ACTUAL=$(shasum -a 256 "$TMP/dott.tar.gz" | awk '{print $1}')
fi
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "SHA256 mismatch — refusing to install." >&2
  exit 1
fi
if [ "$(tar tzf "$TMP/dott.tar.gz")" != "$BIN" ]; then
  echo "Release archive must contain exactly one file named dott." >&2
  exit 1
fi
tar xzf "$TMP/dott.tar.gz" -C "$TMP" "$BIN"
if [ -L "$TMP/$BIN" ] || [ ! -f "$TMP/$BIN" ]; then
  echo "Release binary must be a regular file." >&2
  exit 1
fi
if [ "$("$TMP/$BIN" --version)" != "dott $VERSION" ]; then
  echo "Downloaded binary version does not match the release." >&2
  exit 1
fi
printf '%s\n' "$INSTALL_DIR/$BIN" > "$TMP/receipt"
mv -f "$TMP/$BIN" "$INSTALL_DIR/$BIN"
mv -f "$TMP/receipt" "$INSTALL_DIR/.dott-install"
echo "Installed to $INSTALL_DIR/$BIN"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "Add this directory to PATH in your shell profile:"; echo "  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
if [ -n "$EXISTING" ] && [ "$EXISTING" != "$INSTALL_DIR/$BIN" ]; then
  echo "Another dott exists at $EXISTING. Check 'command -v dott' to confirm which copy runs."
fi
echo "Run: dott"
echo "Update: dott --update"
