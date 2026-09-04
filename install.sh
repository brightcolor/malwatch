#!/bin/sh
# malwatch installer.
#
#   curl -fsSL https://raw.githubusercontent.com/brightcolor/malwatch/main/install.sh | sh
#
# Options (environment variables):
#   VERSION=v1.2.3   install a specific release (default: latest)
#   BINDIR=/path     install directory (default: /usr/local/bin)
#   SIGDIR=/path     signature directory (default: /var/lib/malwatch/signatures)
#   NO_UPDATE=1      do not download signatures after installing
set -eu

REPO="brightcolor/malwatch"
BINDIR="${BINDIR:-/usr/local/bin}"
SIGDIR="${SIGDIR:-/var/lib/malwatch/signatures}"
VERSION="${VERSION:-latest}"

info() { printf '\033[1;34m==>\033[0m %s\n' "$1"; }
err()  { printf '\033[1;31mError:\033[0m %s\n' "$1" >&2; exit 1; }

os="$(uname -s)"
[ "$os" = "Linux" ] || err "malwatch only ships Linux binaries (detected: $os). Build from source instead."

case "$(uname -m)" in
  x86_64|amd64)  arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) err "unsupported architecture: $(uname -m)" ;;
esac

asset="malwatch-linux-$arch"
if [ "$VERSION" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

if command -v curl >/dev/null 2>&1; then dl() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then dl() { wget -qO "$2" "$1"; }
else err "need curl or wget"; fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

info "Downloading $asset ($VERSION)"
dl "$base/$asset" "$tmp/malwatch" || err "download failed: $base/$asset"

# The binary runs as root over every file on the server. It is never installed
# without a verified checksum: a missing sums file aborts the install rather
# than being waved through.
dl "$base/SHA256SUMS" "$tmp/SHA256SUMS" || err "could not download the checksum file"
if command -v sha256sum >/dev/null 2>&1; then
  want="$(grep " \*\?$asset\$" "$tmp/SHA256SUMS" | awk '{print $1}')"
  [ -n "$want" ] || err "the checksum file lists no entry for $asset"
  got="$(sha256sum "$tmp/malwatch" | awk '{print $1}')"
  [ "$want" = "$got" ] || err "checksum mismatch (want $want, got $got)"
  info "Checksum OK"
else
  err "sha256sum is not available, cannot verify the download"
fi

SUDO=""
if [ ! -w "$BINDIR" ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else err "$BINDIR is not writable and sudo is unavailable"; fi
fi

info "Installing to $BINDIR/malwatch"
$SUDO install -m 0755 "$tmp/malwatch" "$BINDIR/malwatch"

if [ "${NO_UPDATE:-0}" != "1" ]; then
  info "Downloading signatures to $SIGDIR"
  $SUDO "$BINDIR/malwatch" update --sig-dir="$SIGDIR" || \
    printf 'The signatures could not be loaded. Run: malwatch update\n' >&2
fi

info "Installed: $("$BINDIR/malwatch" version)"
printf '\nNext: malwatch scan --path=/var/www   (see https://github.com/%s)\n' "$REPO"
