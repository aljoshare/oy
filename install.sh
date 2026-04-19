#!/bin/sh
# install.sh — download and install the oy binary from GitHub Releases.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/aljoshare/oy/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/aljoshare/oy/main/install.sh | sh -s -- -b ~/.local/bin
#   curl -fsSL https://raw.githubusercontent.com/aljoshare/oy/main/install.sh | sh -s -- v1.2.0
#
# Flags:
#   -b <dir>   Installation directory (default: /usr/local/bin)
#
# Arguments:
#   [version]  Version to install, e.g. v1.2.0 (default: latest release)

set -e

REPO="aljoshare/oy"
BIN_DIR="/usr/local/bin"
VERSION=""

usage() {
  echo "Usage: install.sh [-b <bin_dir>] [version]" >&2
}

while getopts "b:h" opt; do
  case "$opt" in
    b) BIN_DIR="$OPTARG" ;;
    h) usage; exit 0 ;;
    ?) usage; exit 1 ;;
  esac
done
shift $((OPTIND - 1))

if [ -n "${1:-}" ]; then
  VERSION="$1"
fi

# --- Detect OS ---
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  linux|darwin) ;;
  *) echo "Error: unsupported OS: $OS" >&2; exit 1 ;;
esac

# --- Detect architecture ---
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)        ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Error: unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# --- Resolve latest version ---
if [ -z "$VERSION" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 \
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
  if [ -z "$VERSION" ]; then
    echo "Error: could not resolve latest release" >&2
    exit 1
  fi
fi

# --- Pick checksum command ---
if command -v sha256sum >/dev/null 2>&1; then
  SHASUM="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHASUM="shasum -a 256"
else
  echo "Warning: sha256sum / shasum not found — skipping checksum verification" >&2
  SHASUM=""
fi

# --- Download ---
ARCHIVE="oy_${OS}_${ARCH}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

echo "Downloading oy ${VERSION} (${OS}/${ARCH})..."
curl -fsSL "${BASE_URL}/${ARCHIVE}" -o "${TMP}/${ARCHIVE}"

# --- Verify checksum ---
if [ -n "$SHASUM" ]; then
  curl -fsSL "${BASE_URL}/checksums.txt" -o "${TMP}/checksums.txt"
  (cd "$TMP" && grep " ${ARCHIVE}$" checksums.txt | $SHASUM -c -)
fi

# --- Extract and install ---
tar -xzf "${TMP}/${ARCHIVE}" -C "$TMP" oy
mkdir -p "$BIN_DIR"
mv "${TMP}/oy" "${BIN_DIR}/oy"
chmod +x "${BIN_DIR}/oy"

echo "Installed ${BIN_DIR}/oy ${VERSION}"
