#!/usr/bin/env sh
# at installer (Unix: macOS and Linux).
#
# Installs the compiled binary under the command name `@`.
#
#   curl -fsSL https://at.krispowers.dev/install.sh | sh
#
# Override the download host or install dir with env vars:
#   AT_INSTALL_BASE   base URL to fetch release archives from
#   AT_INSTALL_DIR    directory to install the `@` binary into
#   AT_VERSION        release tag to install (default: latest)
#
# NOTE: the project repo is currently private, so these downloads will 404
# until the first public release. The single place to change the host is
# AT_INSTALL_BASE below.
set -eu

AT_INSTALL_BASE="${AT_INSTALL_BASE:-https://at.krispowers.dev}"
AT_INSTALL_DIR="${AT_INSTALL_DIR:-$HOME/.local/bin}"
AT_VERSION="${AT_VERSION:-latest}"

say() { printf '%s\n' "$*"; }
err() { printf 'at: error: %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || err "required tool not found: $1"; }

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os" in
    Darwin) os_part="apple-darwin" ;;
    Linux)  os_part="unknown-linux-gnu" ;;
    *) err "unsupported OS: $os (use the prebuilt binaries or build from source)" ;;
  esac
  case "$arch" in
    x86_64|amd64) arch_part="x86_64" ;;
    arm64|aarch64) arch_part="aarch64" ;;
    *) err "unsupported architecture: $arch" ;;
  esac
  printf '%s-%s' "$arch_part" "$os_part"
}

main() {
  need uname
  if command -v curl >/dev/null 2>&1; then
    fetch="curl -fsSL"
  elif command -v wget >/dev/null 2>&1; then
    fetch="wget -qO-"
  else
    err "need curl or wget"
  fi

  target="$(detect_target)"
  archive="at-${target}.tar.gz"
  url="${AT_INSTALL_BASE}/releases/${AT_VERSION}/${archive}"

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  say "Downloading ${url}"
  $fetch "$url" > "$tmp/$archive" || err "download failed: $url"

  tar -xzf "$tmp/$archive" -C "$tmp" || err "could not extract $archive"

  mkdir -p "$AT_INSTALL_DIR"
  # The archive ships the binary as `at`; install it as `@`.
  install -m 0755 "$tmp/at" "$AT_INSTALL_DIR/@" 2>/dev/null \
    || { cp "$tmp/at" "$AT_INSTALL_DIR/@" && chmod 0755 "$AT_INSTALL_DIR/@"; }

  say "Installed: ${AT_INSTALL_DIR}/@"

  case ":$PATH:" in
    *":$AT_INSTALL_DIR:"*) ;;
    *) say ""
       say "Note: ${AT_INSTALL_DIR} is not on your PATH. Add it, for example:"
       say "  echo 'export PATH=\"${AT_INSTALL_DIR}:\$PATH\"' >> ~/.zshrc" ;;
  esac

  say ""
  say "Try it:  @ 127.0.0.1"
}

main "$@"
