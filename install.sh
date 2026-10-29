#!/usr/bin/env sh
# portscan installer (Unix: macOS and Linux).
#
#   curl -fsSL https://raw.githubusercontent.com/KrisPowers/portscan/main/install.sh | sh
#
# Override with env vars:
#   PORTSCAN_INSTALL_DIR   directory to install the binary into
#   PORTSCAN_VERSION       release tag to install, e.g. v0.1.0 (default: latest)
set -eu

repo="https://github.com/KrisPowers/portscan"
dir="${PORTSCAN_INSTALL_DIR:-$HOME/.local/bin}"
version="${PORTSCAN_VERSION:-latest}"

say() { printf '%s\n' "$*"; }
err() { printf 'portscan: error: %s\n' "$*" >&2; exit 1; }

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
  if command -v curl >/dev/null 2>&1; then
    fetch="curl -fsSL"
  elif command -v wget >/dev/null 2>&1; then
    fetch="wget -qO-"
  else
    err "need curl or wget"
  fi

  archive="portscan-$(detect_target).tar.gz"
  if [ "$version" = latest ]; then
    url="$repo/releases/latest/download/$archive"
  else
    url="$repo/releases/download/$version/$archive"
  fi

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  say "Downloading $url"
  $fetch "$url" > "$tmp/$archive" || err "download failed: $url"
  tar -xzf "$tmp/$archive" -C "$tmp" || err "could not extract $archive"

  mkdir -p "$dir"
  install -m 0755 "$tmp/portscan" "$dir/portscan" 2>/dev/null \
    || { cp "$tmp/portscan" "$dir/portscan" && chmod 0755 "$dir/portscan"; }
  say "Installed: $dir/portscan"

  case ":$PATH:" in
    *":$dir:"*) ;;
    *) say ""
       say "Note: $dir is not on your PATH. Add it, for example:"
       say "  echo 'export PATH=\"$dir:\$PATH\"' >> ~/.zshrc" ;;
  esac

  say ""
  say "Try it:  portscan 127.0.0.1"
}

main "$@"
