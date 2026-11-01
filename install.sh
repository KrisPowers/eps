#!/usr/bin/env sh
# EPS installer (Unix: macOS and Linux). Installs the binary as `@`, the
# command you type.
#
#   curl -fsSL https://raw.githubusercontent.com/KrisPowers/eps/main/install.sh | sh
#
# Override with env vars:
#   EPS_INSTALL_DIR   directory to install `@` into
#   EPS_VERSION       release tag to install, e.g. v1.0.0 (default: latest)
set -eu

repo="https://github.com/KrisPowers/eps"
dir="${EPS_INSTALL_DIR:-$HOME/.local/bin}"
version="${EPS_VERSION:-latest}"

say() { printf '%s\n' "$*"; }
err() { printf '@: error: %s\n' "$*" >&2; exit 1; }

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

  archive="eps-$(detect_target).tar.gz"
  if [ "$version" = latest ]; then
    url="$repo/releases/latest/download/$archive"
  else
    url="$repo/releases/download/$version/$archive"
  fi

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  say "Downloading $url"
  $fetch "$url" > "$tmp/$archive" || err "download failed: $url"
  $fetch "$url.sha256" > "$tmp/$archive.sha256" || err "download failed: $url.sha256"
  want="$(cut -d' ' -f1 < "$tmp/$archive.sha256")"
  if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "$tmp/$archive" | cut -d' ' -f1)"
  else
    got="$(shasum -a 256 "$tmp/$archive" | cut -d' ' -f1)"
  fi
  [ -n "$want" ] && [ "$want" = "$got" ] || err "checksum mismatch for $archive"
  tar -xzf "$tmp/$archive" -C "$tmp" || err "could not extract $archive"

  mkdir -p "$dir"
  # The archive ships the binary as `eps`; install it as `@`.
  install -m 0755 "$tmp/eps" "$dir/@" 2>/dev/null \
    || { cp "$tmp/eps" "$dir/@" && chmod 0755 "$dir/@"; }
  say "Installed: $dir/@"

  case ":$PATH:" in
    *":$dir:"*) ;;
    *) say ""
       say "Note: $dir is not on your PATH. Add it, for example:"
       say "  echo 'export PATH=\"$dir:\$PATH\"' >> ~/.zshrc" ;;
  esac

  say ""
  say "Try it:  @ 127.0.0.1"
}

main "$@"
