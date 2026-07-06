#!/usr/bin/env bash
#
# sentinel-install.sh — RunTrust/Sentinel macOS connector installer.
#
# This is the macOS analogue of the MODERN plugin setup path (Invoke-SentinelSetup),
# NOT the deprecated standalone Install-Sentinel that deep-merges ~/.claude/settings.json.
# Hook wiring is owned by the plugin's hooks.json (docs/system/cc-plugin.md:262-269):
# OS selection happens at install by copying the macOS manifest (hooks.darwin.json)
# over the installed plugin's hooks.json — no fragile bash JSON surgery, and stock
# macOS has no guaranteed jq. See docs/superpowers/specs/2026-06-29-macos-connector-design.md
# (decisions 2 + 4). The config scaffold is written UTF-8 with NO BOM, mirroring the
# no-BOM discipline of scripts/install/SentinelCore.psm1:107-112 (a BOM breaks the
# daemon/CLI JSON.parse).
#
# Usage:
#   sentinel-install.sh [--endpoint URL] [--home DIR] --plugin-root DIR
#   sentinel-install.sh --wire-only --plugin-root DIR        # only (re)wire the hook
#   sentinel-install.sh --downloads-dir DIR ...              # offline/test: cp from DIR
#
set -euo pipefail

endpoint="https://app.runtrust.ai"
home="${HOME:-/tmp}/.sentinel"
plugin_root="${CLAUDE_PLUGIN_ROOT:-}"
downloads_dir=""
wire_only=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --endpoint)      endpoint="${2:-}"; shift 2 ;;
    --home)          home="${2:-}"; shift 2 ;;
    --plugin-root)   plugin_root="${2:-}"; shift 2 ;;
    --downloads-dir) downloads_dir="${2:-}"; shift 2 ;;
    --wire-only)     wire_only=1; shift ;;
    *)               echo "sentinel-install: unknown argument: $1" >&2; exit 2 ;;
  esac
done

die() { echo "sentinel-install: $1" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Wiring: copy the macOS manifest over the installed plugin's hooks.json. Guarded so
# a wrong path can never mutate an unrelated directory (or this repo's source tree).
wire_plugin() {
  [ -n "$plugin_root" ] || die "wiring requires --plugin-root (or \$CLAUDE_PLUGIN_ROOT)"
  [ -f "$plugin_root/.claude-plugin/plugin.json" ] || die "not a plugin root (missing .claude-plugin/plugin.json): $plugin_root"
  [ -f "$plugin_root/hooks/sentinel-shim.sh" ]     || die "not a sentinel plugin (missing hooks/sentinel-shim.sh): $plugin_root"
  [ -f "$plugin_root/hooks/hooks.darwin.json" ]    || die "missing hooks/hooks.darwin.json in plugin root: $plugin_root"
  cp -f "$plugin_root/hooks/hooks.darwin.json" "$plugin_root/hooks/hooks.json"
  echo "Wired the macOS PreToolUse hook (hooks.darwin.json -> hooks.json). Run /reload-plugins in Claude Code to apply."
}

if [ "$wire_only" -eq 1 ]; then
  wire_plugin
  exit 0
fi

# A full install MUST wire the hook (wiring is owned by the plugin manifest — decision
# 4). The plugin root is therefore REQUIRED up front: a "successful" install that never
# wires the shim would leave the connector installed but not governing. Fail fast and
# clearly rather than place binaries and warn.
[ -n "$plugin_root" ] || die "a full install requires --plugin-root (or \$CLAUDE_PLUGIN_ROOT) so the macOS hook manifest can be wired; re-run with --plugin-root <installed-plugin-dir>"

# Derive <arch> from uname -m: arm64->arm64, x86_64->x64.
case "$(uname -m 2> /dev/null || echo unknown)" in
  arm64 | aarch64) arch="arm64" ;;
  x86_64 | amd64)  arch="x64" ;;
  *)               arch="x64" ;;
esac

bins=(
  "sentinel-cc-hook-darwin-${arch}.bin"
  "sentinel-cc-daemon-darwin-${arch}.bin"
  "sentinel-status-darwin-${arch}.bin"
)

# Stage into a temp dir; verify EVERY binary before placing ANY (a mismatch must
# abort before the install dir or config is touched).
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

fetch() {
  local name="$1"
  if [ -n "$downloads_dir" ]; then
    [ -f "$downloads_dir/$name" ] || die "artifact not found in --downloads-dir: $name"
    cp -f "$downloads_dir/$name" "$stage/$name"
  else
    curl -fsSL -o "$stage/$name" "${endpoint%/}/downloads/$name" || die "download failed: $name"
  fi
}

fetch "checksums.txt"
for b in "${bins[@]}"; do fetch "$b"; done

# Verify-all-before-place.
for b in "${bins[@]}"; do
  expected="$(awk -v f="$b" '$2 == f {print $1; exit}' "$stage/checksums.txt")"
  [ -n "$expected" ] || die "no checksum for $b in checksums.txt"
  actual="$(sha256_of "$stage/$b")"
  [ "$actual" = "$expected" ] || die "SHA-256 mismatch for $b (expected $expected, got $actual)"
done

# Place under ~/.sentinel/bin (executable).
mkdir -p "$home/bin"
for b in "${bins[@]}"; do
  cp -f "$stage/$b" "$home/bin/$b"
  chmod +x "$home/bin/$b"
done

# Config scaffold — UTF-8, NO BOM (printf to a plain file; see SentinelCore.psm1:107-112).
# Only write the scaffold if config.json does NOT already exist. If it exists (bound OR
# unbound), leave it untouched — sentinel-setup.sh owns the config and its --force guard
# depends on reading the existing tenantId. Overwriting here would defeat that guard.
if [ ! -f "$home/config.json" ]; then
  endpoint_esc="$(printf '%s' "$endpoint" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"
  ( umask 077 && printf '{"endpoint":"%s","tenantId":""}\n' "$endpoint_esc" > "$home/config.json" )
  chmod 600 "$home/config.json"
fi

# Wire the hook via the plugin manifest (owned by hooks.json, not settings.json).
# plugin_root is guaranteed non-empty here (required + checked above).
wire_plugin

echo "Sentinel macOS connector installed under $home (arch: $arch)."
