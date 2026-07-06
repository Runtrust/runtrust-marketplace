#!/usr/bin/env bash
#
# sentinel-status.sh — RunTrust/Sentinel macOS status helper.
#
# Prints the current connector state by shelling out to the status binary
# placed by sentinel-install.sh. Mirrors sentinel-status.ps1 behavior.
#
# Usage:
#   sentinel-status.sh [--home DIR] [--plugin-root DIR]
#
# Exit codes:
#   0  — either not-setup (printed) or the status binary succeeded
#   non-zero — status binary reported an error (exit code relayed)
#
# Down-state semantics: "shadow", "audit-only-allowed", "no-bundle" are NORMAL
# operational states and are never treated as failure here. Only an explicit
# engine/sink unreachable signal in the binary's output indicates a problem —
# and that is surfaced by the binary's own JSON, which we relay verbatim.
#
# If --plugin-root is given, the manifest at $plugin_root/hooks/hooks.json is
# inspected. If it contains a PowerShell invocation (mis-wired after a plugin
# update) a clear warning is printed; we do NOT fail on this.
#
# Zero external dependencies: no python3, no jq.

set -euo pipefail

# --- argument parsing ---------------------------------------------------------
home="${HOME:-/tmp}/.sentinel"
plugin_root=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --home)        home="${2:-}"; shift 2 ;;
    --plugin-root) plugin_root="${2:-}"; shift 2 ;;
    *)             echo "sentinel-status: unknown argument: $1" >&2; exit 2 ;;
  esac
done

# --- not-setup gate -----------------------------------------------------------
config="${home}/config.json"
if [ ! -f "$config" ]; then
  printf 'not-setup\n'
  exit 0
fi

# --- arch derivation (mirrors sentinel-shim.sh:41-46) -------------------------
arch_raw="$(uname -m 2>/dev/null || echo unknown)"
case "$arch_raw" in
  arm64 | aarch64) arch="arm64" ;;
  x86_64 | amd64)  arch="x64" ;;
  *)               arch="x64" ;;
esac

status_bin="${home}/bin/sentinel-status-darwin-${arch}.bin"

# --- binary presence check ----------------------------------------------------
if [ ! -f "$status_bin" ] || [ ! -x "$status_bin" ]; then
  echo "sentinel-status: status binary not found: $status_bin" >&2
  exit 1
fi

# --- mis-wired manifest detection (optional; non-fatal) ----------------------
if [ -n "$plugin_root" ]; then
  hooks_json="${plugin_root}/hooks/hooks.json"
  if [ -f "$hooks_json" ] && grep -qE 'powershell|sentinel-shim\.ps1' "$hooks_json" 2>/dev/null; then
    echo "WARNING: macOS hook is mis-wired — hooks.json contains a PowerShell invocation." >&2
    echo "WARNING: This can happen after a plugin update reverts the manifest." >&2
    echo "WARNING: Re-run /sentinel:setup (or sentinel-install.sh --wire-only --plugin-root ...) to re-wire the bash shim." >&2
  fi
fi

# --- shell out to the status binary and relay its output + exit code ----------
"$status_bin" --json
