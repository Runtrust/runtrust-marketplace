#!/usr/bin/env bash
#
# sentinel-uninstall.sh — RunTrust/Sentinel macOS connector uninstaller.
#
# Removes the ~/.sentinel tree and, if --plugin-root is given, restores the
# hooks.json to the BASH-SHIM manifest (hooks.darwin.json) so the plugin hook
# cleanly no-ops post-uninstall instead of failing on a missing powershell.
#
# macOS-safe post-uninstall hook state (Codex blocking finding):
#   On macOS, powershell is absent. Restoring the PowerShell manifest would
#   make every PreToolUse fire an error. Instead we leave the bash-shim wired:
#   with config.json absent, sentinel-shim.sh hits its "not configured → allow"
#   path (sentinel-shim.sh:105) and cleanly no-ops.
#
# Usage:
#   sentinel-uninstall.sh [--home DIR] [--plugin-root DIR]
#
# Idempotent: running twice succeeds (removing an absent $home is fine).
# Zero external dependencies: no python3, no jq.

set -euo pipefail

# --- argument parsing ---------------------------------------------------------
home="${HOME:-/tmp}/.sentinel"
plugin_root=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --home)        home="${2:-}"; shift 2 ;;
    --plugin-root) plugin_root="${2:-}"; shift 2 ;;
    *)             echo "sentinel-uninstall: unknown argument: $1" >&2; exit 2 ;;
  esac
done

# --- safety guard: refuse dangerous rm -rf targets ---------------------------
# Rules (all must pass before we touch the filesystem):
#   1. $home must be non-empty.
#   2. The final path component must be exactly ".sentinel".
#   3. $home must not equal "/" or "$HOME" or "$HOME/" (belt-and-suspenders).
die() { echo "sentinel-uninstall: $*" >&2; exit 1; }

if [ -z "$home" ]; then die "refusing to run: --home is empty."; fi

_basename="${home%/}"           # strip any trailing slash
_basename="${_basename##*/}"    # keep only the last path component
[ "$_basename" = ".sentinel" ] || \
  die "refusing to run: --home must end in a path component named exactly '.sentinel' (got: '$home')."

_norm="${home%/}"               # normalised (no trailing slash)
if [ "$_norm" = "" ] || [ "$_norm" = "/" ]; then
  die "refusing to run: --home resolves to a filesystem root ('$home')."
fi
if [ "$_norm" = "${HOME%/}" ]; then
  die "refusing to run: --home must not be \$HOME ('$home')."
fi

# Guard: reject a resolved home that is a single path component directly under root
# (matches ^/[^/]*$, e.g. /.sentinel). A real Sentinel home is always
# <user-home>/.sentinel which has at least two components (e.g. /Users/alice/.sentinel).
# This fires when HOME is unset and the default expands to /.sentinel.
case "$_norm" in
  /*)
    _depth="${_norm#/}"          # strip leading /
    case "$_depth" in
      */*)  ;;                   # has at least one more slash — safe
      *)    die "refusing to run: --home '$home' is a single component directly under root (e.g. /.sentinel); a real Sentinel home must be at least two levels deep (e.g. /home/user/.sentinel)." ;;
    esac
    ;;
esac

# --- remove the sentinel home tree (idempotent) --------------------------------
if [ -d "$home" ]; then
  rm -rf "$home"
  echo "RunTrust/Sentinel connector data removed from $home."
else
  echo "RunTrust/Sentinel: $home not found (already removed or never installed)."
fi

# --- macOS-safe hook manifest restore -----------------------------------------
# Leave the BASH-SHIM manifest in place (copy hooks.darwin.json -> hooks.json).
# This ensures:
#   1. powershell is never invoked on macOS (it is absent on stock macOS).
#   2. The bash shim fires on every PreToolUse but immediately exits via the
#      "not configured -> allow" path since config.json is now absent.
#
# Do NOT write the PowerShell manifest here. A PS hook on macOS would produce
# an error on every tool call even after uninstall.
if [ -n "$plugin_root" ]; then
  hooks_darwin="${plugin_root}/hooks/hooks.darwin.json"
  hooks_json="${plugin_root}/hooks/hooks.json"
  if [ -f "$hooks_darwin" ]; then
    cp -f "$hooks_darwin" "$hooks_json"
    echo "Hook manifest restored to bash-shim (hooks.darwin.json -> hooks.json)."
    echo "(To remove the plugin itself, run /plugin uninstall sentinel.)"
  else
    echo "sentinel-uninstall: warning: $hooks_darwin not found; hooks.json not updated." >&2
  fi
fi

exit 0
