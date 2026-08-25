#!/usr/bin/env bash
# Freeze-proof PreToolUse shim (macOS / POSIX bash). Mirrors the Windows
# sentinel-shim.ps1 contract documented in Sentinel-AI:docs/system/cc-plugin.md "Hook shim"
# items 1-7 and the spec Sentinel-AI:docs/superpowers/specs/2026-06-29-macos-connector-design.md
# (decision 3, full freeze-proof parity).
#
# EVERY path emits a POPULATED wire: a real hook decision is relayed exactly
# (first stdout line, byte-for-byte + single trailing LF); every other path
# (pre-setup, stdin-read timeout, delegation timeout, empty stdout, error) emits
# a populated ALLOW via write_allow — NEVER empty stdout (an empty/bare wire
# hangs Claude Code's model loop), and the shim NEVER originates a deny.
#
# Stock macOS has no GNU `timeout`, so each blocking phase is bounded by a
# portable background-PID + watchdog-kill pattern (mirrors sentinel-shim.ps1:53-85
# bounded stdin read and :109-196 bounded delegation). The shim has NO unbounded
# operation anywhere. Unlike the Windows shim it does NOT rewrite the ALLOW
# additionalContext: the hook exe emits ALLOW_CONTINUATION_DIRECTIVE at the
# source (packages/cc-hook/src/types.ts), so a byte-exact relay already carries
# it (no jq/python/node needed). See sentinel-shim.ps1:88,90 for the parity gates.

set -u

# --- argument / env parsing -------------------------------------------------
home=""
hook_exe=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --home)     home="${2:-}"; shift 2 ;;
    --hook-exe) hook_exe="${2:-}"; shift 2 ;;
    *)          shift ;;   # ignore unknown args (forward-compat, never abort)
  esac
done

if [ -z "$home" ]; then
  home="${HOME:-/tmp}/.sentinel"
fi

# Derive <arch> from uname -m: arm64->arm64, x86_64->x64. Tolerate other uname
# (e.g. MINGW on local Git Bash) by still deriving a value so the stub paths work.
if [ -z "$hook_exe" ]; then
  arch_raw="$(uname -m 2>/dev/null || echo unknown)"
  case "$arch_raw" in
    arm64|aarch64) arch="arm64" ;;
    x86_64|amd64)  arch="x64" ;;
    *)             arch="x64" ;;   # unknown host -> default; stub paths still function
  esac
  # Must match the name the installer places (sentinel-install.sh) and stages
  # (stage-downloads-darwin.sh): "...-darwin-<arch>.bin". A mismatch here means the
  # shim reports hook-exe-missing after a real install and never governs.
  hook_exe="${home}/bin/sentinel-cc-hook-darwin-${arch}.bin"
fi

config="${home}/config.json"

# --- populated wires --------------------------------------------------------
# Fixed-string ALLOW wire (no JSON parsing). One trailing LF, never empty stdout.
write_allow() {
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"%s"}}\n' "$1"
}

# Best-effort NDJSON diagnostic; UTF-8 no-BOM (printf to a plain file). Never
# aborts the relay. Mirrors sentinel-shim.ps1:35-44 Write-ShimDiag.
diag() {
  mkdir -p "${home}/logs" 2>/dev/null || return 0
  printf '{"ts":"%s","event":"shim-delegate-failed","reason":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >> "${home}/logs/sentinel-shim.ndjson" 2>/dev/null || true
}

# --- bounded stdin read -----------------------------------------------------
# Claude Code writes the PreToolUse envelope then closes the hook's stdin. An
# unbounded read hangs forever if stdin is never closed, which wedges CC's
# synchronous hook-invocation loop. We read stdin in the FOREGROUND with a
# bounded `read -t` (mirrors sentinel-shim.ps1:67-84).
#
# A BACKGROUNDED reader is WRONG here: when job control is off (the non-interactive
# hook process), bash redirects an async list's stdin from /dev/null *before any
# explicit redirection* (POSIX), so a backgrounded `cat` would read /dev/null and
# NEVER capture the real envelope — the hook would get empty stdin and silently
# fail open, governing nothing. `read -r -d ''` consumes the whole envelope (the
# NUL delimiter never appears, so it reads to EOF); on a stdin that never closes,
# `-t` fires (read returns > 128) -> fail OPEN with a populated allow + diagnostic.
stdin_timeout=2          # seconds (~2s budget, parity with PS 2000ms)
stdin_file="$(mktemp 2>/dev/null || echo "${TMPDIR:-/tmp}/sentinel-shim-stdin.$$")"
out_file="$(mktemp 2>/dev/null || echo "${TMPDIR:-/tmp}/sentinel-shim-out.$$")"
# shellcheck disable=SC2329  # invoked indirectly via the EXIT trap below
cleanup() { rm -f "$stdin_file" "$out_file" 2>/dev/null || true; }
trap cleanup EXIT

envelope=""
IFS= read -r -d '' -t "$stdin_timeout" envelope
read_rc=$?
if [ "$read_rc" -gt 128 ]; then
  # Timed out: stdin opened but never closed (no envelope, no EOF).
  diag 'hook-stdin-read-timeout'
  write_allow 'Sentinel connector did not receive input - allowed.'
  exit 0
fi
# read_rc 0 (NUL seen) or 1 (EOF reached) -> envelope holds the full input.
# Persist it for the hook's stdin; delegation uses an explicit `< "$stdin_file"`,
# so the hook's background redirection is correct (unlike a bare async read).
printf '%s' "$envelope" > "$stdin_file"

# --- pre-setup gates --------------------------------------------------------
# Case (a): not configured -> populated allow (NORMAL; no diagnostic).
if [ ! -f "$config" ]; then
  write_allow 'Sentinel not configured - allowed.'
  exit 0
fi
# Case (b): configured but hook exe missing -> populated allow + diagnostic.
if [ ! -x "$hook_exe" ] && [ ! -f "$hook_exe" ]; then
  diag 'hook-exe-missing'
  write_allow 'Sentinel connector not installed - allowed.'
  exit 0
fi

# --- bounded delegation -----------------------------------------------------
# Run the hook exe in the background, feeding the captured envelope on stdin and
# capturing its stdout to a temp file (stderr -> /dev/null so it can never mix
# into the relay). Watchdog-kill after delegate_timeout. On timeout/empty/error
# emit a populated allow + the matching diagnostic. Relay only the FIRST stdout
# line, byte-exact, with a single trailing LF. NO ALLOW rewrite (the exe emits
# the directive at source). Mirrors sentinel-shim.ps1:109-196.
#
# The watchdog signals "timed out" via a marker file (robust against the
# wait/kill race) and escalates SIGTERM -> SIGKILL so a child that ignores TERM
# (or whose `sleep` survives) is still reaped within the budget.
delegate_timeout=3       # seconds (well under the test's 6s bound; PS bounds each phase ~2s)
killed_marker="${out_file}.killed"

"$hook_exe" < "$stdin_file" > "$out_file" 2>/dev/null &
hook_pid=$!
(
  sleep "$delegate_timeout"
  if kill -0 "$hook_pid" 2>/dev/null; then
    : > "$killed_marker"
    kill "$hook_pid" 2>/dev/null
    sleep 1
    kill -9 "$hook_pid" 2>/dev/null
  fi
) &
dwatch_pid=$!

if wait "$hook_pid" 2>/dev/null; then
  hook_rc=0
else
  hook_rc=$?
fi
# Stop the watchdog (it may still be sleeping if the hook finished naturally).
kill "$dwatch_pid" 2>/dev/null
wait "$dwatch_pid" 2>/dev/null
timed_out=0
[ -f "$killed_marker" ] && timed_out=1
rm -f "$killed_marker" 2>/dev/null || true

if [ "$timed_out" -eq 1 ]; then
  diag "hook-timeout-${delegate_timeout}000"
  write_allow 'Sentinel connector warming up or unavailable - allowed.'
  exit 0
fi

# A SIGTERM/SIGKILL exit (>128) without the watchdog firing still means no clean
# decision was produced; treat as an error path (fail open).
if [ "$hook_rc" -gt 128 ]; then
  diag "delegate-threw"
  write_allow 'Sentinel connector error - allowed.'
  exit 0
fi

# Empty stdout -> populated allow + hook-exited-<code>-no-stdout diagnostic.
if [ ! -s "$out_file" ]; then
  diag "hook-exited-${hook_rc}-no-stdout"
  write_allow 'Sentinel connector returned no decision - allowed.'
  exit 0
fi

# Real decision: relay the FIRST stdout line byte-exact + a single trailing LF.
# `head -n 1` strips at the first LF; we re-add exactly one. DENY/ASK/ALLOW are
# all relayed verbatim (no rewrite). If the line is somehow empty, fail open.
first_line="$(head -n 1 "$out_file")"
if [ -z "$first_line" ]; then
  diag "hook-exited-${hook_rc}-no-stdout"
  write_allow 'Sentinel connector returned no decision - allowed.'
  exit 0
fi
printf '%s\n' "$first_line"
exit 0
