#!/usr/bin/env bash
#
# sentinel-setup.sh — macOS onboarding WRITER (install-token exchange + bound config).
#
# Usage (install token is read from $SENTINEL_INSTALL_TOKEN or stdin — NEVER argv,
# so it cannot leak into `ps`/shell history):
#   SENTINEL_INSTALL_TOKEN=tok sentinel-setup.sh [--endpoint URL] [--home DIR] [--daemon-path PATH]
#   printf %s "$tok" | sentinel-setup.sh [--endpoint URL] ...
#
# Zero-dependency: runs on stock macOS bash with no third-party tools required.

# --- pure helpers (sourceable; defined before set -euo pipefail so the test
#     can source them without the main body running) ---------------------------

# json_escape <str> — produces a JSON-safe string value (without surrounding quotes).
# Escape order is critical: backslash FIRST (so introduced backslashes aren't re-doubled),
# then double-quote, then the three plausible control chars (tab, CR, newline).
# Full \u00XX escaping of all C0 control chars is out of scope — these fields are
# single-line identifiers (token, device-id, hostname); tab/CR/newline are the
# only realistic cases.
# Uses awk so the entire input is processed as one record (no line-by-line mangling),
# which is portable to BSD awk (macOS) and GNU awk / Git Bash.
json_escape() {
  printf '%s' "$1" | awk '
    BEGIN { RS=""; ORS="" }
    {
      gsub(/\\/, "\\\\")
      gsub(/"/, "\\\"")
      gsub(/\t/, "\\t")
      gsub(/\r/, "\\r")
      gsub(/\n/, "\\n")
      print
    }
  '
}

# json_str_field <file> <key> — extracts a flat top-level string field value.
# Matches: "key" : "value" where value contains no embedded double-quotes
# (apiKey/tenantId/installationId are flat strings; apiKey is a JWT with dots,
# dashes, underscores — no embedded quotes).
# Returns empty string if the key is absent.
json_str_field() { sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" | head -n1; }

# --- main body (runs only when executed directly, not when sourced for tests) -
if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
  set -euo pipefail

  endpoint="https://app.runtrust.ai"
  home="${HOME:-/tmp}/.sentinel"
  daemon_path=""

  force=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --endpoint)      endpoint="${2:-}"; shift 2 ;;
      --home)          home="${2:-}"; shift 2 ;;
      --daemon-path)   daemon_path="${2:-}"; shift 2 ;;
      --force)         force=1; shift ;;
      *)               echo "sentinel-setup: unknown argument: $1" >&2; exit 2 ;;
    esac
  done

  die() { echo "sentinel-setup: $1" >&2; exit 1; }

  # Token from env, else stdin. NEVER from argv: a CLI arg would leak the single-use
  # token into `ps` output and shell history. (SentinelCore.psm1 takes -InstallToken
  # as a SecureString-adjacent param; bash has no equivalent, so env/stdin is the
  # safe analogue.)
  install_token="${SENTINEL_INSTALL_TOKEN:-}"
  if [ -z "$install_token" ]; then
    [ -t 0 ] && die "no install token: set SENTINEL_INSTALL_TOKEN or pipe the token on stdin"
    IFS= read -r install_token || true
  fi
  [ -n "$install_token" ] || die "an install token is required (SENTINEL_INSTALL_TOKEN env or stdin)"

  # --- 1b. reinstall guard (--force) -----------------------------------------------
  # Runs BEFORE any device-identity computation or salt-file creation so that a
  # refused reinstall is a true no-op (touches nothing in $home except the config
  # read, which is read-only). If config.json already exists and is bound (non-empty
  # tenantId), abort unless --force was passed. This prevents accidental token
  # re-exchange on a configured machine. With --force the exchange proceeds and the
  # config is overwritten.
  if [ -f "$home/config.json" ]; then
    existing_tenant="$(json_str_field "$home/config.json" tenantId)"
    if [ -n "$existing_tenant" ] && [ "$force" -eq 0 ]; then
      die "already configured for tenant '$existing_tenant'; re-run with --force to reinstall"
    fi
  fi

  # --- device identity (mirrors SentinelCore.psm1 Get-SentinelDeviceId) -----------
  # Primary:  deviceId = 'dev-' + sha256( hostname NUL IOPlatformUUID )
  # Fallback: when ioreg yields no IOPlatformUUID (VM, CI, broken ioreg), derive
  #           deviceId from a persisted random salt at $home/device-salt (created
  #           once at 0600, reused on every subsequent run → stable across re-runs).
  #           deviceId = 'dev-' + sha256( hostname NUL salt )
  # When IOPlatformUUID IS present the salt file is never created or read.
  mkdir -p "$home"
  device_hostname="$(hostname 2>/dev/null || echo unknown)"
  platform_uuid="$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformUUID/{print $4}')"

  if [ -n "$platform_uuid" ]; then
    # Primary path: use the hardware UUID.
    device_id="dev-$(printf '%s\0%s' "$device_hostname" "$platform_uuid" | shasum -a 256 | awk '{print $1}')"
  else
    # Fallback path: read or generate a persisted salt.
    salt_file="$home/device-salt"
    if [ -f "$salt_file" ]; then
      device_salt="$(cat "$salt_file")"
    else
      # Generate a random hex salt (zero-dep: /dev/urandom + shasum).
      device_salt="$(head -c 32 /dev/urandom | shasum -a 256 | awk '{print $1}')"
      # Write at 0600 BEFORE populating: open with restrictive umask so there is
      # no window where the file exists but is world-readable.
      ( umask 177 && printf '%s' "$device_salt" > "$salt_file" )
      chmod 600 "$salt_file"
    fi
    device_id="dev-$(printf '%s\0%s' "$device_hostname" "$device_salt" | shasum -a 256 | awk '{print $1}')"
  fi

  # default daemon path matches the installer's placement
  arch="$(uname -m 2>/dev/null || echo unknown)"
  case "$arch" in arm64 | aarch64) arch="arm64" ;; x86_64 | amd64) arch="x64" ;; *) arch="x64" ;; esac
  [ -n "$daemon_path" ] || daemon_path="$home/bin/sentinel-cc-daemon-darwin-${arch}.bin"

  # --- 2. exchange the install token -----------------------------------------------
  req="$(mktemp)"; resp="$(mktemp)"
  cfg_tmp=""  # will be set below; initialise here so the trap sees a defined variable
  trap 'rm -f "$req" "$resp" "$cfg_tmp"' EXIT
  chmod 600 "$req" "$resp"

  # Build the request body by concatenation with json_escape on each value.
  # Token comes from env/stdin (never argv) — stored in $install_token shell var.
  # The 600 temp keeps the token off `ps` (it is never passed as an argument).
  tok_esc="$(json_escape "$install_token")"
  did_esc="$(json_escape "$device_id")"
  hn_esc="$(json_escape "$device_hostname")"
  printf '{"installToken":"%s","deviceId":"%s","deviceHostname":"%s"}' \
    "$tok_esc" "$did_esc" "$hn_esc" > "$req"

  http="$(curl -sS -o "$resp" -w '%{http_code}' --max-time 30 \
    -X POST "${endpoint%/}/v1/install/exchange" \
    -H 'Content-Type: application/json' --data @"$req" || echo 000)"
  [ "$http" = "200" ] || die "install-token exchange failed (HTTP $http) — 401=expired/used, 429=rate-limited"

  # Parse the response using the zero-dep json_str_field helper.
  api_key="$(json_str_field "$resp" apiKey)"
  tenant_id="$(json_str_field "$resp" tenantId)"
  installation_id="$(json_str_field "$resp" installationId)"
  [ -n "$api_key" ] && [ -n "$tenant_id" ] || die "exchange response missing apiKey/tenantId"

  # --- 4. write the full bound config (0600, temp-then-rename) ---------------------
  # config.json holds the JWT (apiKey). Create the temp with 0600 BEFORE writing
  # the secret (no os.open mode arg in bash → use umask 077 in a subshell to create
  # the file, then write, then chmod 600, then mv -f). endpoint is FORCED to the
  # caller's --endpoint, ignoring any localhost the exchange response echoes.
  # apiKey is kept in a shell var (never on argv); all values are json_escaped.
  mkdir -p "$home/bin"
  cfg_tmp="$home/.config.json.tmp.$$"

  # Create the temp file at 0600 before writing the secret.
  ( umask 077 && : > "$cfg_tmp" )
  chmod 600 "$cfg_tmp"

  ep_esc="$(json_escape "$endpoint")"
  ak_esc="$(json_escape "$api_key")"
  tid_esc="$(json_escape "$tenant_id")"
  dp_esc="$(json_escape "$daemon_path")"
  iid_esc="$(json_escape "$installation_id")"
  did2_esc="$(json_escape "$device_id")"
  hn2_esc="$(json_escape "$device_hostname")"

  printf '{
  "endpoint": "%s",
  "tenantId": "%s",
  "apiKey": "%s",
  "daemonPath": "%s",
  "environment": "prod",
  "installationId": "%s",
  "deviceId": "%s",
  "deviceHostname": "%s"
}\n' \
    "$ep_esc" "$tid_esc" "$ak_esc" "$dp_esc" "$iid_esc" "$did2_esc" "$hn2_esc" > "$cfg_tmp"

  chmod 600 "$cfg_tmp"
  mv -f "$cfg_tmp" "$home/config.json"

  # Do NOT echo apiKey. Tenant + installation are safe to print for operator confirmation.
  echo "sentinel-setup: bound to tenant '$tenant_id' (installation $installation_id) at $endpoint"
  echo "sentinel-setup: wrote $home/config.json (chmod 600). Restart Claude Code so the hook spawns the daemon."
fi
