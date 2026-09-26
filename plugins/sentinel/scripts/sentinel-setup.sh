#!/usr/bin/env bash
#
# sentinel-setup.sh — macOS onboarding WRITER (install-token exchange + bound config).
#
# Usage (install token is read from $SENTINEL_INSTALL_TOKEN or stdin — NEVER argv,
# so it cannot leak into `ps`/shell history). --endpoint is MANDATORY and has no
# default (no endpoint, no setup): the console's Install page renders the command with
# --endpoint <its own origin>, so the token is exchanged where it was issued.
#   SENTINEL_INSTALL_TOKEN=tok sentinel-setup.sh --endpoint URL [--home DIR] [--daemon-path PATH] [--force]
#   printf %s "$tok" | sentinel-setup.sh --endpoint URL ...
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

# sentinel_endpoint_normalize <url> — the endpoint rule (Mac connector install, decisions 14
# and 15): an absolute http(s) URL whose host is DNS labels (letters, digits, hyphens; no
# leading or trailing hyphen; at most 63 chars each) with an optional :port; no user info,
# query or fragment; no whitespace or control character anywhere; an optional path. IPv4 and
# bracketed IPv6 literals are refused — they have no DNS label, and the host's first label is
# the `environment` this install writes on every decision. Stricter than the gateway's own
# rule for its SENTINEL_PUBLIC_ENDPOINT (sentinel-server auth-reenroll.ts checks the first
# label's charset and refuses IP literals; this also refuses user info, query/fragment, other
# schemes and malformed labels) — every plan environment's value passes both.
# Prints the URL with its trailing slashes removed; returns 1 with the reason on stderr.
# Bash builtins only (bash 3.2 on stock macOS: the patterns live in variables).
sentinel_endpoint_normalize() {
  local url="$1" rest hostport host port
  local label_re='^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'
  local ipv4_re='^[0-9]+(\.[0-9]+){3}$'
  local port_re='^[0-9]{1,5}$'
  case "$url" in
    *[[:space:][:cntrl:]]*) echo "endpoint must not contain whitespace or control characters: '$url'" >&2; return 1 ;;
  esac
  case "$url" in
    http://* | https://*) ;;
    *) echo "endpoint must be an absolute http(s):// URL, got '$url'" >&2; return 1 ;;
  esac
  rest="${url#*://}"
  case "$rest" in
    *\?* | *\#*) echo "endpoint must not carry a query or fragment: '$url'" >&2; return 1 ;;
  esac
  hostport="${rest%%/*}"
  case "$hostport" in
    *@*) echo "endpoint must not carry user info: '$url'" >&2; return 1 ;;
    \[*) echo "endpoint host is an IP literal and has no DNS label: '$url' — use a hostname" >&2; return 1 ;;
  esac
  host="${hostport%%:*}"
  port=""
  [ "$hostport" = "$host" ] || port="${hostport#*:}"
  if [ -z "$host" ] || ! [[ "$host" =~ $label_re ]]; then
    echo "endpoint host must be a hostname of DNS labels (letters, digits, hyphens): '$url'" >&2; return 1
  fi
  if [[ "$host" =~ $ipv4_re ]]; then
    echo "endpoint host is an IP literal and has no DNS label: '$url' — use a hostname" >&2; return 1
  fi
  if [ "$hostport" != "$host" ]; then
    if ! [[ "$port" =~ $port_re ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
      echo "endpoint port must be 1-65535: '$url'" >&2; return 1
    fi
  fi
  while [ "${url%/}" != "$url" ]; do url="${url%/}"; done
  printf '%s\n' "$url"
}

# sentinel_environment_label <url> — the endpoint host's first DNS label, lowercased: the
# `environment` this install writes (decision 14: eu1 / sentinel-staging / localhost, verbatim
# from the host — no lookup table, no default). Call with a normalized endpoint.
sentinel_environment_label() {
  local host="${1#*://}"
  host="${host%%/*}"; host="${host%%:*}"; host="${host%%.*}"
  printf '%s\n' "$host" | tr '[:upper:]' '[:lower:]'
}

# --- main body (runs only when executed directly, not when sourced for tests) -
if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
  set -euo pipefail

  endpoint=""
  home="${HOME:-/tmp}/.sentinel"
  daemon_path=""

  die() { echo "sentinel-setup: $1" >&2; exit 1; }

  force=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --endpoint | --home | --daemon-path)
        # A value flag with no value is a message, not a silent exit (shift 2 would fail
        # under set -e with nothing said).
        [ "$#" -ge 2 ] || die "$1 needs a value"
        case "$1" in
          --endpoint)    endpoint="$2" ;;
          --home)        home="$2" ;;
          --daemon-path) daemon_path="$2" ;;
        esac
        shift 2 ;;
      --force)         force=1; shift ;;
      *)               echo "sentinel-setup: unknown argument: $1" >&2; exit 2 ;;
    esac
  done

  # --- 0. the endpoint: mandatory, validated, before anything is read or written --------
  # No default (decision 15). Refused here, the script has touched nothing: no home dir,
  # no salt file, no token read.
  [ -n "$endpoint" ] || die "no endpoint given — copy the command from your console's Install page"
  endpoint="$(sentinel_endpoint_normalize "$endpoint")" \
    || die "the --endpoint is not a usable address — copy the command from your console's Install page"

  # Token from env, else stdin. NEVER from argv: a CLI arg would leak the single-use
  # token into `ps` output and shell history. (SentinelCore.psm1 takes -InstallToken
  # as a SecureString-adjacent param; bash has no equivalent, so env/stdin is the
  # safe analogue.)
  install_token="${SENTINEL_INSTALL_TOKEN:-}"
  if [ -z "$install_token" ]; then
    [ -t 0 ] && die "no install token: set SENTINEL_INSTALL_TOKEN or pipe the token on stdin"
    IFS= read -r install_token || true
  fi
  # The token is one word. A wrapping pair of quotes (the console's command pasted as-is)
  # is stripped; whitespace means the whole command line was handed over as the token —
  # refused before the exchange, so a mangled paste never burns the single-use token.
  case "$install_token" in
    \'*\') install_token="${install_token#\'}"; install_token="${install_token%\'}" ;;
    \"*\") install_token="${install_token#\"}"; install_token="${install_token%\"}" ;;
  esac
  case "$install_token" in
    *[[:space:]]* | --*) die "the install token must be a single word — paste the command from your console's Install page as one line" ;;
  esac
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

  # On a failed transfer curl still prints the -w slot (000) and exits non-zero; the
  # override below keeps the code a single 000 (an appended one would read 000000).
  http="$(curl -sS -o "$resp" -w '%{http_code}' --max-time 30 \
    -X POST "${endpoint%/}/v1/install/exchange" \
    -H 'Content-Type: application/json' --data @"$req")" || http="000"
  case "$http" in
    200) ;;
    401) die "the install token was not recognised by $endpoint: expired, already used, or issued by a different RunTrust console — use the command from the console that issued it" ;;
    000) die "could not reach $endpoint (no HTTP response) — check the address and your network, then re-run the command from your console's Install page" ;;
    *)   die "install-token exchange failed at $endpoint (HTTP $http) — 429=rate-limited" ;;
  esac

  # Parse the response using the zero-dep json_str_field helper.
  api_key="$(json_str_field "$resp" apiKey)"
  tenant_id="$(json_str_field "$resp" tenantId)"
  installation_id="$(json_str_field "$resp" installationId)"
  [ -n "$api_key" ] && [ -n "$tenant_id" ] || die "exchange response missing apiKey/tenantId"

  # --- 3. bind the endpoint the service reports (Windows parity: SentinelCore.psm1
  #     Invoke-SentinelSetup binds the response's endpoint). The exchange response's
  #     `endpoint` is the gateway's own SENTINEL_PUBLIC_ENDPOINT; when present it is bound,
  #     validated like --endpoint, and a difference is said on stderr. Absent or unusable,
  #     the already-validated --endpoint is bound — the single-use token is spent by now, so
  #     refusing here would burn it (code review L1); the unusable value is warned about.
  #     The environment label is the BOUND host's first DNS label, so config.json's endpoint
  #     and environment can never disagree (decision 21).
  resp_endpoint="$(json_str_field "$resp" endpoint)"
  bound_endpoint="$endpoint"
  if [ -n "$resp_endpoint" ]; then
    if resp_norm="$(sentinel_endpoint_normalize "$resp_endpoint")"; then
      bound_endpoint="$resp_norm"
      [ "$bound_endpoint" = "$endpoint" ] \
        || echo "sentinel-setup: warning: binding to $bound_endpoint (the address the service reports), not --endpoint $endpoint" >&2
    else
      echo "sentinel-setup: warning: the service at $endpoint reports an endpoint that is not a usable address ('$resp_endpoint'); binding to --endpoint $endpoint instead" >&2
    fi
  fi
  environment="$(sentinel_environment_label "$bound_endpoint")"

  # --- 4. write the full bound config (0600, temp-then-rename) ---------------------
  # config.json holds the JWT (apiKey). Create the temp with 0600 BEFORE writing
  # the secret (no os.open mode arg in bash → use umask 077 in a subshell to create
  # the file, then write, then chmod 600, then mv -f). endpoint and environment are the
  # bound values from step 3.
  # apiKey is kept in a shell var (never on argv); all values are json_escaped.
  mkdir -p "$home/bin"
  cfg_tmp="$home/.config.json.tmp.$$"

  # Create the temp file at 0600 before writing the secret.
  ( umask 077 && : > "$cfg_tmp" )
  chmod 600 "$cfg_tmp"

  ep_esc="$(json_escape "$bound_endpoint")"
  env_esc="$(json_escape "$environment")"
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
  "environment": "%s",
  "installationId": "%s",
  "deviceId": "%s",
  "deviceHostname": "%s"
}\n' \
    "$ep_esc" "$tid_esc" "$ak_esc" "$dp_esc" "$env_esc" "$iid_esc" "$did2_esc" "$hn2_esc" > "$cfg_tmp"

  chmod 600 "$cfg_tmp"
  mv -f "$cfg_tmp" "$home/config.json"

  # Do NOT echo apiKey. Tenant + installation are safe to print for operator confirmation.
  echo "sentinel-setup: bound to tenant '$tenant_id' (installation $installation_id) at $bound_endpoint (environment $environment)"
  echo "sentinel-setup: wrote $home/config.json (chmod 600). Restart Claude Code so the hook spawns the daemon."
fi
