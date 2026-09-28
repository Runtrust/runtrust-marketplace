#!/usr/bin/env bash
# plugins/sentinel/test/sentinel-shim.test.sh — mirrors sentinel-shim.Tests.ps1
set -u
SHIM="$(cd "$(dirname "$0")/../hooks" && pwd)/sentinel-shim.sh"
fails=0
assert_match(){ printf '%s' "$1" | grep -q -- "$2" || { echo "FAIL: expected /$2/ in: $1"; fails=$((fails+1)); }; }

# 1) no config.json -> populated allow + exit 0, no diagnostic
home="$(mktemp -d)"
out="$(printf '%s' '{"tool_name":"Read","tool_input":{}}' | bash "$SHIM" --home "$home")"; rc=$?
[ "$rc" -eq 0 ] || { echo "FAIL: exit $rc"; fails=$((fails+1)); }
assert_match "$out" '"permissionDecision":"allow"'
assert_match "$out" 'not configured'
[ -f "$home/logs/sentinel-shim.ndjson" ] && { echo "FAIL: pre-setup logged a diagnostic"; fails=$((fails+1)); }

# 2) config present but exe missing -> populated allow + hook-exe-missing diagnostic
home="$(mktemp -d)"; mkdir -p "$home/bin"; printf '%s' '{"tenantId":"t"}' > "$home/config.json"
out="$(printf '%s' '{"tool_name":"Read","tool_input":{}}' | bash "$SHIM" --home "$home")"; rc=$?
[ "$rc" -eq 0 ] || { echo "FAIL: exit $rc"; fails=$((fails+1)); }
assert_match "$out" 'not installed'
assert_match "$(cat "$home/logs/sentinel-shim.ndjson" 2>/dev/null)" 'hook-exe-missing'

# 3) BYTE-EXACT relay of a real deny: stdout MUST equal "<deny>\n" exactly (file+cmp,
#    NOT command substitution which strips trailing bytes); stderr never in stdout.
home="$(mktemp -d)"; mkdir -p "$home/bin"; printf '%s' '{"tenantId":"t"}' > "$home/config.json"
stub="$home/bin/stub-hook"; deny='{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"stub"}}'
printf '#!/usr/bin/env bash\nprintf "log-line\\n" 1>&2\nprintf "%%s\\n" '"'"'%s'"'"'\n' "$deny" > "$stub"; chmod +x "$stub"
{ printf '%s' "$deny"; printf '\n'; } > "$home/expected.txt"   # exactly <deny> + one LF
printf '%s' '{"tool_name":"Read","tool_input":{}}' | bash "$SHIM" --home "$home" --hook-exe "$stub" > "$home/out.txt" 2> "$home/err.txt"
cmp -s "$home/out.txt" "$home/expected.txt" || { echo "FAIL: relay not byte-exact"; echo "  got : $(od -An -tx1 "$home/out.txt" | tail -2)"; fails=$((fails+1)); }
grep -q 'log-line' "$home/out.txt" && { echo "FAIL: stderr leaked into stdout"; fails=$((fails+1)); }

# 4) bounded delegation: hung hook -> populated allow + timeout diagnostic within budget
home="$(mktemp -d)"; mkdir -p "$home/bin"; printf '%s' '{"tenantId":"t"}' > "$home/config.json"
slow="$home/bin/slow-hook"; printf '#!/usr/bin/env bash\nsleep 11\necho "{}"\n' > "$slow"; chmod +x "$slow"
start=$(date +%s); out="$(printf '%s' '{"tool_name":"Read","tool_input":{}}' | bash "$SHIM" --home "$home" --hook-exe "$slow")"; end=$(date +%s)
[ $((end-start)) -lt 6 ] || { echo "FAIL: delegation not bounded (${start}->${end})"; fails=$((fails+1)); }
assert_match "$out" '"permissionDecision":"allow"'
assert_match "$(cat "$home/logs/sentinel-shim.ndjson" 2>/dev/null)" 'hook-timeout'

# 5) empty-stdout hook -> populated allow + hook-exited diagnostic
home="$(mktemp -d)"; mkdir -p "$home/bin"; printf '%s' '{"tenantId":"t"}' > "$home/config.json"
empty="$home/bin/empty-hook"; printf '#!/usr/bin/env bash\nexit 0\n' > "$empty"; chmod +x "$empty"
out="$(printf '%s' '{"tool_name":"Read","tool_input":{}}' | bash "$SHIM" --home "$home" --hook-exe "$empty")"
assert_match "$out" '"permissionDecision":"allow"'
assert_match "$(cat "$home/logs/sentinel-shim.ndjson" 2>/dev/null)" 'no-stdout'

# 6) BOUNDED STDIN READ (no-unbounded-op parity): stdin stays open with no data ->
#    the shim must self-terminate within budget with a populated allow + stdin-read diag.
home="$(mktemp -d)"; mkdir -p "$home/bin"; printf '%s' '{"tenantId":"t"}' > "$home/config.json"
ehook="$home/bin/echo-hook"; printf '#!/usr/bin/env bash\nprintf "{}\\n"\n' > "$ehook"; chmod +x "$ehook"
start=$(date +%s)
bash "$SHIM" --home "$home" --hook-exe "$ehook" < <(sleep 10) > "$home/o6.txt" 2>/dev/null
end=$(date +%s)
[ $((end-start)) -lt 6 ] || { echo "FAIL: stdin read not bounded ($((end-start))s)"; fails=$((fails+1)); }
assert_match "$(cat "$home/o6.txt")" '"permissionDecision":"allow"'
assert_match "$(cat "$home/logs/sentinel-shim.ndjson" 2>/dev/null)" 'stdin-read'

# 7) ENVELOPE REACHES THE HOOK (regression: a backgrounded reader gets /dev/null
#    when job control is off, so the hook used to receive EMPTY stdin and govern
#    nothing). The stub reads stdin and echoes it inside the decision; assert the
#    real envelope content arrives at the child.
home="$(mktemp -d)"; mkdir -p "$home/bin"; printf '%s' '{"tenantId":"t"}' > "$home/config.json"
rstub="$home/bin/relay-hook"
cat > "$rstub" <<'STUB'
#!/usr/bin/env bash
in="$(cat)"
printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"saw %s"}}\n' "$in"
STUB
chmod +x "$rstub"
out="$(printf '%s' '{"tool_name":"Bash","tool_input":{"x":1}}' | bash "$SHIM" --home "$home" --hook-exe "$rstub")"
assert_match "$out" '"permissionDecision":"deny"'
assert_match "$out" 'tool_name'
assert_match "$out" 'Bash'

# 8) THE HOOK RUNS OUTSIDE THE PROJECT (connector#31): Claude Code starts the shim in the
#    project dir, and a Bun-compiled hook loads .env / bunfig.toml from its cwd. The shim must
#    start the hook in /, which users cannot write. The stub records its pwd.
home="$(mktemp -d)"; mkdir -p "$home/bin" "$home/hostile project"; printf '%s' '{"tenantId":"t"}' > "$home/config.json"
cstub="$home/bin/cwd-hook"
printf '#!/usr/bin/env bash\npwd > "%s"\nprintf "{}\\n"\n' "$home/cwd.txt" > "$cstub"; chmod +x "$cstub"
(cd "$home/hostile project" && printf '%s' '{"tool_name":"Read","tool_input":{}}' | bash "$SHIM" --home "$home" --hook-exe "$cstub" > /dev/null)
got="$(cat "$home/cwd.txt" 2>/dev/null)"
[ "$got" = "/" ] || { echo "FAIL: hook cwd is '$got', want /"; fails=$((fails+1)); }

# 10) A RELATIVE --hook-exe still runs the hook (code review, FIX-31 round 1): the path is
#     taken relative to where the shim was started, before the hook runs in /.
home="$(mktemp -d)"; mkdir -p "$home/bin"; printf '%s' '{"tenantId":"t"}' > "$home/config.json"
rdeny='{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"relative"}}'
printf '#!/usr/bin/env bash\nprintf "%%s\\n" '"'"'%s'"'"'\n' "$rdeny" > "$home/bin/rel-hook"; chmod +x "$home/bin/rel-hook"
out="$(cd "$home" && printf '%s' '{"tool_name":"Read","tool_input":{}}' | bash "$SHIM" --home "$home" --hook-exe bin/rel-hook)"
assert_match "$out" '"permissionDecisionReason":"relative"'

# 9) The Windows shim's equivalent (sentinel-shim.ps1 — its Pester suite runs locally only,
#    so this static check is its CI guard): the hook's ProcessStartInfo runs in System32,
#    read from the OS ([Environment]::SystemDirectory), never from an environment variable.
PS1="$(dirname "$SHIM")/sentinel-shim.ps1"
grep -qF '$psi.WorkingDirectory = [Environment]::SystemDirectory' "$PS1" \
  || { echo "FAIL: sentinel-shim.ps1 does not set \$psi.WorkingDirectory = [Environment]::SystemDirectory"; fails=$((fails+1)); }

# 11) THE WATCHDOG KILLS THE HOOK ITSELF (FIX-31 test-engineer pass): the hook starts as
#     `( cd / && exec "$hook_exe" )`, and the `exec` keeps $! the hook's own PID. On a bash that
#     forks the subshell's last command, a dropped exec leaves $! the subshell's: the watchdog
#     kills that and the timed-out hook lives on. bash 5.2 (this suite's CI bash) elides the
#     fork, so there only the static check can see a dropped exec; macOS's /bin/bash 3.2, which
#     hooks.darwin.json runs, predates the elision — the behavioural check is for it.
home="$(mktemp -d)"; mkdir -p "$home/bin"; printf '%s' '{"tenantId":"t"}' > "$home/config.json"
survived="$home/hook-survived"
printf '#!/usr/bin/env bash\nsleep 5\n: > "%s"\n' "$survived" > "$home/bin/hung-hook"; chmod +x "$home/bin/hung-hook"
printf '%s' '{"tool_name":"Read","tool_input":{}}' | bash "$SHIM" --home "$home" --hook-exe "$home/bin/hung-hook" > /dev/null
sleep 4   # the shim returns at ~3 s; a hook it failed to kill writes its marker at 5 s
[ -f "$survived" ] && { echo "FAIL: the watchdog did not kill the timed-out hook"; fails=$((fails+1)); }
grep -qF '( cd / && exec "$hook_exe" )' "$SHIM" \
  || { echo 'FAIL: sentinel-shim.sh does not start the hook as ( cd / && exec "$hook_exe" )'; fails=$((fails+1)); }

if [ "$fails" -eq 0 ]; then echo "ALL PASS"; exit 0; else echo "$fails FAILED"; exit 1; fi
