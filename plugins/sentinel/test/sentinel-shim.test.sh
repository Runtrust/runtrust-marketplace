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

if [ "$fails" -eq 0 ]; then echo "ALL PASS"; exit 0; else echo "$fails FAILED"; exit 1; fi
