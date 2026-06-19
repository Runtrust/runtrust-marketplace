[CmdletBinding()]
param(
  [string]$SentinelHome,
  [string]$HookExe
)
# Freeze-proof PreToolUse shim. EVERY path emits a populated wire: a real hook
# decision is relayed exactly (byte-for-byte + single trailing LF); every other
# path (pre-setup, timeout, empty stdout, exception) emits a populated allow via
# Write-AllowWire — never empty stdout (an empty/bare wire hangs CC's model
# loop), and the shim never originates a deny. Delegation is time-boxed (each
# phase bounded at $timeoutMs). See docs/system/cc-plugin.md.
$ErrorActionPreference = 'Continue'   # hook logs to stderr; must not abort the relay

# FIX 1: Force UTF-8 (no BOM) for the relay round-trip. Decoding of the hook's
# stdout bytes is governed by ProcessStartInfo.StandardOutputEncoding (set to
# $utf8NoBom below); [Console]::OutputEncoding governs how [Console]::Out.Write
# re-encodes back to bytes. Both must be UTF-8 for round-trip fidelity of
# non-ASCII characters (e.g. em-dash U+2014 in permissionDecisionReason on the
# unconditional-block path). $OutputEncoding is kept for any future PS-native
# capture but no longer drives the relay path.
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom

if (-not $SentinelHome -or $SentinelHome -eq '') {
  $base = if ($env:USERPROFILE) { $env:USERPROFILE } elseif ($env:HOME) { $env:HOME } else { $HOME }
  $SentinelHome = Join-Path $base '.sentinel'
}
if (-not $HookExe -or $HookExe -eq '') {
  # PS 5.1 Join-Path takes only Path + ChildPath; nest to build a 3-segment path.
  $HookExe = Join-Path (Join-Path $SentinelHome 'bin') 'sentinel-cc-hook-win-x64.exe'
}
$config = Join-Path $SentinelHome 'config.json'

function Write-ShimDiag([string]$reason) {
  try {
    $logDir = Join-Path $SentinelHome 'logs'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Force $logDir | Out-Null }
    $line = (@{ ts = (Get-Date).ToUniversalTime().ToString('o'); event = 'shim-delegate-failed'; reason = $reason } | ConvertTo-Json -Compress)
    # FIX 2: Use UTF-8 (no BOM) for the NDJSON diagnostic log; Add-Content defaults to
    # ANSI on PS 5.1 which would corrupt non-ASCII in future reason strings.
    [System.IO.File]::AppendAllText((Join-Path $logDir 'sentinel-shim.ndjson'), $line + "`n", (New-Object System.Text.UTF8Encoding($false)))
  } catch { }   # diagnostics are best-effort; never break the hook
}

function Write-AllowWire([string]$context) {
  # Populated allow wire (never an empty/bare wire that hangs CC's loop). ASCII context.
  $obj = [ordered]@{ hookSpecificOutput = [ordered]@{ hookEventName = 'PreToolUse'; permissionDecision = 'allow'; additionalContext = $context } }
  [Console]::Out.Write((ConvertTo-Json $obj -Compress -Depth 5))
  [Console]::Out.Write("`n")
}

# Read all of stdin (the PreToolUse JSON envelope) with a BOUNDED wait. Claude
# Code writes the envelope then closes the hook's stdin; an unbounded
# [Console]::In.ReadToEnd() hangs forever if CC ever fails to close stdin, which
# wedges the VSCode panel's synchronous hook-invocation loop — the Stop button
# stops responding and only a window reload recovers (hard-wedge variant of
# docs/risks/active/2026-06-12-cc-plugin-model-loop-stalls.md; upstream
# precedent anthropics/claude-code#67948 — a synchronous op blocking the
# extension event loop). We read via OpenStandardInput()+StreamReader rather
# than [Console]::In because the latter's SyncTextReader runs ReadToEndAsync
# SYNCHRONOUSLY on .NET Framework (no timeout benefit); the StreamReader over the
# raw stream offloads the blocking read so Wait($timeoutMs) unblocks our main
# thread. On timeout/error: fail OPEN with a populated allow + diagnostic (never
# originate a deny, never emit a bare wire). Mirrors the child-phase bounding
# below; the shim then has NO unbounded operation anywhere.
$stdinReadTimeoutMs = 2000
$stdin = ''
try {
  $stdinStream = [Console]::OpenStandardInput()
  $stdinReader = New-Object System.IO.StreamReader($stdinStream, $utf8NoBom)
  $stdinReadTask = $stdinReader.ReadToEndAsync()
  if ($stdinReadTask.Wait($stdinReadTimeoutMs)) {
    $stdin = $stdinReadTask.Result
  } else {
    Write-ShimDiag 'hook-stdin-read-timeout'
    Write-AllowWire 'Sentinel connector did not receive input - allowed.'
    exit 0
  }
} catch {
  Write-ShimDiag ('hook-stdin-read-error: ' + $_.Exception.Message)
  Write-AllowWire 'Sentinel connector could not read input - allowed.'
  exit 0
}
if ($null -eq $stdin) { $stdin = '' }

# Pre-setup gate (case a): not configured -> populated allow (NORMAL; no diagnostic).
if (-not (Test-Path $config)) { Write-AllowWire 'Sentinel not configured - allowed.'; exit 0 }
# Pre-setup gate (case b): configured but hook exe missing -> populated allow + diagnostic (degraded).
if (-not (Test-Path $HookExe)) { Write-ShimDiag 'hook-exe-missing'; Write-AllowWire 'Sentinel connector not installed - allowed.'; exit 0 }

# Derive CLAUDE_PROJECT_DIR from the envelope cwd when the host did NOT export it.
# Claude Code's VSCode extension does not propagate CLAUDE_PROJECT_DIR to the plugin
# hook's child process; without it the hook exe exits 2 with no stdout, so governance
# silently no-ops (the empty-stdout branch below fails open with a populated allow —
# before the bounded-delegation fix this surfaced as an empty/bare wire that stalled
# CC's loop). We already hold the full stdin envelope, so parse it defensively (never
# throw) and set the env var only when cwd is a non-empty string. A host-supplied
# value always wins (no overwrite).
if (-not $env:CLAUDE_PROJECT_DIR) {
  try {
    $cwd = ($stdin | ConvertFrom-Json).cwd
    if ($cwd -is [string] -and $cwd.Trim().Length -gt 0) {
      $env:CLAUDE_PROJECT_DIR = $cwd
    }
  } catch { }   # malformed envelope -> skip derivation, delegate as today (fail-open)
}

# Bounded delegation: a hung/cold daemon must never freeze CC's loop. Relay a real
# decision EXACTLY; on timeout/empty/exception emit a populated allow (never empty,
# never originate a deny). Each phase (stdin write, WaitForExit) is bounded at
# $timeoutMs, so worst-case end-to-end is ~2x$timeoutMs + kill overhead (~4.5s) —
# bounded either way, the freeze-proof property is per-phase, not a single budget.
# PS 5.1/.NET Framework: .Arguments STRING only (no ArgumentList).
$timeoutMs = 2000
try {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  if ($HookExe -match '\.(cmd|bat)$') {
    $psi.FileName = $env:ComSpec            # cmd.exe — .cmd/.bat are not CreateProcess-executable
    # Double-outer-quote form handles paths with spaces (cmd /d /s /c ""path"").
    $psi.Arguments = '/d /s /c ""' + $HookExe + '""'
  } else {
    $psi.FileName = $HookExe                 # production single-file .exe — direct
    $psi.Arguments = ''
  }
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.StandardOutputEncoding = $utf8NoBom
  $psi.StandardErrorEncoding = $utf8NoBom

  $proc = [System.Diagnostics.Process]::Start($psi)
  # Drain BOTH pipes async BEFORE waiting (a full pipe buffer would deadlock WaitForExit).
  $outTask = $proc.StandardOutput.ReadToEndAsync()
  $errTask = $proc.StandardError.ReadToEndAsync()   # drained + discarded (kept out of relay)
  # Bounded stdin write: a child that never reads stdin must not block us past the
  # timeout. Write raw UTF-8 bytes to the base stream async and cap the wait at $timeoutMs.
  $inBytes = [System.Text.Encoding]::UTF8.GetBytes($stdin)
  $writeTask = $proc.StandardInput.BaseStream.WriteAsync($inBytes, 0, $inBytes.Length)
  if (-not $writeTask.Wait($timeoutMs)) {
    try { $proc.Kill() } catch { }
    try { [void]$proc.WaitForExit(250) } catch { }
    Write-ShimDiag 'hook-stdin-write-timeout'
    Write-AllowWire 'Sentinel connector not reading input - allowed.'
    exit 0
  }
  try { $proc.StandardInput.BaseStream.Flush() } catch { }
  $proc.StandardInput.Close()

  if (-not $proc.WaitForExit($timeoutMs)) {
    try { $proc.Kill() } catch { }
    try { [void]$proc.WaitForExit(250) } catch { }   # bounded; never block on the read tasks
    Write-ShimDiag 'hook-timeout-2000'
    Write-AllowWire 'Sentinel connector warming up or unavailable - allowed.'
    exit 0
  }

  # Normal exit -> the stdout pipe is closed, so reading the drained task is safe.
  $code = $proc.ExitCode
  $text = $outTask.Result
  if ($null -eq $text) { $text = '' }
  if ($text.Length -eq 0) {
    Write-ShimDiag ("hook-exited-" + $code + "-no-stdout")
    Write-AllowWire 'Sentinel connector returned no decision - allowed.'
    exit 0
  }
  # FIX 5 (continuation directive): on routine ALLOW decisions, rewrite the hook's
  # additionalContext from a wrap-up-sounding summary ("Sentinel evaluated and
  # allowed...") into an explicit keep-going directive. The injected per-call notice
  # was observed (live, 2026-06-10) stalling CC's model loop mid-task — the model
  # reads the summary as an end-of-turn cue. Wording inside documented fields is
  # part of the contract when an LLM is the consumer. DENY/ASK wires are relayed
  # byte-exact and untouched; any parse hiccup relays the original exactly.
  try {
    if ($text -match '"permissionDecision"\s*:\s*"allow"') {
      $wire = $text | ConvertFrom-Json
      if ($wire.hookSpecificOutput -and $wire.hookSpecificOutput.permissionDecision -eq 'allow') {
        $wire.hookSpecificOutput.additionalContext = 'Sentinel: allowed. Continue the task - this notice is informational, not a stopping point.'
        $text = (ConvertTo-Json $wire -Compress -Depth 10) + "`n"
      }
    }
  } catch { }   # fall through with the original $text untouched
  # Real decision: relay (single trailing LF; no CRLF translation). DENY/ASK are
  # byte-exact; ALLOW may carry the rewritten continuation directive above.
  # FIX 4: [Console]::Out.Write("`n") emits a literal LF byte — there is no console
  # CRLF translation on the pipe. Claude Code's Node reader (readline + JSON.parse)
  # handles a trailing LF fine.
  [Console]::Out.Write($text)
  if (-not $text.EndsWith("`n")) { [Console]::Out.Write("`n") }
  exit 0
} catch {
  Write-ShimDiag ("delegate-threw: " + $_.Exception.Message)
  Write-AllowWire 'Sentinel connector error - allowed.'
  exit 0   # shim-layer fail-open: never originate a deny
}
