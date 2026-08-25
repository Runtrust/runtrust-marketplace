[CmdletBinding()]
param(
  [string]$SentinelHome,
  [string]$HookExe,
  # TEST-ONLY: never passed by CC's hooks.json command line; forces the scrub fail-open path for the Pester fail-open test.
  [switch]$SelfTestScrubThrow
)
# Freeze-proof PreToolUse shim. EVERY path emits a populated wire: a real hook
# decision is relayed exactly (byte-for-byte + single trailing LF); every other
# path (pre-setup, timeout, empty stdout, exception) emits a populated allow via
# Write-AllowWire — never empty stdout (an empty/bare wire hangs CC's model
# loop), and the shim never originates a deny. Delegation is time-boxed (each
# phase bounded at $timeoutMs). See Sentinel-AI:docs/system/cc-plugin.md.
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

function Clear-InheritableHandles {
  # Clear HANDLE_FLAG_INHERIT on every inheritable handle this process holds, so
  # the hook (and the daemon it later spawns) inherit no stray duplicate of CC's
  # stdout pipe (the cold-spawn freeze). Comprehensive scrub — the prior
  # single-std-handle SetHandleInformation attempt missed the [Console]::Out
  # DUPLICATE; scrubbing all handles catches it (Phase 0 verified). P/Invoke via
  # Reflection.Emit, NOT Add-Type (Add-Type spawns the persistent VBCSCompiler,
  # which itself inherits the pipe and would defeat the scrub).
  # Test seam (no production effect unless explicitly set): driven by the
  # -SelfTestScrubThrow switch param (NOT an env var, which could leak from a
  # user's shell profile into a real CC invocation and silently disable the
  # scrub). Forces the documented fail-open path so the handle-scrub-failed
  # diagnostic + relay-survives behavior is testable against the REAL
  # (child-process) shim — the Pester harness spawns the shim, so a function
  # stub in the parent test scope cannot reach Clear-InheritableHandles.
  if ($SelfTestScrubThrow) { throw 'scrub-selftest-forced-failure' }
  $asm = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
    (New-Object Reflection.AssemblyName('SentinelHandleScrub')),
    [Reflection.Emit.AssemblyBuilderAccess]::Run)
  $mod = $asm.DefineDynamicModule('m', $false)
  $tb = $mod.DefineType('K32', 'Public, Class')
  $get = $tb.DefinePInvokeMethod('GetHandleInformation', 'kernel32.dll',
    'Public, Static', [Reflection.CallingConventions]::Standard,
    [bool], @([IntPtr], [uint32].MakeByRefType()),
    [Runtime.InteropServices.CallingConvention]::Winapi,
    [Runtime.InteropServices.CharSet]::Auto)
  $get.SetImplementationFlags($get.GetMethodImplementationFlags() -bor [Reflection.MethodImplAttributes]::PreserveSig)
  $set = $tb.DefinePInvokeMethod('SetHandleInformation', 'kernel32.dll',
    'Public, Static', [Reflection.CallingConventions]::Standard,
    [bool], @([IntPtr], [uint32], [uint32]),
    [Runtime.InteropServices.CallingConvention]::Winapi,
    [Runtime.InteropServices.CharSet]::Auto)
  $set.SetImplementationFlags($set.GetMethodImplementationFlags() -bor [Reflection.MethodImplAttributes]::PreserveSig)
  $k = $tb.CreateType()
  # Windows handle values are small multiples of 4. Sweep a generous, bounded
  # range (measured < ~200ms; the shim already budgets seconds) and clear inherit.
  for ($h = 4; $h -le 0x10000; $h += 4) {
    $flags = [uint32]0
    $ptr = [IntPtr]$h
    if ($k::GetHandleInformation($ptr, [ref]$flags)) {
      if (($flags -band 1) -ne 0) { [void]$k::SetHandleInformation($ptr, [uint32]1, [uint32]0) }
    }
  }
}

# Read all of stdin (the PreToolUse JSON envelope) with a BOUNDED wait. Claude
# Code writes the envelope then closes the hook's stdin; an unbounded
# [Console]::In.ReadToEnd() hangs forever if CC ever fails to close stdin, which
# wedges the VSCode panel's synchronous hook-invocation loop — the Stop button
# stops responding and only a window reload recovers (hard-wedge variant of
# Sentinel-AI:docs/risks/active/2026-06-12-cc-plugin-model-loop-stalls.md; upstream
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
# never originate a deny). THREE sequential phases are each bounded: stdin write
# ($timeoutMs=2000), WaitForExit ($timeoutMs=2000), and the post-exit stdout line read
# ($readBudgetMs=1500, added with the 2026-06-26 bounded-read (shim internal block)),
# so worst-case end-to-end is ~2x$timeoutMs + $readBudgetMs + kill overhead (~5.5s) —
# bounded either way; the freeze-proof property is per-phase, not a single budget.
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

  try { Clear-InheritableHandles } catch { Write-ShimDiag ('handle-scrub-failed: ' + $_.Exception.Message) }
  $proc = [System.Diagnostics.Process]::Start($psi)
  # Read ONE stdout line async BEFORE waiting (a full pipe buffer would deadlock
  # WaitForExit). The hook writes exactly one newline-terminated JSON decision line
  # then exits; ReadLineAsync returns as soon as that line is buffered — it does NOT
  # wait for stdout EOF. This bounds the SHIM's internal stdout read (the 2026-06-26
  # partial fix); the COMPLETE cold-spawn freeze fix — preventing the daemon from
  # inheriting/holding CC's stdout pipe — is Clear-InheritableHandles called above
  # before the spawn (see Sentinel-AI:docs/changes/2026-06-29-cc-coldspawn-handle-scrub.md).
  # (stderr is still drained via ReadToEndAsync but never awaited — a fire-and-forget
  # drain; if the daemon also holds the stderr pipe, that dangling task is abandoned
  # on exit and never blocks the shim.)
  $outTask = $proc.StandardOutput.ReadLineAsync()
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

  # Normal exit. BOUND the line read at $readBudgetMs: even after the hook process
  # exits, a detached grandchild (the daemon) may still hold the stdout pipe
  # write-end, so ReadLineAsync could block on an EOF that never arrives. The
  # decision line is already buffered the instant the hook wrote it, so this
  # completes immediately on the happy path; only a hook that exited WITHOUT writing
  # a line AND left the pipe held hits the bound -> fail OPEN (populated allow +
  # diagnostic). The shim exits immediately on timeout, abandoning the dangling read.
  $code = $proc.ExitCode
  $readBudgetMs = 1500
  if (-not $outTask.Wait($readBudgetMs)) {
    Write-ShimDiag 'hook-stdout-read-timeout'
    Write-AllowWire 'Sentinel connector stdout not closed - allowed.'
    exit 0
  }
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
