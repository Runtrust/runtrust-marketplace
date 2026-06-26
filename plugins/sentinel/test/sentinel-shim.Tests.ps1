BeforeAll {
  # PS 5.1 Join-Path takes only Path + ChildPath; nest to build a 3-segment path.
  $script:Shim = Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'hooks') 'sentinel-shim.ps1'
}

Describe 'sentinel-shim pre-setup gate' {
  It 'emits populated allow wire and exit 0 when ~/.sentinel/config.json is absent' {
    $testHome = Join-Path ([System.IO.Path]::GetTempPath()) ("shim-nohome-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Force $testHome | Out-Null
    # Real-process invocation (matches how Claude Code runs the hook; the shim
    # reads stdin via [Console]::In, which only exists for a real process).
    $out = '{"tool_name":"Read","tool_input":{}}' | & 'powershell' -NoProfile -ExecutionPolicy Bypass -File $Shim -SentinelHome $testHome
    $LASTEXITCODE | Should -Be 0
    ($out | Out-String) | Should -Match 'permissionDecision":"allow"'
    ($out | Out-String) | Should -Match 'Sentinel not configured - allowed.'
  }

  It 'emits populated allow wire and exit 0 when config exists but hook exe is absent (and logs a diagnostic)' {
    $testHome = Join-Path ([System.IO.Path]::GetTempPath()) ("shim-noexe-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Force (Join-Path $testHome 'bin') | Out-Null
    Set-Content -Path (Join-Path $testHome 'config.json') -Value '{"tenantId":"t"}' -NoNewline
    $out = '{"tool_name":"Read","tool_input":{}}' | & 'powershell' -NoProfile -ExecutionPolicy Bypass -File $Shim -SentinelHome $testHome
    $LASTEXITCODE | Should -Be 0
    ($out | Out-String) | Should -Match 'Sentinel connector not installed - allowed.'
    (Get-Content -Raw (Join-Path (Join-Path $testHome 'logs') 'sentinel-shim.ndjson')) | Should -Match 'hook-exe-missing'
  }
}

Describe 'sentinel-shim delegation (exact relay)' {
  It 'relays the hook exe stdout EXACTLY (byte-for-byte line) and never mixes stderr' {
    $testHome = Join-Path ([System.IO.Path]::GetTempPath()) ("shim-ok-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Force (Join-Path $testHome 'bin') | Out-Null
    Set-Content -Path (Join-Path $testHome 'config.json') -Value '{"tenantId":"t"}' -NoNewline
    $stub = Join-Path (Join-Path $testHome 'bin') 'stub-hook.cmd'
    $expected = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"stub"}}'
    # PS 5.1: force ASCII (no BOM) so the .cmd parses correctly.
    Set-Content -Encoding ascii -Path $stub -Value @"
@echo off
echo log-line 1>&2
echo $expected
"@
    $outFile = Join-Path $testHome 'out.txt'; $errFile = Join-Path $testHome 'err.txt'
    $psi = '{"tool_name":"Read","tool_input":{}}'
    $psi | & 'powershell' -NoProfile -ExecutionPolicy Bypass -File $Shim -SentinelHome $testHome -HookExe $stub 1>$outFile 2>$errFile
    $LASTEXITCODE | Should -Be 0
    (Get-Content -Raw $outFile).Trim() | Should -BeExactly $expected
    (Get-Content -Raw $outFile) | Should -Not -Match 'log-line'
  }

  It 'relays non-ASCII (em-dash U+2014) in permissionDecisionReason without corruption (UTF-8 relay fidelity)' {
    # FIX 1 regression test: the shim forces $OutputEncoding and [Console]::OutputEncoding
    # to UTF-8 (no BOM) so a real hook exe that emits em-dash (U+2014) in its JSON survives
    # the PS 5.1 capture->string->Console::Out.Write round-trip intact.
    #
    # Harness note: PS 5.1's '>' redirection captures child stdout by decoding via the
    # PARENT's $OutputEncoding (not the child's), so 1>$outFile silently corrupts the
    # em-dash regardless of FIX 1. We therefore use System.Diagnostics.Process with
    # StandardOutputEncoding=UTF8 to capture the shim's raw bytes correctly -- this is
    # the only reliable in-harness approach. Production (Claude Code's Node reader) reads
    # the raw bytes directly, so the test accurately models the real consumer.
    $emDash = [char]0x2014
    $testHome = Join-Path ([System.IO.Path]::GetTempPath()) ("shim-utf8-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Force (Join-Path $testHome 'bin') | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $testHome 'config.json'), '{"tenantId":"t"}', (New-Object System.Text.UTF8Encoding($false)))

    # The stub invokes powershell -Command to write raw UTF-8 bytes to stdout -- the only
    # reliable way to emit non-ASCII from a .cmd on PS 5.1 without depending on the
    # console codepage. The JSON payload (containing em-dash) is base64-encoded so the
    # .cmd file itself needs only pure-ASCII characters.
    $stub = Join-Path (Join-Path $testHome 'bin') 'stub-utf8-hook.cmd'
    $jsonPayload = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"blocked' + $emDash + 'reason"}}'
    $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonPayload)
    $payloadB64 = [Convert]::ToBase64String($payloadBytes)
    $line2 = 'powershell -NoProfile -Command "[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);[Console]::Out.Write([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''' + $payloadB64 + ''')))"'
    [System.IO.File]::WriteAllText($stub, "@echo off`r`n$line2`r`n", (New-Object System.Text.UTF8Encoding($false)))

    # Launch shim via System.Diagnostics.Process with StandardOutputEncoding=UTF-8 so the
    # raw UTF-8 bytes the shim writes to stdout are decoded correctly by the test harness.
    $procInfo = New-Object System.Diagnostics.ProcessStartInfo
    $procInfo.FileName = 'powershell'
    $procInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$Shim`" -SentinelHome `"$testHome`" -HookExe `"$stub`""
    $procInfo.UseShellExecute = $false
    $procInfo.RedirectStandardInput = $true
    $procInfo.RedirectStandardOutput = $true
    $procInfo.RedirectStandardError = $true
    $procInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $proc = [System.Diagnostics.Process]::Start($procInfo)
    $proc.StandardInput.Write('{"tool_name":"Read","tool_input":{}}')
    $proc.StandardInput.Close()
    $relayed = $proc.StandardOutput.ReadToEnd().Trim()
    $proc.WaitForExit()

    $proc.ExitCode | Should -Be 0
    $relayed | Should -Match 'permissionDecision":"deny"'
    # Assert that the em-dash (U+2014) survived the relay without corruption.
    # If FIX 1 ($OutputEncoding + [Console]::OutputEncoding = UTF-8 no BOM) were absent,
    # PS 5.1 would decode the child exe's UTF-8 stdout via the OEM codepage, corrupting
    # U+2014 (so .Contains() would return $false).
    # NOTE: [regex]::Escape([char]0x2014) is unreliable in PS 5.1 (maps to '-'); use
    # .Contains() -- this is a REAL assertion, not downgraded.
    $relayed.Contains($emDash) | Should -Be $true
  }
}

Describe 'sentinel-shim CLAUDE_PROJECT_DIR derivation' {
  BeforeAll {
    $script:savedCpd = $env:CLAUDE_PROJECT_DIR

    function script:New-EnvProbeStub($stubHome) {
      New-Item -ItemType Directory -Force (Join-Path $stubHome 'bin') | Out-Null
      [System.IO.File]::WriteAllText((Join-Path $stubHome 'config.json'), '{"tenantId":"t"}', (New-Object System.Text.UTF8Encoding($false)))
      $stub  = Join-Path (Join-Path $stubHome 'bin') 'env-probe-hook.cmd'
      $probe = Join-Path $stubHome 'cpd-seen.txt'
      $body = "@echo off`r`necho.%CLAUDE_PROJECT_DIR%>`"$probe`"`r`necho {""hookSpecificOutput"":{""hookEventName"":""PreToolUse"",""permissionDecision"":""allow"",""additionalContext"":""ok""}}`r`n"
      [System.IO.File]::WriteAllText($stub, $body, (New-Object System.Text.UTF8Encoding($false)))
      return @{ Stub = $stub; Probe = $probe }
    }
  }
  AfterAll {
    if ($null -eq $script:savedCpd) { Remove-Item Env:CLAUDE_PROJECT_DIR -ErrorAction SilentlyContinue }
    else { $env:CLAUDE_PROJECT_DIR = $script:savedCpd }
  }

  It 'derives CLAUDE_PROJECT_DIR from envelope cwd when the parent env var is unset' {
    $testHome = Join-Path ([System.IO.Path]::GetTempPath()) ("shim-cpd-derive-" + [guid]::NewGuid())
    $s = New-EnvProbeStub $testHome
    try {
      Remove-Item Env:CLAUDE_PROJECT_DIR -ErrorAction SilentlyContinue
      $stdinJson = '{"tool_name":"Read","tool_input":{},"cwd":"C:\\proj\\derived"}'
      $out = $stdinJson | & 'powershell' -NoProfile -ExecutionPolicy Bypass -File $Shim -SentinelHome $testHome -HookExe $s.Stub
      $LASTEXITCODE | Should -Be 0
      (Get-Content -Raw $s.Probe) | Should -Match 'C:\\proj\\derived'
      ($out | Out-String) | Should -Match 'permissionDecision'
    } finally {
      Remove-Item Env:CLAUDE_PROJECT_DIR -ErrorAction SilentlyContinue
    }
  }

  It 'does NOT overwrite an already-set CLAUDE_PROJECT_DIR (host precedence)' {
    $testHome = Join-Path ([System.IO.Path]::GetTempPath()) ("shim-cpd-precede-" + [guid]::NewGuid())
    $s = New-EnvProbeStub $testHome
    try {
      $env:CLAUDE_PROJECT_DIR = 'C:\parent\wins'
      $stdinJson = '{"tool_name":"Read","tool_input":{},"cwd":"C:\\proj\\should-be-ignored"}'
      $out = $stdinJson | & 'powershell' -NoProfile -ExecutionPolicy Bypass -File $Shim -SentinelHome $testHome -HookExe $s.Stub
      $LASTEXITCODE | Should -Be 0
      $seen = Get-Content -Raw $s.Probe
      $seen | Should -Match 'C:\\parent\\wins'
      $seen | Should -Not -Match 'should-be-ignored'
      ($out | Out-String) | Should -Match 'permissionDecision'
    } finally {
      Remove-Item Env:CLAUDE_PROJECT_DIR -ErrorAction SilentlyContinue
    }
  }

  It 'preserves fail-open + hook-exited-2 diagnostic when no cwd and no env var' {
    $testHome = Join-Path ([System.IO.Path]::GetTempPath()) ("shim-cpd-noexit-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Force (Join-Path $testHome 'bin') | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $testHome 'config.json'), '{"tenantId":"t"}', (New-Object System.Text.UTF8Encoding($false)))
    $stub = Join-Path (Join-Path $testHome 'bin') 'exit2-hook.cmd'
    [System.IO.File]::WriteAllText($stub, "@echo off`r`nexit /b 2`r`n", (New-Object System.Text.UTF8Encoding($false)))
    try {
      Remove-Item Env:CLAUDE_PROJECT_DIR -ErrorAction SilentlyContinue
      $stdinJson = '{"tool_name":"Read","tool_input":{}}'
      $out = $stdinJson | & 'powershell' -NoProfile -ExecutionPolicy Bypass -File $Shim -SentinelHome $testHome -HookExe $stub
      $LASTEXITCODE | Should -Be 0
      ($out | Out-String) | Should -Match 'permissionDecision":"allow"'
      ($out | Out-String) | Should -Match 'returned no decision'
      (Get-Content -Raw (Join-Path (Join-Path $testHome 'logs') 'sentinel-shim.ndjson')) | Should -Match 'hook-exited-2-no-stdout'
    } finally {
      Remove-Item Env:CLAUDE_PROJECT_DIR -ErrorAction SilentlyContinue
    }
  }

  It 'does not throw on malformed envelope JSON and still delegates' {
    $testHome = Join-Path ([System.IO.Path]::GetTempPath()) ("shim-cpd-malformed-" + [guid]::NewGuid())
    $s = New-EnvProbeStub $testHome
    try {
      Remove-Item Env:CLAUDE_PROJECT_DIR -ErrorAction SilentlyContinue
      $stdinJson = 'not json{ broken'
      $out = $stdinJson | & 'powershell' -NoProfile -ExecutionPolicy Bypass -File $Shim -SentinelHome $testHome -HookExe $s.Stub
      $LASTEXITCODE | Should -Be 0
      ($out | Out-String) | Should -Match 'permissionDecision'
    } finally {
      Remove-Item Env:CLAUDE_PROJECT_DIR -ErrorAction SilentlyContinue
    }
  }
}

Describe 'sentinel-shim freeze-proof delegation' {
  BeforeAll {
    function script:Invoke-Shim($shim,$shimHome,$hookExe,$stdinJson) {
      $psi = New-Object System.Diagnostics.ProcessStartInfo
      $psi.FileName='powershell'
      $psi.Arguments="-NoProfile -ExecutionPolicy Bypass -File `"$shim`" -SentinelHome `"$shimHome`" -HookExe `"$hookExe`""
      $psi.UseShellExecute=$false; $psi.RedirectStandardInput=$true; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true
      $psi.StandardOutputEncoding=[System.Text.Encoding]::UTF8
      $sw=[System.Diagnostics.Stopwatch]::StartNew()
      $p=[System.Diagnostics.Process]::Start($psi)
      $o=$p.StandardOutput.ReadToEndAsync(); $e=$p.StandardError.ReadToEndAsync()
      $p.StandardInput.Write($stdinJson); $p.StandardInput.Close()
      $p.WaitForExit(); $sw.Stop()
      [pscustomobject]@{ Out=$o.Result; Exit=$p.ExitCode; Ms=$sw.ElapsedMilliseconds }
    }
  }

  It 'times out a hung hook within the budget, kills it, emits populated allow + diagnostic' -Tag 'timeout' {
    $h=Join-Path ([IO.Path]::GetTempPath()) ("shim to "+[guid]::NewGuid()); New-Item -ItemType Directory -Force (Join-Path $h 'bin')|Out-Null
    [IO.File]::WriteAllText((Join-Path $h 'config.json'),'{"tenantId":"t"}',(New-Object Text.UTF8Encoding($false)))
    $done=Join-Path $h 'done.marker'
    $stub=Join-Path (Join-Path $h 'bin') 'slow-hook.cmd'
    [IO.File]::WriteAllText($stub, "@echo off`r`nping -n 11 127.0.0.1 >nul`r`necho done> `"$done`"`r`necho {}`r`n",(New-Object Text.UTF8Encoding($false)))
    $r=Invoke-Shim $Shim $h $stub '{"tool_name":"Read","tool_input":{}}'
    $r.Exit | Should -Be 0
    $r.Ms | Should -BeLessThan 5000
    ($r.Out) | Should -Match 'permissionDecision":"allow"'
    ($r.Out) | Should -Match 'warming up or unavailable'
    (Test-Path $done) | Should -Be $false
    (Get-Content -Raw (Join-Path (Join-Path $h 'logs') 'sentinel-shim.ndjson')) | Should -Match 'hook-timeout-2000'
  }

  It 'rewrites ALLOW additionalContext into the continuation directive (FIX 5)' {
    $h=Join-Path ([IO.Path]::GetTempPath()) ("shim allowctx "+[guid]::NewGuid()); New-Item -ItemType Directory -Force (Join-Path $h 'bin')|Out-Null
    [IO.File]::WriteAllText((Join-Path $h 'config.json'),'{"tenantId":"t"}',(New-Object Text.UTF8Encoding($false)))
    $stub=Join-Path (Join-Path $h 'bin') 'allow-hook.cmd'
    $allow='{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"Sentinel evaluated and allowed this Read call by policy."}}'
    [IO.File]::WriteAllText($stub,"@echo off`r`necho $allow`r`n",(New-Object Text.UTF8Encoding($false)))
    $r=Invoke-Shim $Shim $h $stub '{"tool_name":"Read","tool_input":{}}'
    $r.Exit | Should -Be 0
    ($r.Out) | Should -Match 'permissionDecision":"allow"'
    ($r.Out) | Should -Match 'Continue the task'
    ($r.Out) | Should -Not -Match 'evaluated and allowed'
  }

  It 'relays a real DENY exactly (never masked by allow)' {
    $h=Join-Path ([IO.Path]::GetTempPath()) ("shim deny "+[guid]::NewGuid()); New-Item -ItemType Directory -Force (Join-Path $h 'bin')|Out-Null
    [IO.File]::WriteAllText((Join-Path $h 'config.json'),'{"tenantId":"t"}',(New-Object Text.UTF8Encoding($false)))
    $stub=Join-Path (Join-Path $h 'bin') 'deny-hook.cmd'
    $deny='{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"nope"}}'
    [IO.File]::WriteAllText($stub,"@echo off`r`necho $deny`r`n",(New-Object Text.UTF8Encoding($false)))
    $r=Invoke-Shim $Shim $h $stub '{"tool_name":"Read","tool_input":{}}'
    $r.Exit | Should -Be 0
    ($r.Out).Trim() | Should -BeExactly $deny
    ($r.Out) | Should -Not -Match 'permissionDecision":"allow"'
  }

  It 'emits populated allow + diagnostic when the hook exits with empty stdout' {
    $h=Join-Path ([IO.Path]::GetTempPath()) ("shim empty "+[guid]::NewGuid()); New-Item -ItemType Directory -Force (Join-Path $h 'bin')|Out-Null
    [IO.File]::WriteAllText((Join-Path $h 'config.json'),'{"tenantId":"t"}',(New-Object Text.UTF8Encoding($false)))
    $stub=Join-Path (Join-Path $h 'bin') 'empty-hook.cmd'
    [IO.File]::WriteAllText($stub,"@echo off`r`nexit /b 0`r`n",(New-Object Text.UTF8Encoding($false)))
    $r=Invoke-Shim $Shim $h $stub '{"tool_name":"Read","tool_input":{}}'
    $r.Exit | Should -Be 0
    ($r.Out) | Should -Match 'permissionDecision":"allow"'
    ($r.Out) | Should -Match 'returned no decision'
    (Get-Content -Raw (Join-Path (Join-Path $h 'logs') 'sentinel-shim.ndjson')) | Should -Match 'hook-exited-0-no-stdout'
  }

  It 'bounds the stdin write when the hook never reads stdin (large envelope)' -Tag 'timeout' {
    $h=Join-Path ([IO.Path]::GetTempPath()) ("shim stdin "+[guid]::NewGuid()); New-Item -ItemType Directory -Force (Join-Path $h 'bin')|Out-Null
    [IO.File]::WriteAllText((Join-Path $h 'config.json'),'{"tenantId":"t"}',(New-Object Text.UTF8Encoding($false)))
    $stub=Join-Path (Join-Path $h 'bin') 'noread-hook.cmd'
    # Sleeps ~10s and NEVER reads stdin; the shim must return bounded via the stdin-write timeout.
    [IO.File]::WriteAllText($stub, "@echo off`r`nping -n 11 127.0.0.1 >nul`r`necho {}`r`n",(New-Object Text.UTF8Encoding($false)))
    # 200KB envelope far exceeds any OS pipe buffer (~4-64KB), so the write to a
    # non-reading child is GUARANTEED to block -> the stdin-write timeout fires
    # specifically (not the later WaitForExit timeout). Assert that exact branch.
    $big = '{"tool_name":"Read","tool_input":{"x":"' + ('A' * 200000) + '"}}'
    $r=Invoke-Shim $Shim $h $stub $big
    $r.Exit | Should -Be 0
    $r.Ms | Should -BeLessThan 5000
    ($r.Out) | Should -Match 'permissionDecision":"allow"'
    ($r.Out) | Should -Match 'not reading input'
    (Get-Content -Raw (Join-Path (Join-Path $h 'logs') 'sentinel-shim.ndjson')) | Should -Match 'hook-stdin-write-timeout'
  }

  It 'bounds the stdin READ when CC never closes the hook stdin pipe (hard-wedge guard)' -Tag 'timeout' {
    # Models the VSCode-panel hard-wedge: CC invokes the hook but never closes
    # the hook's stdin. An unbounded [Console]::In.ReadToEnd() would hang the
    # shim forever, wedging CC's synchronous hook-invocation loop (Stop button
    # unresponsive; only a window reload recovers). The shim must self-terminate
    # via a bounded read and emit a populated fail-open allow + diagnostic.
    $h=Join-Path ([IO.Path]::GetTempPath()) ("shim stdinread "+[guid]::NewGuid()); New-Item -ItemType Directory -Force (Join-Path $h 'bin')|Out-Null
    [IO.File]::WriteAllText((Join-Path $h 'config.json'),'{"tenantId":"t"}',(New-Object Text.UTF8Encoding($false)))
    $stub=Join-Path (Join-Path $h 'bin') 'unused-hook.cmd'
    [IO.File]::WriteAllText($stub,"@echo off`r`necho {}`r`n",(New-Object Text.UTF8Encoding($false)))
    $psi=New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName='powershell'
    $psi.Arguments="-NoProfile -ExecutionPolicy Bypass -File `"$Shim`" -SentinelHome `"$h`" -HookExe `"$stub`""
    $psi.UseShellExecute=$false; $psi.RedirectStandardInput=$true; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true
    $psi.StandardOutputEncoding=[System.Text.Encoding]::UTF8
    $sw=[System.Diagnostics.Stopwatch]::StartNew()
    $p=[System.Diagnostics.Process]::Start($psi)
    $o=$p.StandardOutput.ReadToEndAsync(); $e=$p.StandardError.ReadToEndAsync()
    # Deliberately DO NOT write or close stdin — the shim's read must time out.
    $exited=$p.WaitForExit(8000); $sw.Stop()
    if (-not $exited) { try { $p.Kill() } catch {} }
    $exited | Should -Be $true
    $sw.ElapsedMilliseconds | Should -BeLessThan 6000
    ($o.Result) | Should -Match 'permissionDecision":"allow"'
    ($o.Result) | Should -Match 'did not receive input'
    (Get-Content -Raw (Join-Path (Join-Path $h 'logs') 'sentinel-shim.ndjson')) | Should -Match 'hook-stdin-read-timeout'
  }
}

Describe 'sentinel-shim cold-spawn bounded stdout read (freeze fix)' {
  # The freeze fix replaces the shim's unbounded ReadToEndAsync().Result (which
  # blocked forever on a stdout EOF that never arrives when the detached daemon
  # inherits the hook's stdout pipe) with a BOUNDED single-line ReadLineAsync().
  #
  # Coverage note (honest, per "no silent caps"): the held-pipe FREEZE itself is NOT
  # reproducible in this Pester harness, and it is NOT for lack of trying. Empirically:
  # a node grandchild spawned by a node parent DOES inherit and hold the parent's stdout
  # fd for the timer's lifetime (so the leak is real) — BUT the shim launches a .cmd hook
  # via `cmd.exe /c`, and that intervening cmd layer breaks the handle-inheritance chain
  # (the grandchild does not hold the shim<->cmd pipe). The shim ALWAYS wraps .cmd/.bat
  # via cmd.exe, so a stub cannot reproduce the production path, where the real
  # SEA-exe hook spawns the daemon DIRECTLY (libuv bInheritHandles=TRUE, no cmd layer)
  # and the daemon keeps the hook's stdout pipe open. The freeze (and the
  # hook-stdout-read-timeout fail-open) are therefore verified AUTHORITATIVELY by the
  # deterministic acceptance repro against the real cc-hook.exe -> daemon (see
  # docs/changes/2026-06-26-daemon-cold-spawn-detach.md and the PR verification).
  # What IS reliably unit-testable here is the OBSERVABLE consequence of the
  # ReadToEnd -> ReadLine switch: the shim now relays only the FIRST stdout line.
  # (Pre-fix ReadToEnd concatenated all stdout; post-fix ReadLine returns one line —
  # empirically confirmed to discriminate the two implementations.)
  BeforeAll {
    function script:Invoke-ShimBounded($shim, $shimHome, $hookExe, $stdinJson, $waitMs) {
      $psi = New-Object System.Diagnostics.ProcessStartInfo
      $psi.FileName = 'powershell'
      $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$shim`" -SentinelHome `"$shimHome`" -HookExe `"$hookExe`""
      $psi.UseShellExecute = $false; $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
      $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
      $sw = [System.Diagnostics.Stopwatch]::StartNew()
      $p = [System.Diagnostics.Process]::Start($psi)
      $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
      $p.StandardInput.Write($stdinJson); $p.StandardInput.Close()
      $exited = $p.WaitForExit($waitMs); $sw.Stop()
      if (-not $exited) { try { $p.Kill() } catch { } }
      $outText = ''
      try { $outText = $o.Result } catch { $outText = '' }
      [pscustomobject]@{ Out = $outText; Ms = $sw.ElapsedMilliseconds; Exited = $exited }
    }
  }

  It 'relays ONLY the first decision line (ReadLine, not ReadToEnd) - the core fix regression' {
    # Empirically: pre-fix ReadToEnd relays BOTH lines (Out contains "second");
    # post-fix ReadLine relays only the first. This is the reliable discriminator.
    $h = Join-Path ([IO.Path]::GetTempPath()) ("shim multiline " + [guid]::NewGuid()); New-Item -ItemType Directory -Force (Join-Path $h 'bin') | Out-Null
    [IO.File]::WriteAllText((Join-Path $h 'config.json'), '{"tenantId":"t"}', (New-Object Text.UTF8Encoding($false)))
    $stub = Join-Path (Join-Path $h 'bin') 'multiline-hook.cmd'
    $first = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"first"}}'
    $second = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"second"}}'
    [IO.File]::WriteAllText($stub, "@echo off`r`necho $first`r`necho $second`r`n", (New-Object Text.UTF8Encoding($false)))
    $r = Invoke-ShimBounded $Shim $h $stub '{"tool_name":"Read","tool_input":{}}' 4000
    $r.Exited | Should -Be $true
    ($r.Out) | Should -Match 'first'
    ($r.Out) | Should -Not -Match 'second'
  }

  It 'relays a single-line DENY exactly through the bounded read (no masking, single LF)' {
    $h = Join-Path ([IO.Path]::GetTempPath()) ("shim rl deny " + [guid]::NewGuid()); New-Item -ItemType Directory -Force (Join-Path $h 'bin') | Out-Null
    [IO.File]::WriteAllText((Join-Path $h 'config.json'), '{"tenantId":"t"}', (New-Object Text.UTF8Encoding($false)))
    $stub = Join-Path (Join-Path $h 'bin') 'rl-deny-hook.cmd'
    $deny = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"bounded-read-relay"}}'
    [IO.File]::WriteAllText($stub, "@echo off`r`necho $deny`r`n", (New-Object Text.UTF8Encoding($false)))
    $r = Invoke-ShimBounded $Shim $h $stub '{"tool_name":"Read","tool_input":{}}' 4000
    $r.Exited | Should -Be $true
    ($r.Out).Trim() | Should -BeExactly $deny
  }
}
