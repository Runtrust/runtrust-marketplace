#Requires -Version 5.1
<#
.SYNOPSIS
    SentinelCore — canonical home of the reusable RunTrust/Sentinel installer logic.

.DESCRIPTION
    Extracted (behavior-preserving) from sentinel-install.ps1. Exposes the pure
    helpers (config read/write, device identity, credential liveness, redaction,
    hashing), the side-effecting install primitives (ACL hardening, hook wiring,
    tray autostart/launch, audit-row probe, uninstall), and three orchestration
    entrypoints:

      Invoke-SentinelSetup       — the install flow WITHOUT wiring the cc-hook
                                   into ~/.claude/settings.json. Returns a rich
                                   pscustomobject so a caller can wire the hook
                                   afterward if desired.
      Install-SentinelDeprecated — Invoke-SentinelSetup + Merge-ClaudeHook, i.e.
                                   the original Install-Sentinel end-state.
      Get-SentinelStatus         — defer to the status exe (single source of
                                   truth) for the live connector status.

    Secrets (the install token and the daemon apiKey) are ALWAYS redacted in
    both the console and the install log via Redact-Secret.
#>

# ---------------------------------------------------------------------------
# Test-PSVersionSupported: pure, testable gate. PowerShell 5.1+ is required.
# ---------------------------------------------------------------------------
function Test-PSVersionSupported {
    [CmdletBinding()]
    param([Parameter(Mandatory)][version]$Version)
    return ($Version -ge [version]'5.1')
}

# ---------------------------------------------------------------------------
# Redact-Secret: collapse a secret to "<prefix6>…(len)" so logs never leak it.
# ---------------------------------------------------------------------------
function Redact-Secret {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline=$true)][AllowNull()][AllowEmptyString()][string]$Secret)
    process {
        if ([string]::IsNullOrEmpty($Secret)) { return '<empty>' }
        $len = $Secret.Length
        $prefixLen = [Math]::Min(6, $len)
        $prefix = $Secret.Substring(0, $prefixLen)
        return ("{0}…({1})" -f $prefix, $len)
    }
}

# ---------------------------------------------------------------------------
# Get-Sha256Hex: lowercase hex SHA-256 of a UTF-8 string. Used for the device
# identity derivation. Pure + deterministic.
# ---------------------------------------------------------------------------
function Get-Sha256Hex {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hash = $sha.ComputeHash($bytes)
        $sb = New-Object System.Text.StringBuilder
        foreach ($b in $hash) { [void]$sb.Append($b.ToString('x2')) }
        return $sb.ToString()
    } finally {
        $sha.Dispose()
    }
}

# ---------------------------------------------------------------------------
# Read-SentinelConfig: load + parse $configPath into a hashtable, or @{} when
# the file is absent/empty/unparseable. Never throws. Used by the merge writer
# and the reinstall heuristic so unknown keys (e.g. deviceSalt) survive.
# ---------------------------------------------------------------------------
function Read-SentinelConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConfigPath)
    if (-not (Test-Path $ConfigPath)) { return @{} }
    try {
        $raw = Get-Content -Raw $ConfigPath
        if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }
        $obj = $raw | ConvertFrom-Json
        $h = ConvertTo-MutableHashtable $obj
        if ($h -is [hashtable]) { return $h }
        return @{}
    } catch {
        return @{}
    }
}

# ---------------------------------------------------------------------------
# Save-SentinelConfig: READ-MODIFY-WRITE merge. Loads the existing config (if
# any), merges $Values over it, and writes the result back — PRESERVING every
# unknown key (especially deviceSalt; dropping it would rotate the device
# identity on the next install). Returns the merged hashtable.
# ---------------------------------------------------------------------------
function Save-SentinelConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][hashtable]$Values
    )
    $merged = Read-SentinelConfig -ConfigPath $ConfigPath
    foreach ($k in $Values.Keys) { $merged[$k] = $Values[$k] }

    $dir = Split-Path -Parent $ConfigPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    # Use WriteAllText (no BOM) instead of Set-Content -Encoding utf8.
    # On PowerShell 5.1, Set-Content -Encoding utf8 prepends a UTF-8 BOM (EF BB BF),
    # which causes JSON.parse to throw on the daemon/CLI reader side.
    # [System.IO.File]::WriteAllText writes UTF-8 without BOM on both PS 5.1 and PS 7.
    $absPath = [System.IO.Path]::GetFullPath($ConfigPath)
    [System.IO.File]::WriteAllText($absPath, ($merged | ConvertTo-Json -Depth 10))
    return $merged
}

# ---------------------------------------------------------------------------
# Get-SentinelDeviceId: derive a stable device identity for install attribution.
#
#   machineGuid = (Get-ItemProperty HKLM:\...\Cryptography\MachineGuid).MachineGuid
#   hostname    = OS hostname, lowercased + trimmed; empty/control-only -> 'unknown-host'
#   deviceId    = 'dev-' + sha256_hex( hostname + NUL + machineGuid )   (lowercase hex)
#
# Fallback when MachineGuid is unreadable: read-or-generate a random GUID
# persisted to config.json as `deviceSalt` (generated ONCE, reused thereafter),
# and use deviceId = 'dev-' + sha256_hex(hostname + NUL + deviceSalt).
#
# Output ALWAYS matches ^dev-[a-f0-9]{64}$. deviceHostname is the (lowercased,
# or 'unknown-host') hostname, returned separately — it is operator-visible by
# design. machineGuid + hostname are injectable for deterministic Pester tests.
# Returns @{ DeviceId = '<dev-...>'; DeviceHostname = '<host>' }.
# ---------------------------------------------------------------------------
function Get-SentinelDeviceId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        # Default to the real lookups; tests inject deterministic values.
        # NOTE: do NOT type these [string] — a [string] param coerces a $null
        # default to '' on binding, which would suppress the real lookups and
        # always fall through to the salt path. Keep them untyped so an unset
        # caller leaves them genuinely $null.
        [AllowNull()][AllowEmptyString()]$MachineGuid = $null,
        [AllowNull()][AllowEmptyString()]$Hostname = $null
    )

    # ---- hostname: lowercase + trim; control-only/empty -> 'unknown-host' ----
    # Only auto-resolve when the caller passed nothing at all. An explicitly
    # injected empty string must be honored (drives the unknown-host case).
    if (-not $PSBoundParameters.ContainsKey('Hostname')) {
        try { $Hostname = [System.Net.Dns]::GetHostName() } catch { $Hostname = $null }
        if ([string]::IsNullOrWhiteSpace([string]$Hostname)) {
            try { $Hostname = $env:COMPUTERNAME } catch { $Hostname = $null }
        }
    }
    $hn = if ($null -eq $Hostname) { '' } else { [string]$Hostname }
    # Strip control characters, then trim whitespace.
    $hn = ($hn -replace '[\x00-\x1f\x7f]', '').Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($hn)) { $hn = 'unknown-host' }

    # ---- machineGuid: real lookup unless injected ---------------------------
    # NOTE: MachineGuid is a *value* under the Cryptography key — must be read
    # with -Path <key> -Name MachineGuid. Treating it as a sub-key path
    # (…\Cryptography\MachineGuid) fails ("path does not exist").
    if (-not $PSBoundParameters.ContainsKey('MachineGuid')) {
        try {
            $mg = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid' -ErrorAction Stop).MachineGuid
            $MachineGuid = [string]$mg
        } catch {
            $MachineGuid = $null
        }
    }
    $MachineGuid = if ($null -eq $MachineGuid) { '' } else { [string]$MachineGuid }

    if (-not [string]::IsNullOrWhiteSpace($MachineGuid)) {
        $deviceId = 'dev-' + (Get-Sha256Hex -Text ($hn + "`0" + $MachineGuid))
        return @{ DeviceId = $deviceId; DeviceHostname = $hn }
    }

    # ---- fallback: persisted deviceSalt (generate once, reuse thereafter) ----
    $cfg = Read-SentinelConfig -ConfigPath $ConfigPath
    $salt = $null
    if ($cfg.ContainsKey('deviceSalt') -and -not [string]::IsNullOrWhiteSpace([string]$cfg['deviceSalt'])) {
        $salt = [string]$cfg['deviceSalt']
    } else {
        $salt = [guid]::NewGuid().ToString()
        # Persist via the merge writer so no other key is dropped.
        [void](Save-SentinelConfig -ConfigPath $ConfigPath -Values @{ deviceSalt = $salt })
    }
    $deviceId = 'dev-' + (Get-Sha256Hex -Text ($hn + "`0" + $salt))
    return @{ DeviceId = $deviceId; DeviceHostname = $hn }
}

# ---------------------------------------------------------------------------
# ConvertFrom-Base64Url: decode a base64url segment (JWT part) to a UTF-8 string.
# Returns $null on any decode failure. Pure; never throws.
# ---------------------------------------------------------------------------
function ConvertFrom-Base64Url {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Segment)
    if ([string]::IsNullOrWhiteSpace($Segment)) { return $null }
    try {
        $s = $Segment.Replace('-', '+').Replace('_', '/')
        switch ($s.Length % 4) {
            2 { $s += '==' }
            3 { $s += '=' }
            1 { return $null }  # invalid base64 length
        }
        $bytes = [System.Convert]::FromBase64String($s)
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    } catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Test-SentinelCredentialValid: reinstall liveness heuristic. NO signature
# verification — the installer has no signing secret. We base64url-decode the
# daemon JWT payload (the middle segment of the opaque apiKey), read `exp`, and
# return $true ONLY when:
#   - exp - now  > 24h, AND
#   - the payload carries both `tenantId` and `installationId` claims.
# Returns $false if the apiKey is absent, undecodable, missing/near-exp, or
# missing the required claims. `Now` (ms-since-epoch) is injectable for tests.
# Never throws.
# ---------------------------------------------------------------------------
function Test-SentinelCredentialValid {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$ApiKey,
        [long]$NowMs = ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
    )
    if ([string]::IsNullOrWhiteSpace($ApiKey)) { return $false }
    $parts = $ApiKey.Split('.')
    if ($parts.Count -lt 2) { return $false }

    $payloadJson = ConvertFrom-Base64Url -Segment $parts[1]
    if ($null -eq $payloadJson) { return $false }

    $payload = $null
    try { $payload = $payloadJson | ConvertFrom-Json } catch { return $false }
    if ($null -eq $payload) { return $false }

    $names = @($payload.PSObject.Properties.Name)
    if (($names -notcontains 'exp') -or
        ($names -notcontains 'tenantId') -or
        ($names -notcontains 'installationId')) {
        return $false
    }
    if ([string]::IsNullOrWhiteSpace([string]$payload.tenantId) -or
        [string]::IsNullOrWhiteSpace([string]$payload.installationId)) {
        return $false
    }

    # `exp` is seconds-since-epoch per JWT (RFC 7519). Compare in ms.
    $expSec = 0L
    try { $expSec = [long][double]$payload.exp } catch { return $false }
    $expMs = $expSec * 1000L
    $twentyFourHoursMs = 24L * 60L * 60L * 1000L
    return (($expMs - $NowMs) -gt $twentyFourHoursMs)
}

# ---------------------------------------------------------------------------
# Write-InstallLog: emit to console AND $SentinelHome\logs\install.log.
# Callers MUST pre-redact any secrets before passing a message here.
# ---------------------------------------------------------------------------
function Write-InstallLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO',
        [string]$LogFile
    )
    $ts = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffK')
    $line = "[$ts] [$Level] $Message"
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        default { Write-Host $line }
    }
    if ($LogFile) {
        try {
            $dir = Split-Path -Parent $LogFile
            if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            # No-BOM append: on PS 5.1, Add-Content -Encoding utf8 prepends a UTF-8
            # BOM (EF BB BF) on the first write to a new file. AppendAllText with
            # UTF8Encoding($false) does not. Matches the shim's Write-ShimDiag fix.
            [System.IO.File]::AppendAllText($LogFile, $line + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
        } catch {
            Write-Host "[$ts] [WARN] failed to append to log file: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# ---------------------------------------------------------------------------
# Set-RestrictiveAcl: current user full control, strip inherited broad access.
# Best-effort: warns and continues on failure (never hard-aborts the install).
# ---------------------------------------------------------------------------
function Set-RestrictiveAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [string]$LogFile)
    try {
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        # (OI)(CI) are container-only inheritance flags — valid on directories,
        # invalid on files (would yield an ACE that does not actually grant the
        # right). Pick the grant spec based on the target type.
        $isContainer = (Test-Path $Path -PathType Container)
        $grantSpec = if ($isContainer) { "${me}:(OI)(CI)F" } else { "${me}:(F)" }
        # /inheritance:r removes inherited ACEs; then grant the current user full control.
        $out = & icacls "$Path" /inheritance:r /grant:r "$grantSpec" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-InstallLog -Message "ACL hardening returned non-zero for ${Path}: $out" -Level WARN -LogFile $LogFile
        } else {
            Write-InstallLog -Message "ACL hardened on $Path (user=$me full control, inheritance removed)" -Level INFO -LogFile $LogFile
        }
    } catch {
        Write-InstallLog -Message "ACL hardening failed for ${Path} (continuing): $($_.Exception.Message)" -Level WARN -LogFile $LogFile
    }
}

# ---------------------------------------------------------------------------
# Get-AuditRowCount: query the hosted console's audit feed for this tenant and
# return @{ Count = <int>; Status = 'ok'|'auth-failed'|'unavailable'|'error';
#           Detail = '<string>' }. Defensive about the response shape: the
# gateway returns { rows: [...], count: N, ... } but we tolerate a bare array
# or a { count } body too. 401 => bad credential ('auth-failed'); 503 => audit
# DB unavailable ('unavailable'). NEVER throws.
# ---------------------------------------------------------------------------
function Get-AuditRowCount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Endpoint,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ApiKey
    )
    $uri = "$Endpoint/v1/audit/recent?tenant_id=$TenantId"
    try {
        $resp = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ Authorization = "Bearer $ApiKey" }
        $count = 0
        if ($null -eq $resp) {
            $count = 0
        } elseif ($resp.PSObject.Properties.Name -contains 'rows' -and $null -ne $resp.rows) {
            $count = @($resp.rows).Count
        } elseif ($resp -is [System.Collections.IEnumerable] -and -not ($resp -is [string])) {
            $count = @($resp).Count
        } elseif ($resp.PSObject.Properties.Name -contains 'count' -and $null -ne $resp.count) {
            $count = [int]$resp.count
        } else {
            $count = 0
        }
        return @{ Count = [int]$count; Status = 'ok'; Detail = '' }
    } catch {
        $status = $null
        if ($_.Exception.Response) {
            try { $status = [int]$_.Exception.Response.StatusCode } catch { $status = $null }
        }
        if ($status -eq 401) {
            return @{ Count = -1; Status = 'auth-failed'; Detail = 'audit-auth-failed' }
        } elseif ($status -eq 503) {
            return @{ Count = -1; Status = 'unavailable'; Detail = 'audit-unavailable' }
        }
        return @{ Count = -1; Status = 'error'; Detail = ("audit-error: " + $_.Exception.Message) }
    }
}

# ---------------------------------------------------------------------------
# Invoke-HookExe: pipe a benign PreToolUseInput JSON to the cc-hook exe with
# $env:CLAUDE_PROJECT_DIR set, and return the hook's STDOUT as a single string.
# Factored out as its own seam so the first-decision probe can be unit-tested
# by mocking the hook invocation. The hook ALWAYS exits 0 after writing its
# HookOutput JSON (even when the daemon is unreachable — that surfaces as a
# `sentinel-unavailable` decision in stdout, NOT a nonzero exit), so the exit
# code is deliberately NOT used as a success signal. NEVER throws.
# ---------------------------------------------------------------------------
function Invoke-HookExe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HookExePath,
        [Parameter(Mandatory)][string]$ProjectDir
    )
    # The cc-hook logs its events to STDERR and the decision JSON to STDOUT.
    # Force Continue locally: under an inherited $ErrorActionPreference='Stop'
    # (a CI/automation wrapper, or an agent shell), PowerShell would treat the
    # hook's stderr as a TERMINATING NativeCommandError and abort the hook
    # mid-relay — the decision never lands and the probe falsely reports
    # "not confirmed" even though the install is healthy. Continue makes the
    # probe robust to any caller's error preference.
    $ErrorActionPreference = 'Continue'
    $probeInput = [ordered]@{
        session_id  = 'install-firstrun'
        tool_use_id = 'install-probe-1'
        tool_name   = 'Read'
        tool_input  = @{ file_path = 'README.md' }
        cwd         = $ProjectDir
    }
    $json = $probeInput | ConvertTo-Json -Compress -Depth 5
    $prev = $env:CLAUDE_PROJECT_DIR
    $env:CLAUDE_PROJECT_DIR = $ProjectDir
    try {
        # Capture STDOUT ONLY (the decision JSON). Route stderr to $null so the
        # hook's diagnostic logs do not leak into the probe's FirstDecisionDetail,
        # install.log, or the wrapper's returned object. Mirrors Get-SentinelStatus's
        # 2>$null discipline.
        $out = $json | & $HookExePath 2>$null
        return (($out | Out-String).Trim())
    } finally {
        $env:CLAUDE_PROJECT_DIR = $prev
    }
}

# ---------------------------------------------------------------------------
# Invoke-FirstDecisionProbe: confirm the first decision ACTUALLY landed in the
# hosted console's audit feed — the real end-to-end signal.
#
# WHY NOT exit-code: the cc-hook binary ALWAYS exits 0 after writing its
# HookOutput JSON, even when the daemon is unreachable (that failure is a
# `sentinel-unavailable` decision in stdout, NOT a nonzero exit). So exit-0 is
# NOT proof a decision was recorded. The authoritative check is: did a NEW
# audit row appear for this tenant after we drove a tool call through the hook?
#
# Flow:
#   1. Snapshot the current audit row count for the tenant (baseline).
#      401 => bad daemon credential  -> Confirmed=$false, detail audit-auth-failed
#      503 => audit DB unavailable   -> Confirmed=$false, detail audit-unavailable
#   2. Invoke the hook with a benign PreToolUseInput. Capture stdout; a
#      `sentinel-unavailable` (or empty/unparseable) stdout is a negative
#      signal recorded in the detail (but step 3 is authoritative).
#   3. Poll audit/recent up to ~10s (10 attempts, 1s apart) for a row count
#      > baseline. New row => Confirmed=$true (audit-row-observed). Timeout =>
#      Confirmed=$false (no-audit-row).
#
# Best-effort — NEVER throws to the caller. Returns @{ Confirmed; Detail }.
# ---------------------------------------------------------------------------
function Invoke-FirstDecisionProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HookExePath,
        [Parameter(Mandatory)][string]$SentinelHome,
        [Parameter(Mandatory)][string]$Endpoint,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ApiKey,
        [int]$PollAttempts = 15,
        [int]$PollIntervalMs = 1000,
        [string]$LogFile
    )
    try {
        if (-not (Test-Path $HookExePath)) {
            return @{ Confirmed = $false; Detail = 'hook-exe-missing' }
        }

        # ---- 1. Baseline audit row count ----------------------------------
        $baseline = Get-AuditRowCount -Endpoint $Endpoint -TenantId $TenantId -ApiKey $ApiKey
        if ($baseline.Status -eq 'auth-failed') {
            return @{ Confirmed = $false; Detail = 'audit-auth-failed' }
        }
        if ($baseline.Status -eq 'unavailable') {
            return @{ Confirmed = $false; Detail = 'audit-unavailable' }
        }
        if ($baseline.Status -ne 'ok') {
            return @{ Confirmed = $false; Detail = $baseline.Detail }
        }
        $baselineCount = [int]$baseline.Count

        # ---- 2+3. Drive tool calls through the hook + poll for a NEW row --
        # The daemon cold-starts on the FIRST hook call (it spawns a ~118MB
        # self-contained exe that unpacks itself, which can take several
        # seconds). A single cold call may not land a decision before the
        # daemon's pipe is ready, so we RE-DRIVE the benign Read hook on the
        # early poll iterations: the first call spawns the daemon, the warm
        # follow-up calls produce decisions that the gateway audits. Each call
        # is idempotent (a benign Read). The audit row is the authoritative
        # confirmation regardless of which call landed it.
        $hookOut = ''
        for ($i = 0; $i -lt $PollAttempts; $i++) {
            if ($i -lt 5) {
                try { $hookOut = Invoke-HookExe -HookExePath $HookExePath -ProjectDir (Get-Location).Path } catch { $hookOut = '' }
            }
            $poll = Get-AuditRowCount -Endpoint $Endpoint -TenantId $TenantId -ApiKey $ApiKey
            if ($poll.Status -eq 'ok' -and [int]$poll.Count -gt $baselineCount) {
                return @{ Confirmed = $true; Detail = 'audit-row-observed' }
            }
            if ($i -lt ($PollAttempts - 1)) { Start-Sleep -Milliseconds $PollIntervalMs }
        }

        $hookStdout = if ([string]::IsNullOrWhiteSpace($hookOut)) { '<empty>' } else { $hookOut }
        return @{ Confirmed = $false; Detail = ("no-audit-row (hook stdout: " + $hookStdout + ")") }
    } catch {
        return @{ Confirmed = $false; Detail = ("probe-error: " + $_.Exception.Message) }
    }
}

# ---------------------------------------------------------------------------
# Merge-ClaudeHook: idempotently wire the cc-hook into ~/.claude/settings.json.
# ---------------------------------------------------------------------------
function Merge-ClaudeHook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SettingsPath,
        [Parameter(Mandatory)][string]$HookExePath,
        [string]$LogFile
    )
    $dir = Split-Path -Parent $SettingsPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $settings = $null
    if (Test-Path $SettingsPath) {
        $raw = Get-Content -Raw $SettingsPath
        if ($raw -and $raw.Trim().Length -gt 0) {
            try { $settings = $raw | ConvertFrom-Json } catch {
                Write-InstallLog -Message "settings.json was not valid JSON; backing up and recreating" -Level WARN -LogFile $LogFile
                Copy-Item -Path $SettingsPath -Destination ("$SettingsPath.bak." + (Get-Date).ToString('yyyyMMddHHmmss')) -Force
                $settings = $null
            }
        }
    }
    if ($null -eq $settings) { $settings = [pscustomobject]@{} }

    # Convert the whole tree to a mutable hashtable for easy manipulation.
    $h = ConvertTo-MutableHashtable $settings
    if (-not $h.ContainsKey('hooks') -or $null -eq $h['hooks']) { $h['hooks'] = @{} }
    if (-not ($h['hooks'] -is [hashtable])) { $h['hooks'] = ConvertTo-MutableHashtable $h['hooks'] }
    if (-not $h['hooks'].ContainsKey('PreToolUse') -or $null -eq $h['hooks']['PreToolUse']) {
        $h['hooks']['PreToolUse'] = @()
    }

    # Drop any existing Sentinel entry (command contains sentinel-cc-hook).
    $existing = @($h['hooks']['PreToolUse'])
    $kept = @()
    foreach ($entry in $existing) {
        $eh = ConvertTo-MutableHashtable $entry
        $cmds = @()
        if ($eh.ContainsKey('hooks') -and $eh['hooks']) {
            foreach ($hk in @($eh['hooks'])) {
                $hkh = ConvertTo-MutableHashtable $hk
                if ($hkh.ContainsKey('command')) { $cmds += [string]$hkh['command'] }
            }
        }
        if (($cmds -join ' ') -match 'sentinel-cc-hook') {
            # skip — will be re-added fresh
            continue
        }
        $kept += $eh
    }

    # Quote the exe path so it survives a %USERPROFILE% that contains spaces
    # (e.g. C:\Users\John Doe\.sentinel\bin\...). Claude Code's hook runner
    # invokes the command via a shell, so an unquoted path with spaces breaks.
    $quotedCommand = '"' + $HookExePath + '"'
    $sentinelEntry = @{
        matcher = '*'
        hooks   = @(@{ type = 'command'; command = $quotedCommand })
    }
    $kept += $sentinelEntry
    $h['hooks']['PreToolUse'] = $kept

    # No-BOM write so Claude Code's settings.json parser is never tripped by a
    # leading BOM. On PowerShell 5.1, Set-Content -Encoding utf8 prepends a UTF-8
    # BOM (EF BB BF); WriteAllText with UTF8Encoding($false) does not. Matches the
    # discipline in Save-SentinelConfig and Uninstall-Sentinel.
    [System.IO.File]::WriteAllText($SettingsPath, ($h | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
    Write-InstallLog -Message "cc-hook wired into $SettingsPath (Sentinel PreToolUse entries: 1)" -Level INFO -LogFile $LogFile
}

# ---------------------------------------------------------------------------
# Uninstall-Sentinel: clean teardown — the exact inverse of an install. Stops
# the daemon + tray, removes the tray autostart, unwires ONLY the Sentinel
# cc-hook from settings.json (every other hook/key is preserved), and deletes
# the %USERPROFILE%\.sentinel tree. Idempotent + best-effort; safe to re-run.
# ---------------------------------------------------------------------------
function Uninstall-Sentinel {
    [CmdletBinding()]
    param(
        [string]$SentinelHome = (Join-Path $env:USERPROFILE '.sentinel'),
        [string]$SettingsPath = (Join-Path $env:USERPROFILE '.claude\settings.json')
    )
    Write-Host "Uninstalling RunTrust/Sentinel connector..."

    # 1. Stop the daemon, tray, and any hook process (best-effort).
    foreach ($name in @('sentinel-cc-daemon-win-x64.exe', 'sentinel-tray-win-x64.exe', 'sentinel-cc-hook-win-x64.exe')) {
        try {
            @(Get-CimInstance Win32_Process -Filter "Name='$name'" -ErrorAction SilentlyContinue) | ForEach-Object {
                Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                Write-Host "  stopped $name (pid $($_.ProcessId))"
            }
        } catch {}
    }

    # 2. Remove the tray autostart (HKCU Run).
    try {
        $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        if ($null -ne (Get-ItemProperty -Path $runKey -Name SentinelTray -ErrorAction SilentlyContinue)) {
            Remove-ItemProperty -Path $runKey -Name SentinelTray -ErrorAction SilentlyContinue
            Write-Host "  removed tray autostart (HKCU Run\SentinelTray)"
        }
    } catch {}

    # 3. Unwire ONLY the Sentinel cc-hook from settings.json; keep everything else.
    try {
        if (Test-Path $SettingsPath) {
            $raw = Get-Content -Raw $SettingsPath
            if ($raw -and $raw.Trim().Length -gt 0) {
                $settings = $null
                try { $settings = $raw | ConvertFrom-Json } catch { $settings = $null }
                if ($null -ne $settings) {
                    $h = ConvertTo-MutableHashtable $settings
                    if ($h.ContainsKey('hooks') -and ($h['hooks'] -is [hashtable]) -and $h['hooks'].ContainsKey('PreToolUse')) {
                        $kept = @()
                        foreach ($entry in @($h['hooks']['PreToolUse'])) {
                            $eh = ConvertTo-MutableHashtable $entry
                            $cmds = @()
                            if ($eh.ContainsKey('hooks') -and $eh['hooks']) {
                                foreach ($hk in @($eh['hooks'])) {
                                    $hkh = ConvertTo-MutableHashtable $hk
                                    if ($hkh.ContainsKey('command')) { $cmds += [string]$hkh['command'] }
                                }
                            }
                            if (($cmds -join ' ') -match 'sentinel-cc-hook') { continue } # drop Sentinel entry
                            $kept += $eh
                        }
                        if (@($kept).Count -eq 0) { [void]$h['hooks'].Remove('PreToolUse') } else { $h['hooks']['PreToolUse'] = $kept }
                        if (($h['hooks'] -is [hashtable]) -and $h['hooks'].Count -eq 0) { [void]$h.Remove('hooks') }
                        # No-BOM write so Claude Code's JSON parser is never tripped by a leading BOM.
                        [System.IO.File]::WriteAllText($SettingsPath, ($h | ConvertTo-Json -Depth 20))
                        Write-Host "  unwired cc-hook from $SettingsPath (other hooks preserved)"
                    }
                }
            }
        }
    } catch {
        Write-Host "  WARN: could not edit settings.json: $($_.Exception.Message)"
    }

    # 4. Remove the .sentinel home (config, bin, logs, status, spool).
    try {
        if (Test-Path $SentinelHome) {
            Remove-Item -Path $SentinelHome -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path $SentinelHome) {
                Write-Host "  WARN: some files under $SentinelHome are still in use; re-run after closing Claude Code."
            } else {
                Write-Host "  removed $SentinelHome"
            }
        }
    } catch {
        Write-Host "  WARN: could not remove ${SentinelHome}: $($_.Exception.Message)"
    }

    Write-Host "Uninstall complete. In VSCode, run Ctrl+Shift+P -> 'Developer: Reload Window' so the removed hook unloads."
}

# ---------------------------------------------------------------------------
# Set-TrayAutostart: register the tray exe to start on user login via the HKCU
# Run key, idempotently. Writes a SINGLE named value (default 'SentinelTray')
# pointing at the QUOTED tray exe path (survives a %USERPROFILE% with spaces,
# same discipline as Merge-ClaudeHook's quoted hook command). A reinstall
# OVERWRITES the same value (-Force on New-ItemProperty) — never a duplicate.
# Best-effort: warns + RETURNS on failure (never throws — autostart failure
# must not fail the install, mirroring Set-RestrictiveAcl). $RunKeyPath /
# $ValueName are overridable so tests can redirect to a fake hive.
# ---------------------------------------------------------------------------
function Set-TrayAutostart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TrayExePath,
        [string]$LogFile,
        [string]$RunKeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        [string]$ValueName  = 'SentinelTray'
    )
    try {
        # Create the Run key if missing (it normally exists, but guard it).
        if (-not (Test-Path $RunKeyPath)) {
            New-Item -Path $RunKeyPath -Force | Out-Null
        }
        # Quote the exe path so it survives a %USERPROFILE% containing spaces
        # (e.g. C:\Users\Jane Doe\.sentinel\bin\...). -Force overwrites the same
        # single value on reinstall (idempotent — no duplicate).
        $quotedPath = '"' + $TrayExePath + '"'
        New-ItemProperty -Path $RunKeyPath -Name $ValueName -Value $quotedPath -PropertyType String -Force | Out-Null
        Write-InstallLog -Message "Tray autostart registered: $RunKeyPath\$ValueName -> $TrayExePath" -Level INFO -LogFile $LogFile
    } catch {
        Write-InstallLog -Message "Tray autostart registration failed for ${ValueName} (continuing): $($_.Exception.Message)" -Level WARN -LogFile $LogFile
        return
    }
}

# ---------------------------------------------------------------------------
# Start-TrayHelper: fire-and-forget launch of the tray exe immediately after
# install so the user sees the RunTrust status icon without waiting for next
# login. Best-effort: a missing exe or a launch failure logs a WARN and returns
# $false — it NEVER throws, mirroring Set-RestrictiveAcl / Set-TrayAutostart.
# Returns $true when Start-Process actually succeeded, $false otherwise (exe
# missing or launch threw). The caller uses this to print an accurate console
# line — suppressing the false "tray started" claim on a skipped launch.
# ---------------------------------------------------------------------------
function Start-TrayHelper {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TrayExePath,
        [string]$LogFile
    )
    if (-not (Test-Path $TrayExePath)) {
        Write-InstallLog -Message "Tray exe not found, skipping launch: $TrayExePath" -Level WARN -LogFile $LogFile
        return $false
    }
    try {
        Start-Process -FilePath $TrayExePath
        Write-InstallLog -Message "Tray launched: $TrayExePath" -Level INFO -LogFile $LogFile
        return $true
    } catch {
        Write-InstallLog -Message "Tray launch failed (continuing): $($_.Exception.Message)" -Level WARN -LogFile $LogFile
        return $false
    }
}

# ---------------------------------------------------------------------------
# ConvertTo-MutableHashtable: deep-convert PSCustomObject/array into hashtables
# so we can merge/edit settings.json freely. Arrays are preserved as arrays.
# ---------------------------------------------------------------------------
function ConvertTo-MutableHashtable {
    param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process {
        if ($null -eq $InputObject) { return $null }
        if ($InputObject -is [hashtable]) {
            $h = @{}
            foreach ($k in $InputObject.Keys) { $h[$k] = ConvertTo-MutableHashtable $InputObject[$k] }
            return $h
        }
        if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
            $h = @{}
            foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = ConvertTo-MutableHashtable $p.Value }
            return $h
        }
        if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
            $arr = @()
            foreach ($item in $InputObject) { $arr += ,(ConvertTo-MutableHashtable $item) }
            return ,$arr
        }
        return $InputObject
    }
}

# ---------------------------------------------------------------------------
# Invoke-SentinelSetup: the install flow WITHOUT wiring the cc-hook into
# ~/.claude/settings.json (section 5 omitted). This is the exact body of the
# original Install-Sentinel with only the Merge-ClaudeHook call removed; the
# returned object is EXTENDED with SettingsPath/LogFile/Probe so a
# caller (e.g. Install-SentinelDeprecated) can wire the hook afterward. The
# daemon credential (ApiKey) is deliberately NOT returned (see the SECURITY
# note in the return block).
#
# This reordering is behavior-preserving: the first-decision probe drives the
# hook EXE directly via Invoke-HookExe (NOT through settings.json), so wiring
# the hook after the probe changes no result.
# ---------------------------------------------------------------------------
function Invoke-SentinelSetup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InstallToken,
        [string]$Endpoint = 'https://app.runtrust.ai',
        [string]$SentinelHome = (Join-Path $env:USERPROFILE '.sentinel'),
        # Re-exchange the install token even when the existing config already
        # holds a live daemon credential (the reinstall heuristic otherwise skips).
        [switch]$Force
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $binDir  = Join-Path $SentinelHome 'bin'
    $logDir  = Join-Path $SentinelHome 'logs'
    $logFile = Join-Path $logDir 'install.log'
    $redToken = Redact-Secret $InstallToken

    $hookName   = 'sentinel-cc-hook-win-x64.exe'
    $daemonName = 'sentinel-cc-daemon-win-x64.exe'
    $statusName = 'sentinel-status-win-x64.exe'
    $trayName   = 'sentinel-tray-win-x64.exe'

    try {
        # ----- 1. Preflight -------------------------------------------------
        if (-not (Test-PSVersionSupported -Version $PSVersionTable.PSVersion)) {
            throw "PowerShell 5.1+ required (found $($PSVersionTable.PSVersion))."
        }
        foreach ($d in @($SentinelHome, $binDir, $logDir)) {
            if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        }
        Write-InstallLog -Message "Preflight OK. SentinelHome=$SentinelHome token=$redToken endpoint=$Endpoint" -Level INFO -LogFile $logFile
        Set-RestrictiveAcl -Path $SentinelHome -LogFile $logFile

        $configPath = Join-Path $SentinelHome 'config.json'

        # ----- 1b. Device identity (stable, operator-visible hostname) -------
        # Derived BEFORE the exchange so the device assertions can ride along in
        # the request body. The salt-fallback path persists `deviceSalt` into
        # config.json via the merge writer (never a wholesale overwrite).
        $device = Get-SentinelDeviceId -ConfigPath $configPath
        $deviceId = [string]$device.DeviceId
        $deviceHostname = [string]$device.DeviceHostname
        Write-InstallLog -Message "Device identity: deviceId=$deviceId hostname=$deviceHostname" -Level INFO -LogFile $logFile

        # ----- 1c. Reinstall liveness heuristic -----------------------------
        # If an existing config already holds a live daemon credential (decoded
        # exp > now+24h AND tenantId+installationId claims present), SKIP the
        # exchange — UNLESS -Force was passed. No signature verification: the
        # installer has no signing secret, this is a liveness/continuity check.
        $existingConfig = Read-SentinelConfig -ConfigPath $configPath
        $existingApiKey = if ($existingConfig.ContainsKey('apiKey')) { [string]$existingConfig['apiKey'] } else { $null }
        $credentialLive = Test-SentinelCredentialValid -ApiKey $existingApiKey
        $skipExchange = ($credentialLive -and -not $Force)

        if ($skipExchange) {
            Write-InstallLog -Message "Existing credential is live (exp > now+24h, claims present); skipping exchange (pass -Force to re-exchange)." -Level INFO -LogFile $logFile
            # Fix 5: when an install token was explicitly supplied but exchange is
            # being skipped, surface that the supplied token was NOT used — on a
            # shared OS profile this would silently keep a different user's credential.
            if (-not [string]::IsNullOrWhiteSpace($InstallToken)) {
                $skipWarn = "WARNING: existing live Sentinel credential found; skipping exchange. The supplied install token was NOT used. Re-run with -Force to rebind this machine to the new token."
                Write-InstallLog -Message $skipWarn -Level WARN -LogFile $logFile
                Write-Warning $skipWarn
            }
            $resolvedEndpoint = if ($existingConfig.ContainsKey('endpoint') -and $existingConfig['endpoint']) { [string]$existingConfig['endpoint'] } else { $Endpoint }
            $tenantId = if ($existingConfig.ContainsKey('tenantId')) { [string]$existingConfig['tenantId'] } else { '' }
            $apiKey   = $existingApiKey
            $installationId = if ($existingConfig.ContainsKey('installationId')) { [string]$existingConfig['installationId'] } else { '' }
            $redKey = Redact-Secret $apiKey
        } else {
            # ----- 2. Exchange install token --------------------------------
            if ($Force) {
                Write-InstallLog -Message "-Force specified; re-exchanging install token regardless of existing credential." -Level INFO -LogFile $logFile
            }
            Write-InstallLog -Message "Exchanging install token $redToken at $Endpoint/v1/install/exchange" -Level INFO -LogFile $logFile
            $exchanged = $null
            try {
                $body = @{
                    installToken   = $InstallToken
                    deviceId       = $deviceId
                    deviceHostname = $deviceHostname
                } | ConvertTo-Json
                $exchanged = Invoke-RestMethod -Method Post -Uri "$Endpoint/v1/install/exchange" -Body $body -ContentType 'application/json'
            } catch {
                throw "Install-token exchange failed for token $redToken : $($_.Exception.Message)"
            }
            if ($null -eq $exchanged -or -not $exchanged.apiKey -or -not $exchanged.tenantId) {
                throw "Install-token exchange returned an incomplete response for token $redToken."
            }
            $resolvedEndpoint = if ($exchanged.endpoint) { [string]$exchanged.endpoint } else { $Endpoint }
            $tenantId = [string]$exchanged.tenantId
            $apiKey   = [string]$exchanged.apiKey
            $installationId = if ($exchanged.PSObject.Properties.Name -contains 'installationId' -and $exchanged.installationId) { [string]$exchanged.installationId } else { '' }
            $expiresAtMs = $exchanged.expiresAtMs
            $redKey = Redact-Secret $apiKey
            Write-InstallLog -Message "Exchange OK. tenantId=$tenantId apiKey=$redKey endpoint=$resolvedEndpoint expiresAtMs=$expiresAtMs installationId=$installationId" -Level INFO -LogFile $logFile
        }

        # ----- 3. Download + checksum-verify --------------------------------
        $hookDownload   = Join-Path $binDir ($hookName + '.download')
        $daemonDownload = Join-Path $binDir ($daemonName + '.download')
        $statusDownload = Join-Path $binDir ($statusName + '.download')
        $trayDownload   = Join-Path $binDir ($trayName + '.download')
        $checksumPath   = Join-Path $binDir 'checksums.txt'

        # All staged temp files — used for cleanup on any verification abort so a
        # partial download never lingers in $binDir.
        $allDownloads = @($hookDownload, $daemonDownload, $statusDownload, $trayDownload, $checksumPath)

        Write-InstallLog -Message "Downloading binaries + checksums from $Endpoint/downloads/" -Level INFO -LogFile $logFile
        Invoke-WebRequest -Uri "$Endpoint/downloads/$hookName"   -OutFile $hookDownload   -UseBasicParsing | Out-Null
        Invoke-WebRequest -Uri "$Endpoint/downloads/$daemonName" -OutFile $daemonDownload -UseBasicParsing | Out-Null
        Invoke-WebRequest -Uri "$Endpoint/downloads/$statusName" -OutFile $statusDownload -UseBasicParsing | Out-Null
        Invoke-WebRequest -Uri "$Endpoint/downloads/$trayName"   -OutFile $trayDownload   -UseBasicParsing | Out-Null
        Invoke-WebRequest -Uri "$Endpoint/downloads/checksums.txt" -OutFile $checksumPath -UseBasicParsing | Out-Null

        $manifest = @{}
        foreach ($line in (Get-Content $checksumPath)) {
            $t = $line.Trim()
            if (-not $t) { continue }
            # Format: "<sha256>  <filename>" (sha256sum style: two spaces, leading * optional)
            $parts = $t -split '\s+', 2
            if ($parts.Count -eq 2) {
                $fname = $parts[1].TrimStart('*').Trim()
                $manifest[$fname] = $parts[0].Trim().ToLowerInvariant()
            }
        }

        # Verify ALL FOUR staged exes against the manifest BEFORE any config is
        # written. A missing manifest entry OR a hash mismatch for ANY of them
        # aborts the install (and cleans up every partial download) so we never
        # place an unverified binary or write config off a tampered download.
        $verifyPairs = @(
            @{ File = $hookDownload;   Name = $hookName },
            @{ File = $daemonDownload; Name = $daemonName },
            @{ File = $statusDownload; Name = $statusName },
            @{ File = $trayDownload;   Name = $trayName }
        )
        foreach ($p in $verifyPairs) {
            if (-not $manifest.ContainsKey($p.Name)) {
                Remove-Item -Force $allDownloads -ErrorAction SilentlyContinue
                throw "Checksum manifest has no entry for $($p.Name); aborting before writing config."
            }
            $actual = (Get-FileHash -Path $p.File -Algorithm SHA256).Hash.ToLowerInvariant()
            $expected = $manifest[$p.Name]
            if ($actual -ne $expected) {
                Remove-Item -Force $allDownloads -ErrorAction SilentlyContinue
                throw "Checksum MISMATCH for $($p.Name) (expected $expected, got $actual); aborting before writing config."
            }
            Write-InstallLog -Message "Checksum OK for $($p.Name)" -Level INFO -LogFile $logFile
        }

        # All good — move into place.
        $hookExe   = Join-Path $binDir $hookName
        $daemonExe = Join-Path $binDir $daemonName
        $statusExe = Join-Path $binDir $statusName
        $trayExe   = Join-Path $binDir $trayName
        Move-Item -Path $hookDownload   -Destination $hookExe   -Force
        Move-Item -Path $daemonDownload -Destination $daemonExe -Force
        Move-Item -Path $statusDownload -Destination $statusExe -Force
        Move-Item -Path $trayDownload   -Destination $trayExe   -Force
        Write-InstallLog -Message "Verified binaries placed in $binDir" -Level INFO -LogFile $logFile
        Write-InstallLog -Message "Status + tray binaries verified + placed: $statusExe, $trayExe" -Level INFO -LogFile $logFile

        # ----- 4. Config (backup, then READ-MODIFY-WRITE merge) -------------
        # Merge (never blind-overwrite) so unknown keys survive — especially
        # `deviceSalt`, whose loss would rotate the device identity on the next
        # install. installationId/deviceId/deviceHostname are persisted too.
        if (Test-Path $configPath) {
            $bak = "$configPath.bak." + (Get-Date).ToString('yyyyMMddHHmmss')
            Copy-Item -Path $configPath -Destination $bak -Force
            Write-InstallLog -Message "Backed up existing config.json -> $(Split-Path -Leaf $bak)" -Level INFO -LogFile $logFile
        }
        $configValues = @{
            endpoint       = $resolvedEndpoint
            tenantId       = $tenantId
            apiKey         = $apiKey
            daemonPath     = $daemonExe
            environment    = 'prod'
            installationId = $installationId
            deviceId       = $deviceId
            deviceHostname = $deviceHostname
        }
        [void](Save-SentinelConfig -ConfigPath $configPath -Values $configValues)
        Set-RestrictiveAcl -Path $configPath -LogFile $logFile
        Write-InstallLog -Message "Wrote config.json (apiKey=$redKey tenantId=$tenantId installationId=$installationId deviceId=$deviceId)" -Level INFO -LogFile $logFile

        # ----- 5. Wire cc-hook into Claude Code -----------------------------
        # OMITTED in Invoke-SentinelSetup. The settings.json path is returned so
        # a caller (Install-SentinelDeprecated) can wire the hook afterward; the
        # first-decision probe drives the hook exe directly, so wiring order does
        # not affect the probe result.
        $settingsPath = Join-Path $env:USERPROFILE '.claude\settings.json'

        # ----- 5b. Register tray autostart (HKCU Run) -----------------------
        # Best-effort: registers the tray to start on user login. The tray exe
        # is already verified + placed and config is written, so it exists.
        # Internal try/catch keeps autostart failure from failing the install.
        Set-TrayAutostart -TrayExePath $trayExe -LogFile $logFile

        # ----- 5c. Launch tray immediately (best-effort) --------------------
        # Fire-and-forget so the user sees the RunTrust status icon in the
        # system tray right now, without waiting for the next login.
        # Capture the bool return so the final console line is ACCURATE: if the
        # tray actually launched we say so; if it was skipped (exe missing or
        # Start-Process threw) we say autostart-only instead of falsely claiming
        # the icon is already visible.
        $trayLaunched = Start-TrayHelper -TrayExePath $trayExe -LogFile $logFile

        # ----- 6. Health checks ---------------------------------------------
        Write-InstallLog -Message "Health: GET $resolvedEndpoint/ui/login" -Level INFO -LogFile $logFile
        try {
            $loginResp = Invoke-WebRequest -Uri "$resolvedEndpoint/ui/login" -UseBasicParsing -Method Get
            if ($loginResp.StatusCode -ne 200) {
                Write-InstallLog -Message "ui/login returned $($loginResp.StatusCode) (expected 200)" -Level WARN -LogFile $logFile
            } else {
                Write-InstallLog -Message "Reachability OK (ui/login 200)" -Level INFO -LogFile $logFile
            }
        } catch {
            throw "Reachability probe failed (GET $resolvedEndpoint/ui/login): $($_.Exception.Message)"
        }

        Write-InstallLog -Message "Health: GET $resolvedEndpoint/v1/audit/recent?tenant_id=$tenantId (Bearer $redKey)" -Level INFO -LogFile $logFile
        try {
            $auditResp = Invoke-WebRequest -Uri "$resolvedEndpoint/v1/audit/recent?tenant_id=$tenantId" `
                -Headers @{ Authorization = "Bearer $apiKey" } -UseBasicParsing -Method Get
            $code = $auditResp.StatusCode
            if ($code -eq 200 -or $code -eq 503) {
                Write-InstallLog -Message "Credential check OK (audit/recent $code)" -Level INFO -LogFile $logFile
            } else {
                Write-InstallLog -Message "audit/recent returned unexpected $code" -Level WARN -LogFile $logFile
            }
        } catch {
            # 401 => bad daemon credential: fail loudly. Other codes (503) are acceptable.
            $status = $null
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if ($status -eq 401) {
                throw "Daemon credential rejected (audit/recent 401) for apiKey=$redKey — install aborted."
            } elseif ($status -eq 503) {
                Write-InstallLog -Message "Credential check OK (audit/recent 503 — audit DB absent, JWT accepted)" -Level INFO -LogFile $logFile
            } else {
                Write-InstallLog -Message "audit/recent probe error (status=$status): $($_.Exception.Message)" -Level WARN -LogFile $logFile
            }
        }

        # ----- 7. First decision probe (best-effort, structured result) -----
        # Authoritative confirmation is "a NEW audit row landed for this tenant
        # after we drove a tool call through the hook" — NOT the hook exit code
        # (the hook always exits 0, even when the daemon is unreachable).
        $probe = Invoke-FirstDecisionProbe -HookExePath $hookExe -SentinelHome $SentinelHome `
            -Endpoint $resolvedEndpoint -TenantId $tenantId -ApiKey $apiKey -LogFile $logFile
        # Be defensive: a (mocked) probe may return a bare value; coerce to shape.
        $firstDecisionConfirmed = $false
        $probeDetail = ''
        if ($probe -is [hashtable] -and $probe.ContainsKey('Confirmed')) {
            $firstDecisionConfirmed = [bool]$probe['Confirmed']
            $probeDetail = [string]$probe['Detail']
        } else {
            $probeDetail = [string]$probe
        }
        Write-InstallLog -Message "First-decision probe: confirmed=$firstDecisionConfirmed detail=$probeDetail" -Level INFO -LogFile $logFile

        # ----- 8. Final outcome (CONDITIONAL on first-decision confirmation) -
        # The install (config + hook wiring) is valid regardless — never roll
        # back here. But we MUST NOT report unqualified success when the first
        # decision was not confirmed (daemon/gateway may be unreachable).
        $decisionsUrl = "$resolvedEndpoint/ui/"
        if ($firstDecisionConfirmed) {
            Write-InstallLog -Message "Install complete; first decision confirmed. Decisions URL: $decisionsUrl (tenant $tenantId)" -Level INFO -LogFile $logFile
            Write-Host ""
            Write-Host "✓ Sentinel / RunTrust installed; first decision sent." -ForegroundColor Green
            Write-Host "  Tenant:    $tenantId"
            Write-Host "  Decisions: $decisionsUrl  (see $resolvedEndpoint/ui/ under tenant $tenantId)"
            if ($trayLaunched) {
                Write-Host "  Tray:      status helper started — look for the RunTrust icon in your system tray."
            } else {
                Write-Host "  Tray:      autostart configured; the RunTrust status icon will appear on next sign-in (immediate launch was skipped — see install.log)."
            }
            Write-Host ""
        } else {
            $warn = "Setup completed BUT the first decision was not confirmed ($probeDetail). " +
                    "Sentinel is configured (config is valid), but verify the " +
                    "daemon/gateway and re-run the probe; the tenant may show no first decision yet."
            Write-InstallLog -Message $warn -Level WARN -LogFile $logFile
            Write-Host ""
            Write-Host "============================================================" -ForegroundColor Yellow
            Write-Host " ⚠ WARNING: first decision NOT confirmed" -ForegroundColor Yellow
            Write-Host "------------------------------------------------------------" -ForegroundColor Yellow
            Write-Host " $warn" -ForegroundColor Yellow
            Write-Host "   Tenant:    $tenantId"
            Write-Host "   Decisions: $decisionsUrl"
            Write-Host "============================================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Warning $warn
        }

        return [pscustomobject]@{
            Installed              = $true
            FirstDecisionConfirmed = $firstDecisionConfirmed
            FirstDecisionDetail    = $probeDetail
            Endpoint               = $resolvedEndpoint
            TenantId               = $tenantId
            ConfigPath             = $configPath
            HookExe                = $hookExe
            DaemonExe              = $daemonExe
            DecisionsUrl           = $decisionsUrl
            # ---- extended fields so the deprecated wrapper can wire the hook ----
            # SECURITY: the daemon credential ($apiKey) is deliberately NOT returned.
            # PowerShell writes a function's return object to stdout, so including the
            # JWT here would leak it into Claude Code output/transcripts. The probe
            # consumes $apiKey internally; no caller needs it.
            SettingsPath           = $settingsPath
            LogFile                = $logFile
            Probe                  = $probe
        }
    } catch {
        Write-InstallLog -Message "INSTALL FAILED: $($_.Exception.Message)" -Level ERROR -LogFile $logFile
        throw
    }
}

# ---------------------------------------------------------------------------
# Install-SentinelDeprecated: reproduce the ORIGINAL Install-Sentinel end-state
# (settings.json wired) on top of the section-5-less Invoke-SentinelSetup. This
# is behaviorally equivalent to the original: the first-decision probe drives
# the hook EXE directly via Invoke-HookExe (NOT through settings.json), so
# wiring the hook AFTER the probe changes no result.
# ---------------------------------------------------------------------------
function Install-SentinelDeprecated {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InstallToken,
        [string]$Endpoint = 'https://app.runtrust.ai',
        [string]$SentinelHome = (Join-Path $env:USERPROFILE '.sentinel'),
        [switch]$Force
    )
    $r = Invoke-SentinelSetup @PSBoundParameters
    Merge-ClaudeHook -SettingsPath $r.SettingsPath -HookExePath $r.HookExe -LogFile $r.LogFile
    return $r
}

# ---------------------------------------------------------------------------
# Get-SentinelStatus: the live connector status, sourced from the status exe
# (the single source of truth). Does NOT re-derive tenant/mode/reachability in
# PowerShell.
#
#   - status exe ABSENT  -> pre-setup object (State='not-setup').
#   - status exe PRESENT -> run `<exe> --json`, capture stdout, and check the
#                           shim NDJSON log for any `shim-delegate-failed` line.
#                           Returns State='setup' with the raw StatusJson and a
#                           ShimDegraded flag.
# Never throws.
# ---------------------------------------------------------------------------
function Get-SentinelStatus {
    [CmdletBinding()]
    param(
        [string]$SentinelHome = (Join-Path $env:USERPROFILE '.sentinel'),
        # Test seam: override the status exe path (mirrors the shim's -HookExe).
        [string]$StatusExe
    )

    if (-not $StatusExe -or $StatusExe -eq '') {
        $StatusExe = Join-Path (Join-Path $SentinelHome 'bin') 'sentinel-status-win-x64.exe'
    }
    $statusExe = $StatusExe

    if (-not (Test-Path $statusExe)) {
        return [pscustomobject]@{
            State   = 'not-setup'
            Message = 'Sentinel plugin installed — run /sentinel:setup to provision the connector.'
        }
    }

    # The exe is the single source of truth. Capture STDOUT ONLY — the exe may
    # write diagnostics to stderr while emitting JSON on stdout, and merging the
    # streams (2>&1) would corrupt the JSON returned to /sentinel:status. Route
    # stderr to $null so only the JSON stdout is captured.
    $statusJson = ''
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $statusExe --json 2>$null
        $statusJson = (($out | Out-String).Trim())
    } catch {
        $statusJson = ''
    } finally {
        $ErrorActionPreference = $prevPref
    }

    # Detect shim degradation from the shim NDJSON log (best-effort).
    $shimDegraded = $false
    $shimLog = Join-Path (Join-Path $SentinelHome 'logs') 'sentinel-shim.ndjson'
    if (Test-Path $shimLog) {
        try {
            # Bound the read: only the recent shim-delegate-failed entries matter,
            # and the NDJSON log can grow unbounded. -Tail 200 caps memory/time.
            $shimLines = Get-Content -Path $shimLog -Tail 200 -ErrorAction SilentlyContinue
            foreach ($l in $shimLines) {
                if ($l -match 'shim-delegate-failed') { $shimDegraded = $true; break }
            }
        } catch {
            $shimDegraded = $false
        }
    }

    return [pscustomobject]@{
        State        = 'setup'
        StatusJson   = $statusJson
        ShimDegraded = $shimDegraded
    }
}

# ---------------------------------------------------------------------------
# Export everything. (Redact-Secret uses an unapproved verb deliberately — kept
# verbatim for compatibility with sentinel-install.ps1. Wildcard export plus a
# -DisableNameChecking import on the consumer side suppresses the warning.)
# ---------------------------------------------------------------------------
Export-ModuleMember -Function *
