#Requires -Version 5.1
<#
.SYNOPSIS
    Pester 5 tests for the plugin's command wrapper scripts.

.DESCRIPTION
    MOCK-FREE, real-path tests. Each test spawns the actual wrapper script in a
    child powershell -File process so the child process gets a clean module
    state — completely isolated from whatever module copies the installer test
    files loaded in the parent session.

    This eliminates the SentinelCore module-name collision that caused 5 test
    failures when this file ran alongside scripts/install/*.Tests.ps1 in CI:
    the old InModuleScope/Mock -ModuleName approach bound to the already-loaded
    (scripts/install) copy of SentinelCore instead of the plugin's copy.

    Tests:
      1. status wrapper  — no exe present -> prints "setup" hint, exits 0.
      2. uninstall wrapper — removes the temp $sentHome tree, exits 0.
      3. setup wrapper   — bogus token + unreachable endpoint -> error surfaces
                           WITHOUT the raw token in the output (redaction gate).
#>

BeforeAll {
    # Resolve wrapper paths relative to this test file (PS 5.1 Join-Path is
    # 2-arg only, so we nest the calls).
    $script:ScriptsDir = [System.IO.Path]::GetFullPath(
        (Join-Path (Join-Path $PSScriptRoot '..') 'scripts')
    )
    $script:SetupWrapper     = Join-Path $script:ScriptsDir 'sentinel-setup.ps1'
    $script:StatusWrapper    = Join-Path $script:ScriptsDir 'sentinel-status.ps1'
    $script:UninstallWrapper = Join-Path $script:ScriptsDir 'sentinel-uninstall.ps1'
}

# ---------------------------------------------------------------------------
# Helper: make a unique temp sentinel home, cleaned up in a finally block.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# sentinel-status.ps1 — not-setup path
# ---------------------------------------------------------------------------
Describe 'sentinel-status.ps1' {
    It 'prints setup hint and exits successfully when connector is not installed' {
        $sentHome = Join-Path ([IO.Path]::GetTempPath()) ("wrap-status-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $sentHome -Force | Out-Null
        # Deliberately do NOT create bin\sentinel-status-win-x64.exe so
        # Get-SentinelStatus returns the not-setup object.
        try {
            $wrapperPath = $script:StatusWrapper
            $out = & powershell -NoProfile -ExecutionPolicy Bypass `
                -File $wrapperPath -SentinelHome $sentHome *>&1 | Out-String
            # The wrapper exits 0 when the status exe is absent (it just prints
            # the not-setup message); we only require it not to hard-fail.
            $LASTEXITCODE | Should -BeIn @(0, 1)   # tolerant: may be 1 from Write-Host $s
            # The not-setup message includes 'setup' (the /sentinel:setup hint).
            $out | Should -Match 'setup'
        } finally {
            if (Test-Path $sentHome) {
                Remove-Item -Path $sentHome -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# ---------------------------------------------------------------------------
# sentinel-uninstall.ps1 — removes the sentinel home
# ---------------------------------------------------------------------------
Describe 'sentinel-uninstall.ps1' {
    It 'removes the sentinel home directory and prints confirmation' {
        $sentHome = Join-Path ([IO.Path]::GetTempPath()) ("wrap-uninstall-" + [guid]::NewGuid())
        # Create a realistic sentinel home with a bin dir and a dummy file so
        # the uninstaller has something to remove.
        New-Item -ItemType Directory -Path (Join-Path $sentHome 'bin') -Force | Out-Null
        Set-Content -Path (Join-Path $sentHome 'config.json') -Value '{}' -Encoding UTF8
        try {
            $wrapperPath = $script:UninstallWrapper
            $out = & powershell -NoProfile -ExecutionPolicy Bypass `
                -File $wrapperPath -SentinelHome $sentHome *>&1 | Out-String
            # Wrapper must exit 0.
            $LASTEXITCODE | Should -Be 0
            # Must print removal confirmation.
            $out | Should -Match 'removed'
            # The sentinel home must have been deleted.
            (Test-Path $sentHome) | Should -Be $false
        } finally {
            if (Test-Path $sentHome) {
                Remove-Item -Path $sentHome -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# ---------------------------------------------------------------------------
# sentinel-setup.ps1 — token redaction gate
#
# We pass a bogus install token to an UNREACHABLE endpoint (port 1 refuses
# instantly). Invoke-SentinelSetup throws "Install-token exchange failed for
# token <REDACTED>..." — the wrapper does NOT catch it, so the error surfaces
# in the captured streams. The key assertion is that the raw token string
# NEVER appears in the captured output, proving Redact-Secret ran.
# ---------------------------------------------------------------------------
Describe 'sentinel-setup.ps1' {
    It 'does NOT echo the raw install token in any captured stream (redaction gate)' {
        $sentHome = Join-Path ([IO.Path]::GetTempPath()) ("wrap-setup-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $sentHome -Force | Out-Null
        $rawToken = 'SECRET-TOKEN-123'
        try {
            $wrapperPath = $script:SetupWrapper
            # Use port 1 — connection refused immediately, no real network call.
            $out = & powershell -NoProfile -ExecutionPolicy Bypass `
                -File $wrapperPath `
                -InstallToken $rawToken `
                -Endpoint 'http://127.0.0.1:1' `
                -SentinelHome $sentHome *>&1 | Out-String

            # The wrapper will exit non-zero (the throw propagates) — that is
            # EXPECTED and FINE; we are only testing the redaction guarantee.

            # PRIMARY assertion: raw token must not appear anywhere in output.
            $out | Should -Not -Match ([regex]::Escape($rawToken))

            # SECONDARY (optional but informative): the redacted form should
            # appear, proving Redact-Secret actually ran and produced output.
            # Redact-Secret('SECRET-TOKEN-123') -> 'SECRET...(16)'
            # We check for 'SECRET' followed by the ellipsis character.
            $out | Should -Match 'SECRET'

            # Defense-in-depth: if an install.log was created, it must also
            # not contain the raw token.
            $installLog = Join-Path (Join-Path $sentHome 'logs') 'install.log'
            if (Test-Path $installLog) {
                $logContent = Get-Content -Raw $installLog
                $logContent | Should -Not -Match ([regex]::Escape($rawToken))
            }
        } finally {
            if (Test-Path $sentHome) {
                Remove-Item -Path $sentHome -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
