[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$InstallToken,
  # No default - no endpoint, no setup (decision 15): the console's Install page renders
  # the command with the address of the console that issued the token.
  [string]$Endpoint,
  [string]$SentinelHome = (Join-Path $env:USERPROFILE '.sentinel')
)
# Refused here, before the module runs, with the Install-page message. An explicit check,
# not [Parameter(Mandatory)]: a missing Mandatory value makes powershell.exe prompt on
# stdin, which hangs or errors under Claude Code's Bash tool (decision 22).
if ([string]::IsNullOrWhiteSpace($Endpoint)) { throw "no endpoint given - copy the command from your console's Install page" }
Import-Module (Join-Path $PSScriptRoot 'SentinelCore.psm1') -Force -DisableNameChecking
# NO Merge-ClaudeHook — the plugin's hooks/hooks.json owns the PreToolUse wiring.
$result = Invoke-SentinelSetup -InstallToken $InstallToken -Endpoint $Endpoint -SentinelHome $SentinelHome
# Print a clean, REDACTED confirmation. Never echo the install token or any secret.
Write-Host ""
Write-Host "RunTrust/Sentinel setup result:"
Write-Host ("  Installed:               " + $result.Installed)
Write-Host ("  FirstDecisionConfirmed:  " + $result.FirstDecisionConfirmed)
Write-Host ("  Detail:                  " + $result.FirstDecisionDetail)
Write-Host ("  Tenant:                  " + $result.TenantId)
Write-Host ("  Endpoint:                " + $result.Endpoint)
Write-Host ("  Decisions:               " + $result.DecisionsUrl)
# Return the object too (without secrets — Invoke-SentinelSetup already omits ApiKey).
$result
