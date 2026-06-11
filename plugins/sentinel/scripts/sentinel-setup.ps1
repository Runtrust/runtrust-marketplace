[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$InstallToken,
  [string]$Endpoint = 'https://app.runtrust.ai',
  [string]$SentinelHome = (Join-Path $env:USERPROFILE '.sentinel')
)
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
