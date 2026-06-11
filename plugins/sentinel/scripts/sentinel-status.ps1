[CmdletBinding()]
param([string]$SentinelHome = (Join-Path $env:USERPROFILE '.sentinel'))
Import-Module (Join-Path $PSScriptRoot 'SentinelCore.psm1') -Force -DisableNameChecking
$s = Get-SentinelStatus -SentinelHome $SentinelHome
if ($s.State -eq 'not-setup') {
  Write-Host $s.Message
} else {
  if ($s.ShimDegraded) { Write-Host 'WARNING: shim degraded - see ~/.sentinel/logs/sentinel-shim.ndjson' }
  Write-Host $s.StatusJson
}
$s
