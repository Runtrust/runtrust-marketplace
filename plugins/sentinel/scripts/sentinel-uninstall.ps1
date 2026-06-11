[CmdletBinding()]
param([string]$SentinelHome = (Join-Path $env:USERPROFILE '.sentinel'))
Import-Module (Join-Path $PSScriptRoot 'SentinelCore.psm1') -Force -DisableNameChecking
Uninstall-Sentinel -SentinelHome $SentinelHome
Write-Host "RunTrust/Sentinel connector removed from $SentinelHome. (To remove the plugin itself, run /plugin uninstall sentinel.)"
