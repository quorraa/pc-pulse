[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SourceDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts\publish'),
    [string]$InstallDirectory = (Join-Path $env:ProgramFiles 'PC Pulse')
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this setup script from an elevated PowerShell window.'
}
$serviceSource = Join-Path $SourceDirectory 'PcPulse.Service.exe'
$tuiSource = Join-Path $SourceDirectory 'PcPulse.exe'
$notifierSource = Join-Path $SourceDirectory 'PcPulse.Notify.exe'
if (-not (Test-Path -LiteralPath $serviceSource) -or
    -not (Test-Path -LiteralPath $tuiSource) -or
    -not (Test-Path -LiteralPath $notifierSource)) {
    throw 'Release binaries are missing. Run scripts\Build-Release.ps1 first.'
}
if ($PSCmdlet.ShouldProcess($InstallDirectory, 'Install PC Pulse and register its collector service')) {
    New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
    Copy-Item -LiteralPath $serviceSource -Destination (Join-Path $InstallDirectory 'PcPulse.Service.exe') -Force
    Copy-Item -LiteralPath $tuiSource -Destination (Join-Path $InstallDirectory 'PcPulse.exe') -Force
    Copy-Item -LiteralPath $notifierSource -Destination (Join-Path $InstallDirectory 'PcPulse.Notify.exe') -Force
    $existing = Get-Service -Name 'PcPulseCollector' -ErrorAction SilentlyContinue
    if ($existing) {
        Stop-Service -Name 'PcPulseCollector' -Force -ErrorAction SilentlyContinue
        & sc.exe delete 'PcPulseCollector' | Out-Null
        Start-Sleep -Milliseconds 500
    }
    $binaryPath = '"{0}"' -f (Join-Path $InstallDirectory 'PcPulse.Service.exe')
    & sc.exe create 'PcPulseCollector' binPath= $binaryPath start= auto obj= LocalSystem DisplayName= 'PC Pulse Collector' | Out-Null
    if ($LASTEXITCODE) { throw 'Service creation failed.' }
    & sc.exe description 'PcPulseCollector' 'Low-overhead Windows performance collector for PC Pulse.' | Out-Null
    & sc.exe failure 'PcPulseCollector' reset= 86400 actions= restart/15000/restart/30000/none/0 | Out-Null
    & sc.exe failureflag 'PcPulseCollector' 1 | Out-Null
    Start-Service -Name 'PcPulseCollector'
    $runKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    New-ItemProperty -Path $runKey -Name 'PcPulseNotify' -PropertyType String `
        -Value ('"{0}"' -f (Join-Path $InstallDirectory 'PcPulse.Notify.exe')) -Force | Out-Null
    Write-Host "Installed PC Pulse. TUI: $InstallDirectory\PcPulse.exe"
    Write-Host 'The native notification helper starts at the next user logon.'
}
