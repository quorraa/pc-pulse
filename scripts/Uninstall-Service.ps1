[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$InstallDirectory = (Join-Path $env:ProgramFiles 'PC Pulse'),
    [switch]$KeepHistory
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this uninstall script from an elevated PowerShell window.'
}
if ($PSCmdlet.ShouldProcess('PcPulseCollector', 'Stop and remove service')) {
    Stop-Service -Name 'PcPulseCollector' -Force -ErrorAction SilentlyContinue
    & sc.exe delete 'PcPulseCollector' | Out-Null
}
Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' `
    -Name 'PcPulseNotify' -ErrorAction SilentlyContinue
$notifier = Get-Process -Name 'PcPulse.Notify' -ErrorAction SilentlyContinue
if ($notifier) {
    $notifier | Stop-Process -Force
}
$resolvedInstall = [IO.Path]::GetFullPath($InstallDirectory).TrimEnd('\')
$programFilesRoot = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\')
if (-not $resolvedInstall.StartsWith($programFilesRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to remove a directory outside Program Files: $resolvedInstall"
}
if (Test-Path -LiteralPath $resolvedInstall) {
    Remove-Item -LiteralPath $resolvedInstall -Recurse -Force
}
if (-not $KeepHistory) {
    $dataDirectory = Join-Path $env:ProgramData 'PcPulse'
    if ($PSCmdlet.ShouldProcess($dataDirectory, 'Remove PC Pulse history and settings')) {
        Remove-Item -LiteralPath $dataDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}
