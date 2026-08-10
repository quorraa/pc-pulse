[CmdletBinding()]
param(
    [ValidateSet('x64')]
    [string]$Architecture = 'x64',
    [string]$Version = '1.9.1',
    [string]$CertificateThumbprint,
    [string]$TimestampUrl = 'http://timestamp.digicert.com',
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$artifacts = Join-Path $repo 'artifacts'
$publish = Join-Path $artifacts 'publish'
$resolvedRepo = [IO.Path]::GetFullPath($repo).TrimEnd('\')
$resolvedArtifacts = [IO.Path]::GetFullPath($artifacts).TrimEnd('\')
if (-not $resolvedArtifacts.StartsWith($resolvedRepo + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean an artifacts path outside the repository: $resolvedArtifacts"
}
if (Test-Path -LiteralPath $resolvedArtifacts) {
    Remove-Item -LiteralPath $resolvedArtifacts -Recurse -Force
}
New-Item -ItemType Directory -Path $publish -Force | Out-Null

function Invoke-CodeSign([string]$Path) {
    if (-not $CertificateThumbprint) { return }
    $signTool = Get-Command 'signtool.exe' -ErrorAction SilentlyContinue
    if (-not $signTool) { throw 'signtool.exe was not found; install the Windows SDK signing tools.' }
    & $signTool.Source sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $Path
    if ($LASTEXITCODE) { throw "Code signing failed for $Path" }
}

$sdkVersion = (& dotnet --version).Trim()
if ([version]$sdkVersion -lt [version]'10.0.100') { throw '.NET SDK 10 or newer is required.' }
& cargo --version | Out-Null

if (-not $SkipTests) {
    & cargo test --workspace
    if ($LASTEXITCODE) { throw 'Rust tests failed.' }
    & cargo clippy --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE) { throw 'Rust clippy failed.' }
}

& cargo build --workspace --release
if ($LASTEXITCODE) { throw 'Rust release build failed.' }
Copy-Item -LiteralPath (Join-Path $repo 'target\release\pcpulse-collector.exe') -Destination (Join-Path $publish 'PcPulse.Service.exe')
Copy-Item -LiteralPath (Join-Path $repo 'target\release\pcpulse.exe') -Destination (Join-Path $publish 'PcPulse.exe')
Copy-Item -LiteralPath (Join-Path $repo 'target\release\pcpulse-notify.exe') -Destination (Join-Path $publish 'PcPulse.Notify.exe')
Invoke-CodeSign (Join-Path $publish 'PcPulse.Service.exe')
Invoke-CodeSign (Join-Path $publish 'PcPulse.exe')
Invoke-CodeSign (Join-Path $publish 'PcPulse.Notify.exe')

& dotnet build (Join-Path $repo 'installer\PcPulse.Installer\PcPulse.Installer.wixproj') `
    -c Release -p:Platform=$Architecture -p:Version=$Version
if ($LASTEXITCODE) { throw 'MSI build failed.' }
$msi = Get-ChildItem -Path (Join-Path $repo 'installer\PcPulse.Installer\bin') -Filter '*.msi' -Recurse | Select-Object -First 1
if (-not $msi) { throw 'MSI output was not found.' }
Copy-Item -LiteralPath $msi.FullName -Destination (Join-Path $artifacts "PcPulse-$Version-$Architecture.msi")
Invoke-CodeSign (Join-Path $artifacts "PcPulse-$Version-$Architecture.msi")

$hashes = Get-ChildItem -Path $artifacts -File | Get-FileHash -Algorithm SHA256 |
    ForEach-Object { "{0} *{1}" -f $_.Hash.ToLowerInvariant(), (Split-Path -Leaf $_.Path) }
Set-Content -LiteralPath (Join-Path $artifacts 'SHA256SUMS.txt') -Value $hashes -Encoding ascii
Write-Host "Release ready in $artifacts"
