[CmdletBinding()]
param(
    [ValidateSet('x64')]
    [string]$Architecture = 'x64',
    [string]$Version,
    [string]$CertificateThumbprint,
    [string]$TimestampUrl = 'http://timestamp.digicert.com',
    [switch]$SkipTests,
    [switch]$ValidateOnly
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $repo
try {
    $metadataJson = & cargo metadata --no-deps --locked --offline --format-version 1
    if ($LASTEXITCODE) { throw 'Cargo metadata failed.' }
    $metadata = ($metadataJson -join "`n") | ConvertFrom-Json
    $packages = @($metadata.packages | Where-Object { $_.name -in @('pcpulse-service', 'pcpulse-tui') })
    if ($packages.Count -ne 2) { throw 'Expected the service and TUI workspace packages.' }
    $versions = @($packages.version | Select-Object -Unique)
    if ($versions.Count -ne 1) { throw "Service and TUI versions disagree: $($versions -join ', ')" }
    $packageVersion = $versions[0]
    if ($Version -and $Version -cne $packageVersion) {
        throw "Requested MSI version $Version does not match the binaries' version $packageVersion."
    }
    $Version = $packageVersion
    if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'MSI releases require a numeric major.minor.patch version.' }
    $numericVersion = [version]$Version
    if ($numericVersion.Major -gt 255 -or $numericVersion.Minor -gt 255 -or $numericVersion.Build -gt 65535) {
        throw 'The version exceeds the Windows Installer major.minor.build limits.'
    }
    # Cargo metadata honors CARGO_TARGET_DIR and repository Cargo configuration.
    $targetTriple = 'x86_64-pc-windows-msvc'
    $releaseOutput = Join-Path $metadata.target_directory "$targetTriple\release"
    if ($ValidateOnly) {
        [pscustomobject]@{ Version = $Version; Architecture = $Architecture; ReleaseOutput = $releaseOutput }
        return
    }
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
    if ($LASTEXITCODE) { throw '.NET SDK was not found.' }
    if ([version]$sdkVersion -lt [version]'10.0.100') { throw '.NET SDK 10 or newer is required.' }
    & cargo --version | Out-Null
    if ($LASTEXITCODE) { throw 'Cargo was not found.' }

    if (-not $SkipTests) {
        & cargo test --workspace --locked
        if ($LASTEXITCODE) { throw 'Rust tests failed.' }
        & cargo clippy --workspace --all-targets --locked -- -D warnings
        if ($LASTEXITCODE) { throw 'Rust clippy failed.' }
    }

    & cargo build --workspace --release --locked --target $targetTriple
    if ($LASTEXITCODE) { throw 'Rust release build failed.' }
    Copy-Item -LiteralPath (Join-Path $releaseOutput 'pcpulse-collector.exe') -Destination (Join-Path $publish 'PcPulse.Service.exe')
    Copy-Item -LiteralPath (Join-Path $releaseOutput 'pcpulse.exe') -Destination (Join-Path $publish 'PcPulse.exe')
    Copy-Item -LiteralPath (Join-Path $releaseOutput 'pcpulse-notify.exe') -Destination (Join-Path $publish 'PcPulse.Notify.exe')
    Invoke-CodeSign (Join-Path $publish 'PcPulse.Service.exe')
    Invoke-CodeSign (Join-Path $publish 'PcPulse.exe')
    Invoke-CodeSign (Join-Path $publish 'PcPulse.Notify.exe')

    $msiOutput = Join-Path $artifacts 'msi'
    & dotnet build (Join-Path $repo 'installer\PcPulse.Installer\PcPulse.Installer.wixproj') `
        -c Release -p:Platform=$Architecture -p:Version=$Version --output $msiOutput
    if ($LASTEXITCODE) { throw 'MSI build failed.' }
    $msi = @(Get-ChildItem -LiteralPath $msiOutput -Filter '*.msi' -File)
    if ($msi.Count -ne 1) { throw 'Expected exactly one fresh MSI output.' }
    Copy-Item -LiteralPath $msi[0].FullName -Destination (Join-Path $artifacts "PcPulse-$Version-$Architecture.msi")
    Invoke-CodeSign (Join-Path $artifacts "PcPulse-$Version-$Architecture.msi")

    $hashes = Get-ChildItem -Path $artifacts -File | Get-FileHash -Algorithm SHA256 |
        ForEach-Object { "{0} *{1}" -f $_.Hash.ToLowerInvariant(), (Split-Path -Leaf $_.Path) }
    Set-Content -LiteralPath (Join-Path $artifacts 'SHA256SUMS.txt') -Value $hashes -Encoding ascii
    Write-Host "Release ready in $artifacts"
} finally {
    Pop-Location
}
