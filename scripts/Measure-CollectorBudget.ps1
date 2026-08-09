[CmdletBinding()]
param(
    [int]$DurationSeconds = 120,
    [string]$CollectorPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'target\release\pcpulse-collector.exe')
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $CollectorPath)) { throw 'Build the release collector first.' }
$dataDirectory = Join-Path ([IO.Path]::GetTempPath()) ("PcPulse-Budget-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dataDirectory | Out-Null
$process = Start-Process -FilePath $CollectorPath -ArgumentList @('--console', '--data-dir', $dataDirectory) -PassThru -WindowStyle Hidden
try {
    Start-Sleep -Seconds 5
    if ($process.HasExited) { throw 'Collector exited during startup. Run elevated so its ETW session can start.' }
    $samples = [Collections.Generic.List[object]]::new()
    $previousCpu = (Get-Process -Id $process.Id).CPU
    $previousAt = Get-Date
    $count = [Math]::Max(1, [Math]::Floor($DurationSeconds / 2))
    for ($index = 0; $index -lt $count; $index++) {
        Start-Sleep -Seconds 2
        $current = Get-Process -Id $process.Id
        $now = Get-Date
        $elapsed = ($now - $previousAt).TotalSeconds
        $cpu = (($current.CPU - $previousCpu) / $elapsed / [Environment]::ProcessorCount) * 100
        $samples.Add([pscustomobject]@{ Cpu = $cpu; WorkingSet = $current.WorkingSet64; Handles = $current.HandleCount })
        $previousCpu = $current.CPU
        $previousAt = $now
    }
    $averageCpu = ($samples | Measure-Object Cpu -Average).Average
    $maxWorkingSet = ($samples | Measure-Object WorkingSet -Maximum).Maximum
    $maxHandles = ($samples | Measure-Object Handles -Maximum).Maximum
    $growth = $samples[-1].WorkingSet - $samples[0].WorkingSet
    $result = [pscustomobject]@{
        AverageCpuPercent = [Math]::Round($averageCpu, 4)
        MaxWorkingSetMb = [Math]::Round($maxWorkingSet / 1MB, 2)
        MaxHandles = $maxHandles
        WorkingSetGrowthMb = [Math]::Round($growth / 1MB, 2)
        Passed = $averageCpu -lt 0.2 -and $maxWorkingSet -lt 25MB -and $maxHandles -lt 600 -and $growth -lt 1MB
    }
    $result
    if (-not $result.Passed) { throw 'Collector did not meet one or more resource budgets.' }
}
finally {
    if (Get-Process -Id $process.Id -ErrorAction SilentlyContinue) { Stop-Process -Id $process.Id -Force }
    Remove-Item -LiteralPath $dataDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
