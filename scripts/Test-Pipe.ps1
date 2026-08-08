[CmdletBinding()]
param([int]$TimeoutMilliseconds = 3000)

$pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'PcPulse.v1', [IO.Pipes.PipeDirection]::InOut)
try {
    $pipe.Connect($TimeoutMilliseconds)
    $pipe.ReadMode = [IO.Pipes.PipeTransmissionMode]::Message
    $request = [Text.Encoding]::UTF8.GetBytes('{"command":"getSnapshot"}')
    $pipe.Write($request, 0, $request.Length)
    $pipe.Flush()
    $buffer = [byte[]]::new(65536)
    $memory = [IO.MemoryStream]::new()
    do {
        $read = $pipe.Read($buffer, 0, $buffer.Length)
        if ($read -eq 0) { throw 'Collector closed the pipe.' }
        $memory.Write($buffer, 0, $read)
        if ($memory.Length -gt 1MB) { throw 'Collector response exceeded 1 MiB.' }
    } until ($pipe.IsMessageComplete)
    $json = [Text.Encoding]::UTF8.GetString($memory.ToArray()) | ConvertFrom-Json
    if ($json.status -ne 'ok' -or $json.data.protocolVersion -ne 1) { throw 'Collector returned an invalid protocol response.' }
    $json.data
}
finally { $pipe.Dispose() }
