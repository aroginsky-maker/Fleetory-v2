# Shared bounded, single-buffer reads for independently retained evidence files.
function Read-BoundedEvidenceSnapshot(
    [string] $Path, [string] $Name, [ValidateRange(1, 8388610)][int] $MaximumBytes = 8388608) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Name does not exist." }
    if ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "$Name cannot be a symbolic link."
    }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $memory = [IO.MemoryStream]::new()
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) { throw "$Name size is outside the permitted range." }
        $buffer = New-Object byte[] 4096
        while ($true) {
            $count = [int][Math]::Min($buffer.Length, $MaximumBytes + 1 - $memory.Length)
            $read = $stream.Read($buffer, 0, $count)
            if ($read -eq 0) { break }
            if ($memory.Length + $read -gt $MaximumBytes) { throw "$Name size is outside the permitted range." }
            $memory.Write($buffer, 0, $read)
        }
        if ($memory.Length -eq 0) { throw "$Name is empty." }
        $bytes = $memory.ToArray()
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try { $digest = [BitConverter]::ToString($sha256.ComputeHash($bytes)).Replace('-', '') }
        finally { $sha256.Dispose() }
        return [pscustomobject]@{ Bytes = $bytes; Sha256 = $digest }
    }
    finally { $memory.Dispose(); $stream.Dispose() }
}
