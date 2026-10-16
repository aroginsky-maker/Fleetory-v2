function Assert-PackageContents(
    [string] $PackageDirectory,
    [string] $Rid,
    [string[]] $AdditionalRequiredFiles = @()) {
    $requiredFiles = @(
        'Fleetory.Server.dll',
        'Fleetory.Server.deps.json',
        'Fleetory.Server.runtimeconfig.json',
        'appsettings.json',
        'appsettings.Production.json'
    ) + $AdditionalRequiredFiles

    foreach ($requiredFile in $requiredFiles) {
        $path = Join-Path $PackageDirectory $requiredFile
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Package '$Rid' is missing required file '$requiredFile'."
        }
    }

    if (Test-Path -LiteralPath (Join-Path $PackageDirectory 'appsettings.Development.json')) {
        throw "Package '$Rid' must not contain appsettings.Development.json."
    }

    $files = @(Get-ChildItem -LiteralPath $PackageDirectory -Recurse -File)
    $forbidden = @($files | Where-Object {
        $_.Extension -in @('.cs', '.csproj', '.sln', '.user', '.suo') -or
        $_.Name -like '*.Tests.dll' -or
        $_.Name -like '*.Tests.pdb' -or
        $_.FullName -match '[\\/](?:obj|bin|TestResults|coverage|\.sonarqube)[\\/]'
    })

    if ($forbidden.Count -gt 0) {
        throw "Package '$Rid' contains forbidden development/test artifacts: $($forbidden.FullName -join ', ')."
    }

    $secretKeyPattern = '"(?i:password|secret|token|api[_-]?key|connectionstrings?)"\s*:'
    foreach ($jsonFile in $files | Where-Object { $_.Extension -eq '.json' }) {
        $json = Get-Content -LiteralPath $jsonFile.FullName -Raw
        if ($json -match $secretKeyPattern) {
            throw "Package '$Rid' configuration '$($jsonFile.Name)' contains a secret-like configuration key."
        }
    }
}

function Get-FreeLoopbackPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        return ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}
