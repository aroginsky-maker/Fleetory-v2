#requires -Version 7.3
param([string]$Python='')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
foreach($helper in @('PilotNativeProcess.ps1','../../eng/pilot/ProviderRecoveryPolicy.ps1','NativeSignerFixture.ps1','NativeWorkerRuntime.ps1')){. (Join-Path $PSScriptRoot $helper)}
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if(-not $Python){$Python=(Get-Command $(if($IsLinux){'python3'}else{'python'})).Source}
$fixture=[Guid]::NewGuid().ToString('D')
$root=Join-Path $repo ('artifacts/audit-event-expectations-'+$fixture)
$proof=$null
try{
    $null=New-Item -ItemType Directory -Path $root
    $restore=Invoke-NativeBytes 'dotnet' @('restore',(Join-Path $repo 'eng/ServerBackendProbe/ServerBackendProbe.csproj'),'--disable-parallel') -TimeoutSeconds 120
    if($restore.ExitCode -ne 0){throw 'Expectation probe restore failed; no diagnostic payload logged.'}
    $published=Publish-NativeProbe $repo 'ServerBackendProbe' $root
    $dll=Join-Path $published 'ServerBackendProbe.dll'
    $probeHash=(Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash.ToLowerInvariant()
    $result=Invoke-NativeBytes $Python @('-B',(Join-Path $PSScriptRoot 'audit_event_expectations_tests.py'),'--probe',$dll) -TimeoutSeconds 120
    if(($result.Stdout+$result.Stderr).Contains('PRIVATE_INPUT_CANARY',[StringComparison]::Ordinal)){throw 'Expectation canary reached parent output.'}
    if($result.ExitCode -ne 0 -or $result.Stderr -notmatch 'Ran 19 tests' -or $result.Stderr -notmatch '(?m)^OK\s*$'){
        throw 'Generated expectation contracts failed; no snapshot or diagnostic payload logged.'
    }
    Write-Output $result.Stderr.Trim()
    $integration=Invoke-NativeBytes $Python @('-B',(Join-Path $PSScriptRoot 'audit_expectation_source_tests.py'),'--integration-probe',$dll) -TimeoutSeconds 30
    if($integration.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($integration.Stderr)){throw 'Generated source integration failed; no payload logged.'}
    $sourceProof=$integration.Stdout|ConvertFrom-Json -AsHashtable
    if($sourceProof.schema -cne 'fleetory.generated-expectation-source-integration.v1' -or $sourceProof.verified -ne $true -or $sourceProof.cleanupVerified -ne $true -or $sourceProof.productionGoldenValuesMatched -ne $true){throw 'Generated source integration proof refused.'}
    Write-Output $integration.Stdout.Trim()
    $diagnostic=Invoke-NativeBytes $Python @('-B',(Join-Path $PSScriptRoot 'audit_expectation_diagnostic_tests.py'),'--integration-probe',$dll) -TimeoutSeconds 90
    if($diagnostic.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($diagnostic.Stderr)){throw 'Generated expectation diagnosis failed; no payload logged.'}
    $diagnosticProof=$diagnostic.Stdout|ConvertFrom-Json -AsHashtable
    if($diagnosticProof.schema -cne 'fleetory.generated-expectation-diagnostic.v1' -or $diagnosticProof.verified -ne $true -or $diagnosticProof.nativeCases -ne 7 -or $diagnosticProof.cleanupVerified -ne $true -or $diagnosticProof.originalExpectationsAccepted -ne $false){throw 'Generated expectation diagnostic proof refused.'}
    Write-Output $diagnostic.Stdout.Trim()
    $proof=@{schema='fleetory.generated-event-expectations.v1';verified=$true;portableNativeMethods=19;eventFields=10;knownEvents=4;
        productionSinkSerializationUsed=$true;inMemoryRequestsPerSnapshot=16;exactAsciiGoldenValuesVerified=$true;
        sourceFieldMappingVerified=$true;unicodeOrdinalContextAndUtcVerified=$true;observerFrameCompatible=$true;
        valueLimitBytes=8192;probeSha256=$probeHash;sourceReaderIntegrationVerified=$true;diagnosticCompatibilityVerified=$true;sourceOriginAuthenticated=$false;sourceIndependenceAuthenticated=$false;
        realBackendContacted=$false;originalInputsRead=$false;sourceVpsAccessed=$false;originalPkiOrProviderUsed=$false;
        serverApplicationStarted=$false;issuerActivated=$false;signaturesVerified=$false;executionAuthorized=$false;
        fullSystemRecoveryVerified=$false;phase7Complete=$false}
}finally{
    Remove-NativePublicPayload $repo $root
}
if(Test-Path -LiteralPath $root){throw 'Expectation public payload cleanup unverified.'}
$proof.cleanupVerified=$true
$proof|ConvertTo-Json -Compress -Depth 6
$global:LASTEXITCODE=0
