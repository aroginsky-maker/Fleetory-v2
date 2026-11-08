#requires -Version 7.3
# Receipts for already-bound generated resources only. No Docker or private payload.
function Get-HistoricalResourceAcknowledgement([string]$ExpectedPin,[string]$Python,[byte[]]$Header,[string]$ReadyPin,[byte[]]$Frame,$Reservation,[int]$NativePid,[switch]$ProbeRuntime){
    $schema=if($ProbeRuntime){'fleetory.native-probe-runtime-action.v1'}else{'fleetory.native-linked-resource-action.v1'}
    $module=if($ProbeRuntime){'audit_native_probe_runtime.py'}else{'audit_native_resources.py'}
    $value=@{schema=$schema;headerBase64=[Convert]::ToBase64String($Header);frameBase64=[Convert]::ToBase64String($Frame)}
    foreach($key in @('ownerSha256','payloadDirectorySha256','intentSha256')){$value[$key]=$Reservation[$key]}
    $body=[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 6 -Compress))
    $ack=Invoke-NativeBytes $Python @('-B',(Join-Path $PSScriptRoot $module),'acknowledge',$ExpectedPin,$ReadyPin,$NativePid.ToString()) $body 10
    Assert-ImmuData ($ack.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($ack.Stderr)) 'resource-ack'
    return ($ack.Stdout|ConvertFrom-Json -AsHashtable)
}
function Invoke-HistoricalResourceAcknowledgement([string]$ExpectedPin,[string]$Python,[string]$Repository,[string]$Git,[switch]$ProbeRuntime){
    return (Invoke-HistoricalPayloadReservation $ExpectedPin $Python $Repository $Git -AcknowledgeResources -ProbeRuntime:$ProbeRuntime)
}
