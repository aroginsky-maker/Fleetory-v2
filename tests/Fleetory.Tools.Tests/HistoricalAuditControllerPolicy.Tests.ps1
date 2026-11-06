#requires -Version 7.3
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../eng/pilot/HistoricalAuditControllerPolicy.ps1')
$message="rpc error: code = DataLoss desc = transaction checksums don't match"
if(-not (Test-HistoricalArchiveChecksumRefusal @{ExitCode=1;Stdout='';Stderr=$message})){throw 'Typed archive checksum refusal not recognized.'}
if(Test-HistoricalArchiveChecksumRefusal @{ExitCode=0;Stdout='';Stderr=$message}){throw 'Success misclassified as checksum refusal.'}
$count=0
foreach($text in @('connection refused','unexpected EOF','malformed server response','TLS handshake failed',
    "rpc error: code = Unavailable desc = transaction checksums don't match",
    "rpc error: code = Unauthenticated desc = transaction checksums don't match",
    "rpc error: code = PermissionDenied desc = transaction checksums don't match",
    "rpc error: code = DeadlineExceeded desc = transaction checksums don't match")){
    if(Test-HistoricalArchiveChecksumRefusal @{ExitCode=1;Stdout='';Stderr=$text}){throw 'Operational error misclassified as archive checksum refusal.'}
    $count++
}
Write-Output ('HISTORICAL CONTROLLER POLICY PASS:'+ $count +' operational refusals separated;checksum failure andsuccess distinguished.')
