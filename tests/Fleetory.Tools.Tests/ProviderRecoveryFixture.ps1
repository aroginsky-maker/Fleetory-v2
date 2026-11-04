#requires -Version 7.3
# Generated metadata only; never imports protected operator state.
function New-ControllerFixturePlan([string] $Directory,[string] $SourceId=('a'*64)) {
    $header=[Convert]::FromHexString('0000000b7373682d6564323535313900000020')
    $key=[byte[]]::new(51);[Array]::Copy($header,$key,19)
    [Array]::Copy([Security.Cryptography.RandomNumberGenerator]::GetBytes(32),0,$key,19,32)
    $pinPath=Join-Path $Directory 'public known_hosts'
    $pinBytes=[Text.Encoding]::UTF8.GetBytes('192.0.2.17 ssh-ed25519 '+[Convert]::ToBase64String($key)+"`n")
    [IO.File]::WriteAllBytes($pinPath,$pinBytes)
    return @{
        schema='fleetory.provider-recovery-plan.v1';scope='synthetic-fixture';operationId=[Guid]::NewGuid().ToString('D');stateDirectory=$Directory;
        ssh=@{Address='192.0.2.17';KnownHostsFile=$pinPath;
            KnownHostsSha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($pinBytes)).ToLowerInvariant();
            HostFingerprint=('SHA256:'+ [Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData($key)).TrimEnd('='));
            IdentityFile=(Join-Path $Directory 'absent identity')};
        snapshot=@{path=(Join-Path $Directory 'snapshot');bytes=4096;sha256=('b'*64)};
        share=@{path=(Join-Path $Directory 'share');bytes=44;mtimeUtc=[DateTimeOffset]::UtcNow.ToString('O')};
        clusterId=[Guid]::NewGuid().ToString('D');publicSpkiSha256=('c'*64);transitKey='fleetory-recovery-fixture';
        auditName='fixture-file';sourceContainerName='fixture-source';sourceContainerIds=@($SourceId);codePins=(Get-ProviderCodePins)
    }
}
function Get-ControllerFixtureHash($Plan) {
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes(($Plan|ConvertTo-Json -Depth 16)))).ToLowerInvariant()
}
function New-ControllerFixtureGrant($Plan,[string] $Hash) {
    return @{schema='fleetory.provider-recovery-grant.v1';scope='synthetic-fixture';operationId=$Plan.operationId;planSha256=$Hash;
        permission='one-target-restore-four-share-submissions-one-root-one-300s-probe';decision='approved';evidenceRef='generated-fixture-only';
        issuedUtc=[DateTimeOffset]::UtcNow.AddSeconds(-1).ToString('O');expiresUtc=[DateTimeOffset]::UtcNow.AddMinutes(59).ToString('O')}
}
function New-ControllerFixtureResult([string] $Out,[int] $Code=0,[string] $Err='') {
    return [pscustomobject]@{ExitCode=$Code;Stdout=$Out;Stderr=$Err;StdoutBytes=[Text.Encoding]::UTF8.GetBytes($Out);StderrBytes=[Text.Encoding]::UTF8.GetBytes($Err)}
}
