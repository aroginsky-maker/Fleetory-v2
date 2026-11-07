#requires -Version 7.3
# Close-only metadata path. It never creates a payload, key, image or backend.
function Read-PreparationFrame([IO.Stream]$Stream,[int]$Bound){
    $bytes=[Collections.Generic.List[byte]]::new()
    while($bytes.Count -le $Bound){
        $value=$Stream.ReadByte()
        Assert-ImmuData ($value -ge 0) 'preparation-eof'
        if($value -eq 10){Assert-ImmuData ($bytes.Count -gt 0) 'preparation-empty';return ,$bytes.ToArray()}
        $bytes.Add([byte]$value)
    }
    throw 'Preparation frame exceeded bound.'
}
function Send-PreparationFrame($Value){
    [byte[]]$bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 6 -Compress))
    Assert-ImmuData ($bytes.Length -le 2048) 'preparation-output-bound'
    $stream=[Console]::OpenStandardOutput();$stream.Write($bytes,0,$bytes.Length);$stream.WriteByte(10);$stream.Flush()
    return ,$bytes
}
function Assert-PreparationGit([string]$Git,[string]$Expected){
    Assert-ImmuData ([IO.Path]::IsPathFullyQualified($Git) -and [IO.Path]::GetFileName($Git) -in @('git','git.exe')) 'preparation-git-path'
    Assert-ImmuData ((Get-HistoricalInputFileHash $Git 67108864).sha256 -ceq $Expected) 'preparation-git-pin'
}
function Assert-PreparationSnapshot([string]$Repository,[string]$Git,$Info){
    $snapshot=Get-HistoricalAuditCodeSnapshot $Repository $Git
    Assert-ImmuData ($snapshot.revision -ceq $Info.revision -and $snapshot.sha256 -ceq $Info.codeSha256) 'preparation-code'
    Assert-ImmuData ((Get-HistoricalInputFileHash $Git 67108864).sha256 -ceq $Info.gitSha256) 'preparation-git-changed'
}
function Send-PreparationReady($Info){
    return ,(Send-PreparationFrame @{schema='fleetory.native-preparation-ready.v1';nonce=$Info.nonce;revision=$Info.revision;
        controlSha256=$Info.controlSha256;nativePlanSha256=$Info.nativePlanSha256;codeSha256=$Info.codeSha256;
        headerSha256=$Info.headerSha256;gitSha256=$Info.gitSha256;pid=$PID;
        privateInputsAccepted=$false;payloadCreated=$false;backendCreated=$false})
}
function Invoke-HistoricalPreparation([string]$ExpectedPin,[string]$Python,[string]$Repository,[string]$Git){
    $stage='header';$inputStream=[Console]::OpenStandardInput()
    try{
        Assert-ImmuData (-not [string]::IsNullOrWhiteSpace($Python)) 'preparation-python'
        $raw=Read-PreparationFrame $inputStream 24576
        $checked=Invoke-NativeBytes $Python @('-B',(Join-Path $PSScriptRoot 'audit_native_preparation.py'),'header',$ExpectedPin) $raw 10
        Assert-ImmuData ($checked.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($checked.Stderr)) 'preparation-header'
        $info=$checked.Stdout|ConvertFrom-Json -AsHashtable
        $stage='git';Assert-PreparationGit $Git $info.gitSha256
        $stage='code';Assert-PreparationSnapshot $Repository $Git $info
        $readyBytes=Send-PreparationReady $info;$readyPin=Get-ImmuDataHash $readyBytes
        $stage='close';$close=Read-PreparationFrame $inputStream 2048
        $checked=Invoke-NativeBytes $Python @('-B',(Join-Path $PSScriptRoot 'audit_native_preparation.py'),'close',
            $info.nonce,$info.controlSha256,$info.headerSha256,$readyPin) $close 10
        Assert-ImmuData ($checked.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($checked.Stderr) -and $inputStream.ReadByte() -eq -1) 'preparation-close'
        $null=Send-PreparationFrame @{schema='fleetory.native-preparation-closed.v1';nonce=$info.nonce;headerSha256=$info.headerSha256;
            readySha256=$readyPin;privateInputsAccepted=$false;payloadCreated=$false;backendCreated=$false}
        return 0
    }catch{
        $null=Send-PreparationFrame @{schema='fleetory.native-preparation-refused.v1';stage=$stage;privateInputsAccepted=$false;payloadCreated=$false;backendCreated=$false}
        [Console]::Error.WriteLine('Historical preparation refused; no private input accepted.')
        return 1
    }
}
