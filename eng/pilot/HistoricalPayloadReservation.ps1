#requires -Version 7.3
# Empty metadata directory only. No archived payload, credentials, Docker or backend.
function New-NativePayloadAction([byte[]]$Header,[byte[]]$Frame,$Reservation=$null){
    $value=@{schema='fleetory.native-empty-payload-action.v1';headerBase64=[Convert]::ToBase64String($Header);frameBase64=[Convert]::ToBase64String($Frame)}
    if($null -ne $Reservation){
        foreach($key in @('ownerSha256','payloadDirectorySha256','intentSha256')){$value[$key]=$Reservation[$key]}
    }
    return ,[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 6 -Compress))
}
function Invoke-HistoricalPayloadReservation([string]$ExpectedPin,[string]$Python,[string]$Repository,[string]$Git,[switch]$AcknowledgeResources,[switch]$ProbeRuntime,[switch]$CreateProbe){
    $stage='header';$state='not-attempted';$stream=[Console]::OpenStandardInput()
    $helper=Join-Path $PSScriptRoot $(if($CreateProbe){'audit_native_probe_create.py'}else{'audit_native_payload.py'})
    try{
        Assert-ImmuData ((-not $ProbeRuntime -or $AcknowledgeResources) -and (-not $CreateProbe -or $ProbeRuntime)) 'probe-ack-mode'
        $raw=Read-PreparationFrame $stream 24576
        $checked=Invoke-NativeBytes $Python @('-B',$helper,'header',$ExpectedPin) $raw 10
        Assert-ImmuData ($checked.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($checked.Stderr)) 'empty-payload-header'
        $info=$checked.Stdout|ConvertFrom-Json -AsHashtable
        $stage='git';Assert-PreparationGit $Git $info.gitSha256
        $stage='code';Assert-PreparationSnapshot $Repository $Git $info
        $readyBytes=Send-PreparationReady $info;$readyPin=Get-ImmuDataHash $readyBytes
        $stage='reserve';$frame=Read-PreparationFrame $stream 2048
        $body=New-NativePayloadAction $raw $frame
        $state='unknown';$created=Invoke-NativeBytes $Python @('-B',$helper,'reserve',$ExpectedPin,$readyPin,$PID.ToString()) $body 10
        Assert-ImmuData ($created.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($created.Stderr)) 'empty-payload-reserve'
        $reservation=$created.Stdout|ConvertFrom-Json -AsHashtable
        $state='reserved';$null=Send-PreparationFrame $reservation
        if($CreateProbe){
            $stage='create';$frame=Read-PreparationFrame $stream 16384
            $body=New-NativePayloadAction $raw $frame $reservation
            $made=Invoke-NativeBytes $Python @('-B',$helper,'create',$ExpectedPin,$readyPin,$PID.ToString()) $body 10
            Assert-ImmuData ($made.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($made.Stderr)) 'probe-native-create'
            $null=Send-PreparationFrame ($made.Stdout|ConvertFrom-Json -AsHashtable)
        }
        if($AcknowledgeResources){
            $stage='resources';$frame=Read-PreparationFrame $stream 2048
            $null=Send-PreparationFrame (Get-HistoricalResourceAcknowledgement $ExpectedPin $Python $raw $readyPin $frame $reservation $PID -ProbeRuntime:$ProbeRuntime -CreateProbe:$CreateProbe)
        }
        $stage='remove';$frame=Read-PreparationFrame $stream 2048
        Assert-ImmuData ($stream.ReadByte() -eq -1) 'empty-payload-trailing-input'
        $body=New-NativePayloadAction $raw $frame $reservation
        $state='unknown';$removed=Invoke-NativeBytes $Python @('-B',$helper,'remove',$ExpectedPin,$readyPin,$PID.ToString()) $body 10
        Assert-ImmuData ($removed.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($removed.Stderr)) 'empty-payload-remove'
        $null=Send-PreparationFrame ($removed.Stdout|ConvertFrom-Json -AsHashtable)
        return 0
    }catch{
        $schema=if($CreateProbe){'fleetory.native-probe-create-refused.v1'}elseif($ProbeRuntime){'fleetory.native-probe-runtime-refused.v1'}elseif($AcknowledgeResources){'fleetory.native-linked-resource-refused.v1'}else{'fleetory.native-empty-payload-refused.v1'}
        $null=Send-PreparationFrame @{schema=$schema;stage=$stage;emptyPayloadState=$state;privateInputsAccepted=$false;backendCreated=$false}
        [Console]::Error.WriteLine('Native empty metadata reservation refused; no private input accepted.')
        return 1
    }
}
