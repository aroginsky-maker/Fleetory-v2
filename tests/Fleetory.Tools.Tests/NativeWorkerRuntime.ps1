#requires -Version 7.3
# Shared generated-only worker lifecycle; caller's Invoke-Docker is local and bounded.
function Publish-NativeProbe([string]$Repository,[string]$Project,[string]$Directory){
    Assert-NativeSigner ($Project -cin @('SignerBackendProbe','SignerJournalProbe','ServerBackendProbe')) 'probe-project'
    $null=Get-ProviderOrdinaryItem $Directory
    $published=Join-Path $Directory 'publish'
    $result=Invoke-NativeBytes 'dotnet' @('publish',(Join-Path $Repository ('eng/'+$Project+'/'+$Project+'.csproj')),
        '-c','Release','--no-restore','--disable-build-servers','-p:UseAppHost=false','-o',$published) -TimeoutSeconds 120
    Assert-NativeSigner ($result.ExitCode -eq 0) 'probe-publish'
    $files=@(Get-ChildItem -LiteralPath $published -File -Recurse)
    Assert-NativeSigner ($files.Count -gt 0 -and $files.Count -le 128 -and
        (Test-Path -LiteralPath (Join-Path $published ($Project+'.dll')))) 'probe-payload'
    foreach($file in $files){$null=Get-ProviderOrdinaryItem $file.FullName;Assert-NativeSigner ($file.Extension -cin @('.dll','.json','.pdb') -and $file.Length -le 33554432) 'probe-payload-file'}
    return $published
}
function New-NativeWorkerContext([string]$Session,[string]$ProviderId,[string]$Directory,$Image){
    return @{Id=$null;Name=('fleetory-native-signer-'+$Session.Replace('-',''));Session=$Session;ProviderId=$ProviderId;
        Directory=$Directory;ImageId=[string]$Image.Id;Environment=@($Image.Config.Env);Started=$null;RunClaimed=$false}
}
function Read-NativeWorkerContext($Context){
    $info=@((Invoke-Docker @('inspect',$Context.Id)).Stdout|ConvertFrom-Json -AsHashtable -Depth 32)
    Assert-NativeSigner ($info.Count -eq 1) 'worker-inspection'
    Assert-NativeSignerWorker $info[0] $Context.Id $Context.Session $Context.ProviderId $Context.Directory $Context.ImageId $Context.Started $Context.Environment
}
function Start-NativeWorkerContext($Context){
    $absent=Invoke-Docker @('inspect',$Context.Name) -AllowFailure
    Assert-NativeSigner ($absent.ExitCode -ne 0 -and ($absent.Stderr+$absent.Stdout) -match '(?i)no such (object|container)') 'worker-name'
    $Context.Started=[DateTimeOffset]::UtcNow;$Context.RunClaimed=$true
    $Context.Id=(Invoke-Docker (Get-NativeSignerWorkerArguments $Context.Session $Context.ProviderId $Context.Directory)).Stdout.Trim()
    Assert-NativeSigner ($Context.Id -cmatch '^[0-9a-f]{64}$') 'worker-id'
    Read-NativeWorkerContext $Context
    $net=(Invoke-Docker @('exec',$Context.Id,'/bin/cat','/proc/net/dev')).Stdout
    $interfaces=@($net -split "`n"|Where-Object {$_ -match ':'}|ForEach-Object {($_ -split ':',2)[0].Trim()})
    Assert-NativeSigner (($interfaces -join '|') -ceq 'lo') 'worker-network-interfaces'
}
function Write-NativeWorkerFile($Context,[string]$Path,[byte[]]$Bytes){
    $names=@('infrastructure-ca','signer-policy','signer-postgresql','signer-server-ca','signer-server-cert','signer-server-key','signer-transit-public-key','signer-transit-token')
    $allowed=@('/tmp/ca.pem','/tmp/wrong-ca.pem')+@($names|ForEach-Object {'/run/fleetory-native/signer/'+$_})
    $serverNames=@('fleetory-postgresql','agent-gateway-root-ca','agent-gateway-server-cert','agent-gateway-server-key',
        'admin-gateway-root-ca','admin-gateway-server-cert','admin-gateway-server-key','audit-immudb-password','infrastructure-ca',
        'agent-gateway-client-cert','agent-gateway-client-key','admin-gateway-client-cert','admin-gateway-client-key')
    $allowed+=@($serverNames|ForEach-Object {'/run/fleetory-native/server/'+$_})
    Assert-NativeSigner ($Path -cin $allowed -and $Bytes.Length -gt 0 -and $Bytes.Length -le 16384) 'worker-file-slot'
    Read-NativeWorkerContext $Context
    $null=Invoke-Docker @('exec','-i',$Context.Id,'/bin/sh','-c','umask 077; cat > "$1"','private-fixture',$Path) $Bytes
    $stat=Invoke-Docker @('exec',$Context.Id,'/usr/bin/stat','-c','%a:%u:%h',$Path)
    Assert-NativeSigner ($stat.Stdout.Trim() -ceq '600:1654:1') 'worker-file-permissions'
}
function Invoke-NativeWorker($Context,[string]$Assembly,[string]$Mode,[byte[]]$Packet,[string[]]$Canaries,[switch]$WrongTrust){
    Assert-NativeSigner ($Assembly -cin @('SignerBackendProbe','SignerJournalProbe','ServerBackendProbe') -and $Mode -cmatch '^[a-z-]{1,32}$' -and
        ($null -eq $Packet -or $Packet.Length -le 16385)) 'worker-probe-input'
    Read-NativeWorkerContext $Context
    $ca=if($WrongTrust){'/tmp/wrong-ca.pem'}else{'/tmp/ca.pem'}
    $result=Invoke-Docker @('exec','-i','-e',('SSL_CERT_FILE='+$ca),$Context.Id,'dotnet',('/tool/'+$Assembly+'.dll'),$Mode) $Packet -TimeoutSeconds 25 -AllowFailure
    foreach($secret in $Canaries){Assert-NativeSigner ($secret.Length -lt 12 -or -not ($result.Stdout+$result.Stderr).Contains($secret,[StringComparison]::Ordinal)) 'worker-output-canary'}
    return $result
}
function Remove-NativeWorker($Context){
    if($null -eq $Context -or -not $Context.RunClaimed){return}
    $lookup=if($Context.Id){$Context.Id}else{$Context.Name}
    $inspection=Invoke-Docker @('inspect',$lookup) -AllowFailure
    if($inspection.ExitCode -ne 0){Assert-NativeSigner (($inspection.Stderr+$inspection.Stdout) -match '(?i)no such (object|container)') 'worker-cleanup-absence';return}
    $found=@($inspection.Stdout|ConvertFrom-Json -AsHashtable -Depth 32);Assert-NativeSigner ($found.Count -eq 1) 'worker-cleanup-identity'
    $id=[string]$found[0].Id
    Assert-NativeSignerWorker $found[0] $id $Context.Session $Context.ProviderId $Context.Directory $Context.ImageId $Context.Started $Context.Environment -CleanupOnly
    $null=Invoke-Docker @('rm','-f','-v',$id)
    $gone=Invoke-Docker @('inspect',$id) -AllowFailure
    Assert-NativeSigner ($gone.ExitCode -ne 0 -and ($gone.Stderr+$gone.Stdout) -match '(?i)no such (object|container)') 'worker-cleanup'
}
function Remove-NativePublicPayload([string]$Repository,[string]$Directory){
    if(Test-Path -LiteralPath $Directory){
        $ordinary=Get-ProviderOrdinaryItem $Directory
        Assert-NativeSigner ($ordinary.FullName -ceq $Directory -and
            $ordinary.FullName.StartsWith((Join-Path $Repository 'artifacts')+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) 'public-cleanup-path'
        Remove-Item -LiteralPath $ordinary.FullName -Recurse -Force
    }
}
