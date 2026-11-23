#requires -Version 7.3
# Private immutable value/byte commitments. Only the digest is sent to the coordinator.
function Get-RetainedPgHba{
    return "local all postgres peer`nlocal all all reject`nhostssl fleetory fleetory_server 127.0.0.1/32 scram-sha-256`nhostssl fleetory_signer fleetory_signer 127.0.0.1/32 scram-sha-256`nhost all all 0.0.0.0/0 reject`nhost all all ::/0 reject`n"
}
function Get-RetainedServerSlots($Material){
    $slots=@{'infrastructure-ca'=$Material.PostgresTls.RootCertificatePem;'audit-immudb-password'=$Material.Secrets.reader}
    foreach($entry in @(@('fleetory-postgresql','fleetory','fleetory_server','database'),@('fleetory-signer-postgresql','fleetory_signer','fleetory_signer','signer'))){
        $slots[$entry[0]]='Host=127.0.0.1;Port=5432;Database='+$entry[1]+';Username='+$entry[2]+';Password='+$Material.Secrets[$entry[3]]+
            ';SSL Mode=VerifyFull;Root Certificate=/run/fleetory-native/server/infrastructure-ca;GSS Encryption Mode=Disable;Timeout=5;Command Timeout=5;Pooling=false'
    }
    foreach($role in @('agent','admin')){
        $tls=$Material.GatewayTls[$role]
        $slots[$role+'-gateway-root-ca']=$tls.RootCertificatePem;$slots[$role+'-gateway-server-cert']=$tls.ServerCertificatePem
        $slots[$role+'-gateway-server-key']=$tls.ServerPrivateKeyPem
    }
    return $slots
}
function New-RetainedConfiguration($Material,[bool]$Server,[bool]$Historical){
    $values=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach($entry in @(@('/tmp/ca.pem',$Material.Tls.RootCertificatePem),@('/tmp/server.crt',$Material.Tls.ServerCertificatePem),
        @('/tmp/server.key',$Material.Tls.ServerPrivateKeyPem),@('/tmp/client.crt',$Material.Tls.ClientCertificatePem),
        @('/tmp/client.key',$Material.Tls.ClientPrivateKeyPem),@('/tmp/state.key',$Material.SigningPem),
        @('/tmp/immudb.toml',('admin-password = "'+$Material.Secrets.admin+'"'+"`n")),@('/tmp/cli.toml',"# Generated retained coupled target only.`n"))){
        $values.Add(('audit:'+$entry[0]),[string]$entry[1])
    }
    foreach($name in @('admin','reader','writer')){$values.Add(('credential:audit/'+$name),[string]$Material.Secrets[$name])}
    if($Server){
        foreach($entry in @(@('/tmp/ca.pem',$Material.PostgresTls.RootCertificatePem),@('/tmp/server.crt',$Material.PostgresTls.ServerCertificatePem),
            @('/tmp/server.key',$Material.PostgresTls.ServerPrivateKeyPem),@('/tmp/hba.conf',(Get-RetainedPgHba)))){
            $values.Add(('postgres:'+$entry[0]),[string]$entry[1])
        }
        foreach($entry in @(@('fleetory_server','database'),@('fleetory_signer','signer'))){$values.Add(('credential:postgres/'+$entry[0]),[string]$Material.Secrets[$entry[1]])}
        $slots=Get-RetainedServerSlots $Material
        foreach($name in $slots.Keys){$values.Add(('audit:/run/fleetory-native/server/'+$name),[string]$slots[$name])}
    }
    [string[]]$keys=@($values.Keys);[Array]::Sort($keys,[StringComparer]::Ordinal)
    $lines=[Collections.Generic.List[string]]::new();$lines.Add('fleetory.retained-configuration.v1');$lines.Add([string]$Server);$lines.Add([string]$Historical)
    foreach($key in $keys){
        Assert-ImmuData ($values[$key].Length -gt 0 -and $values[$key].Length -le 16384) 'retained-configuration-value-bound'
        $lines.Add($key);$lines.Add((Get-ImmuDataHash ([Text.Encoding]::UTF8.GetBytes($values[$key]))))
    }
    return @{Values=[Collections.ObjectModel.ReadOnlyDictionary[string,string]]::new($values);
        Sha256=(Get-ImmuDataHash ([Text.Encoding]::UTF8.GetBytes(($lines -join "`n")+"`n")));Count=$values.Count}
}
function Assert-RetainedConfigurationValue($Configuration,[string]$Key,[string]$Value){
    if(-not $Configuration.Values.ContainsKey($Key) -or -not [string]::Equals($Configuration.Values[$Key],$Value,[StringComparison]::Ordinal)){
        throw [InvalidOperationException]::new('Retained configuration drift refused.')
    }
}

function Assert-RetainedRestoreInput([string[]]$Arguments,[byte[]]$InputBytes,$Pins){
    $kind=$null
    if($Arguments -ccontains 'pg_restore'){
        $kind=if($Arguments -ccontains '--dbname=fleetory'){'application-postgres'}elseif($Arguments -ccontains '--dbname=fleetory_signer'){'signer-postgres'}else{throw 'Retained restore database refused.'}
    }elseif($Arguments -ccontains '/usr/local/bin/immuadmin' -and $Arguments -ccontains 'hot-restore'){$kind='audit-immudb'}
    if($null -eq $kind){return}
    Assert-ImmuData ($Pins -is [Collections.ObjectModel.ReadOnlyDictionary[string,string]] -and
        $Pins.ContainsKey($kind) -and $Pins[$kind] -cmatch '^[a-f0-9]{64}\z') 'retained-restore-packet-pin'
    if($kind -ceq 'audit-immudb'){Assert-ImmuDataPacket $InputBytes $Pins[$kind]}else{Assert-PgDataPacket $InputBytes $Pins[$kind]}
}

function Assert-RetainedConfigurationInput([string]$Role,[string[]]$Arguments,[byte[]]$InputBytes,$Configuration){
    $key=$null
    if($Arguments -ccontains '/bin/sh'){$key=$Role+':'+$Arguments[-1]}
    elseif($Arguments -ccontains '/usr/local/bin/immuadmin' -and $Arguments -ccontains 'login'){$key='credential:audit/admin'}
    if($null -eq $key){return}
    Assert-ImmuData ($null -ne $Configuration -and $Configuration.Values -is [Collections.ObjectModel.ReadOnlyDictionary[string,string]] -and
        $Configuration.Values.ContainsKey($key)) 'retained-configuration-input-key'
    $expected=[Text.Encoding]::UTF8.GetBytes($Configuration.Values[$key])
    Assert-ImmuData ($null -ne $InputBytes -and $InputBytes.Length -gt 0 -and $InputBytes.Length -le 16384 -and
        $InputBytes.Length -eq $expected.Length -and (Get-ImmuDataHash $InputBytes) -ceq (Get-ImmuDataHash $expected)) 'retained-configuration-input-bytes'
}
