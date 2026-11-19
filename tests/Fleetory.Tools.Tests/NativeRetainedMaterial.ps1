#requires -Version 7.3
function New-NativeRetainedMaterial([ValidatePattern('^[a-z-]+$')][string]$Flow,[bool]$ServerEnabled){
    $material=@{Tls=(New-PilotDisposableTlsMaterial -IncludeClient);Secrets=@{};SigningPem=$null;
        PublicKeyPath=(Join-Path $root ('retained-target-'+$flow+'-public.pem'))}
    foreach($name in @('admin','writer','reader')){
        $material.Secrets[$name]=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
        $state.Canaries.Add($material.Secrets[$name])
    }
    $key=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
    try{$material.SigningPem=$key.ExportECPrivateKeyPem();[IO.File]::WriteAllText($material.PublicKeyPath,$key.ExportSubjectPublicKeyInfoPem(),[Text.UTF8Encoding]::new($false))}finally{$key.Dispose()}
    foreach($pem in @($material.Tls.ServerPrivateKeyPem,$material.Tls.ClientPrivateKeyPem,$material.SigningPem)){
        foreach($line in ($pem -split "`n")){if($line.Length -ge 40 -and -not $line.StartsWith('-----')){$state.Canaries.Add($line.Substring(0,40))}}
    }
    if($ServerEnabled){
        $material.PostgresTls=New-PilotDisposableTlsMaterial
        $material.GatewayTls=@{}
        foreach($role in @('agent','admin')){$material.GatewayTls[$role]=New-PilotDisposableTlsMaterial}
        foreach($name in @('database','signer')){
            $material.Secrets[$name]=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
            $state.Canaries.Add($material.Secrets[$name])
        }
        foreach($pem in @($material.PostgresTls.ServerPrivateKeyPem,$material.GatewayTls.agent.ServerPrivateKeyPem,$material.GatewayTls.admin.ServerPrivateKeyPem)){
            foreach($line in ($pem -split "`n")){if($line.Length -ge 40 -and -not $line.StartsWith('-----')){$state.Canaries.Add($line.Substring(0,40))}}
        }
    }
    return $material
}
