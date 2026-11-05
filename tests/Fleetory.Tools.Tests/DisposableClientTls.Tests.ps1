#requires -Version 7.3
# All material generated in memory; no stores, retained keys, files or network.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'PilotDisposableTls.ps1')
$owned=[Collections.Generic.List[IDisposable]]::new()
function Assert-DisposableClient([bool]$Value){if(-not $Value){throw 'Disposable client TLS contract failed.'}}
function Read-DisposablePair($Material,[string]$Role){
    $cert=[Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($Material.($Role+'CertificatePem'),$Material.($Role+'PrivateKeyPem'))
    $owned.Add($cert)
    $key=[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert);$owned.Add($key)
    $pub=[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($cert);$owned.Add($pub)
    $challenge=[Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    Assert-DisposableClient ($key.KeySize -eq 256 -and $pub.VerifyData($challenge,$key.SignData($challenge,[Security.Cryptography.HashAlgorithmName]::SHA256),[Security.Cryptography.HashAlgorithmName]::SHA256))
    $constraints=@($cert.Extensions|Where-Object {$_.Oid.Value -ceq '2.5.29.19'})
    $usage=@($cert.Extensions|Where-Object {$_.Oid.Value -ceq '2.5.29.15'})
    $eku=@($cert.Extensions|Where-Object {$_.Oid.Value -ceq '2.5.29.37'})
    $purpose=if($Role -ceq 'Client'){'1.3.6.1.5.5.7.3.2'}else{'1.3.6.1.5.5.7.3.1'}
    Assert-DisposableClient ($constraints.Count -eq 1 -and -not $constraints[0].CertificateAuthority -and
        $usage.Count -eq 1 -and $usage[0].KeyUsages -eq [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -and
        $eku.Count -eq 1 -and $eku[0].EnhancedKeyUsages.Count -eq 1 -and $eku[0].EnhancedKeyUsages[0].Value -ceq $purpose -and
        $cert.NotAfter.ToUniversalTime() -gt [DateTime]::UtcNow -and $cert.NotAfter.ToUniversalTime() -lt [DateTime]::UtcNow.AddMinutes(61))
    return $cert
}
function Test-DisposableChain($Leaf,$Root,[string]$Purpose,[bool]$Expected){
    $chain=[Security.Cryptography.X509Certificates.X509Chain]::new()
    try{
        $chain.ChainPolicy.TrustMode=[Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
        $null=$chain.ChainPolicy.CustomTrustStore.Add($Root)
        $chain.ChainPolicy.DisableCertificateDownloads=$true
        $chain.ChainPolicy.RevocationMode=[Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags=[Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $null=$chain.ChainPolicy.ApplicationPolicy.Add([Security.Cryptography.Oid]::new($Purpose))
        Assert-DisposableClient ($chain.Build($Leaf) -eq $Expected)
        if($Expected){Assert-DisposableClient ($chain.ChainElements.Count -eq 2 -and $chain.ChainElements[1].Certificate.Thumbprint -ceq $Root.Thumbprint)}
    }finally{$chain.Dispose()}
}
try{
    $default=New-PilotDisposableTlsMaterial
    Assert-DisposableClient (($default.PSObject.Properties.Name|Sort-Object)-join '|' -ceq 'RootCertificatePem|ServerCertificatePem|ServerPrivateKeyPem')
    $defaultRoot=[Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($default.RootCertificatePem);$owned.Add($defaultRoot)
    $defaultServer=Read-DisposablePair $default 'Server'
    Test-DisposableChain $defaultServer $defaultRoot '1.3.6.1.5.5.7.3.1' $true
    $roots=@();$clients=@();$servers=@()
    foreach($gateway in @('agent','admin')){
        $material=New-PilotDisposableTlsMaterial -IncludeClient
        Assert-DisposableClient (($material.PSObject.Properties.Name|Sort-Object)-join '|' -ceq 'ClientCertificatePem|ClientPrivateKeyPem|RootCertificatePem|ServerCertificatePem|ServerPrivateKeyPem')
        $root=[Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($material.RootCertificatePem);$owned.Add($root)
        Assert-DisposableClient (-not $root.HasPrivateKey -and -not $material.RootCertificatePem.Contains('PRIVATE KEY',[StringComparison]::Ordinal))
        $roots+=,$root;$clients+=,(Read-DisposablePair $material 'Client');$servers+=,(Read-DisposablePair $material 'Server')
    }
    Assert-DisposableClient ($roots[0].Thumbprint -cne $roots[1].Thumbprint -and $roots[0].Thumbprint -cne $defaultRoot.Thumbprint -and $roots[1].Thumbprint -cne $defaultRoot.Thumbprint)
    foreach($index in @(0,1)){
        Test-DisposableChain $servers[$index] $roots[$index] '1.3.6.1.5.5.7.3.1' $true
        Test-DisposableChain $clients[$index] $roots[$index] '1.3.6.1.5.5.7.3.2' $true
        Test-DisposableChain $clients[$index] $roots[1-$index] '1.3.6.1.5.5.7.3.2' $false
        Test-DisposableChain $clients[$index] $roots[$index] '1.3.6.1.5.5.7.3.1' $false
        Test-DisposableChain $servers[$index] $roots[$index] '1.3.6.1.5.5.7.3.2' $false
    }
    Write-Host 'DISPOSABLE CLIENT TLS PASS: default3/client5 public-leaf slots; 5 key pairs/5 valid chains/6 chain refusals; no CA private export, files or network.'
}finally{
    for($index=$owned.Count-1;$index -ge 0;$index--){$owned[$index].Dispose()}
    $default=$material=$null
}
