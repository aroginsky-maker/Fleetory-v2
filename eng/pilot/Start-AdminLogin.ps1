#requires -Version 7.3
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$ProfilePath,
 [Parameter(Mandatory)][string]$SshIdentityPath,
 [Parameter(Mandatory)][string]$KnownHostsPath,
 [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$')][string]$HostName,
 [ValidatePattern('^[a-z_][a-z0-9_-]{0,31}$')][string]$SshUser='ubuntu'
)
$ErrorActionPreference='Stop'
foreach($file in @($ProfilePath,$SshIdentityPath,$KnownHostsPath)){
 if(-not[IO.Path]::IsPathFullyQualified($file) -or -not(Test-Path -LiteralPath $file -PathType Leaf)){throw 'Use existing absolute operator paths.'}
}
$repo=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$dll=Join-Path $repo 'eng/AdminLogin/bin/Release/net10.0/AdminLogin.dll'
if(-not(Test-Path -LiteralPath $dll -PathType Leaf)){throw 'Build the reviewed eng/AdminLogin project in Release first.'}
& dotnet $dll $ProfilePath --check-config
if($LASTEXITCODE-ne0){throw 'Protected operator profile preflight did not pass.'}
$profileData=Get-Content -LiteralPath $ProfilePath -Raw|ConvertFrom-Json
$origin=[uri]$profileData.adminApiOrigin
if(-not$origin.IsAbsoluteUri -or $origin.Scheme-ne'https' -or $origin.Host-ne'localhost' -or
 $origin.Port-lt1024 -or $origin.UserInfo -or $origin.Query -or $origin.Fragment -or $origin.AbsolutePath-ne'/'){
 throw 'Admin API origin must be an HTTPS localhost origin with an unprivileged port.'
}
$start=[Diagnostics.ProcessStartInfo]::new((Get-Command ssh -CommandType Application).Source)
$start.UseShellExecute=$false
$start.CreateNoWindow=$true
foreach($argument in @('-i',$SshIdentityPath,'-o','IdentitiesOnly=yes','-o','BatchMode=yes',
 '-o','StrictHostKeyChecking=yes','-o',('UserKnownHostsFile='+$KnownHostsPath),
 '-o','ExitOnForwardFailure=yes','-o','ConnectTimeout=10','-N','-L',
 ('127.0.0.1:'+$origin.Port+':127.0.0.1:5444'),($SshUser+'@'+$HostName))){
 $start.ArgumentList.Add($argument)
}
$tunnel=[Diagnostics.Process]::new()
$tunnel.StartInfo=$start
$started=$false
try{
 if(-not$tunnel.Start()){throw 'Could not start the SSH tunnel.'}
 $started=$true
 Start-Sleep -Milliseconds 750
 if($tunnel.HasExited){throw 'Pinned SSH tunnel failed; verify the operator SSH profile.'}
 & dotnet $dll $ProfilePath
 if($LASTEXITCODE-ne0){throw 'Admin login did not pass; no token was saved.'}
}finally{
 if($started -and -not$tunnel.HasExited){$tunnel.Kill($true);$tunnel.WaitForExit()}
 $tunnel.Dispose()
}
