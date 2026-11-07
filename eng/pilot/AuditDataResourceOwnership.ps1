#requires -Version 7.3
# In-process claims and atomic resource metadata; neither authenticates a dead owner.
if(-not ('Fleetory.Pilot.ExclusiveAuditDirectory' -as [type])){
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
namespace Fleetory.Pilot {
    public static class ExclusiveAuditDirectory {
        [DllImport("kernel32.dll", EntryPoint="CreateDirectoryW", CharSet=CharSet.Unicode, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateWindows(string path, IntPtr attributes);
        [DllImport("libc", EntryPoint="mkdir", SetLastError=true)]
        private static extern int CreateUnix([MarshalAs(UnmanagedType.LPUTF8Str)] string path, uint mode);
        public static void Create(string path) {
            bool created;
            if (OperatingSystem.IsWindows()) created = CreateWindows(path, IntPtr.Zero);
            else if (OperatingSystem.IsLinux()) created = CreateUnix(path, 448) == 0;
            else throw new PlatformNotSupportedException("Exclusive audit directory platform.");
            if (!created) throw new IOException("Exclusive audit directory creation refused.");
        }
    }
}
'@
}
function Assert-AuditDataPayloadPath([string]$Repository,$Context){
    Assert-ImmuData ($Context.Fixture -cmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\z' -and
        $Context.Fixture -cne [Guid]::Empty.ToString('D')) 'payload-fixture'
    $parent=Join-Path $Repository 'artifacts'
    $expected=Join-Path $parent ('native-audit-controller-'+$Context.Fixture)
    Assert-ImmuData ([IO.Path]::IsPathFullyQualified($Repository) -and
        [IO.Path]::GetFullPath($Repository) -ceq $Repository -and $Context.Root -ceq $expected) 'payload-path'
    $ordinary=Get-ProviderOrdinaryItem $parent
    Assert-ImmuData ($ordinary.PSIsContainer -and $ordinary.FullName -ceq $parent) 'payload-parent'
}
function New-AuditDataPublicPayload([string]$Repository,$Context){
    Assert-AuditDataPayloadPath $Repository $Context
    Assert-ImmuData ($Context.PayloadClaimed -is [bool] -and -not $Context.PayloadClaimed -and
        $Context.PayloadRemoved -is [bool] -and -not $Context.PayloadRemoved) 'payload-claim-state'
    # Native exclusive mkdir also refuses a directory created between check and use.
    [Fleetory.Pilot.ExclusiveAuditDirectory]::Create($Context.Root)
    $Context.PayloadClaimed=$true
}
function Remove-AuditDataPublicPayload([string]$Repository,$Context){
    Assert-ImmuData ($Context.PayloadClaimed -is [bool] -and $Context.PayloadRemoved -is [bool]) 'payload-claim-state'
    if(-not $Context.PayloadClaimed){return}
    Assert-AuditDataPayloadPath $Repository $Context
    Remove-NativePublicPayload $Repository $Context.Root
    Assert-ImmuData (-not (Test-Path -LiteralPath $Context.Root)) 'payload-cleanup-absence'
    $Context.PayloadClaimed=$false
    $Context.PayloadRemoved=$true
}
function Publish-AuditDataLedger([string]$Temporary,[string]$Destination){
    if([IO.File]::Exists($Destination)){[IO.File]::Replace($Temporary,$Destination,[NullString]::Value)}
    else{[IO.File]::Move($Temporary,$Destination)}
}
function Write-AuditDataLedger($Context){
    $root=Get-ProviderOrdinaryItem $Context.Root
    Assert-ImmuData ($root.PSIsContainer -and $root.FullName -ceq $Context.Root -and
        $Context.ImageName -ceq (Get-ImmuDataImageName $Context.Fixture) -and
        ($null -eq $Context.ImageId -or $Context.ImageId -cmatch '^sha256:[a-f0-9]{64}\z') -and
        $Context.Stores.Count -le 16) 'ledger-context'
    $items=@($Context.Stores|ForEach-Object {
        Assert-ImmuData ($_.Session -cmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\z' -and
            $_.Name -ceq ('fleetory-immu-store-'+$_.Session.Replace('-','')) -and
            ($null -eq $_.Id -or $_.Id -cmatch '^[a-f0-9]{64}\z') -and $_.Started -is [DateTimeOffset] -and
            $_.Role -cin @('source','target','corrupt')) 'ledger-store'
        @{Id=$_.Id;Session=$_.Session;Name=$_.Name;Started=$_.Started;Role=$_.Role}
    })
    $bytes=[Text.Encoding]::UTF8.GetBytes((@{fixture=$Context.Fixture;image=$Context.ImageName;imageId=$Context.ImageId;stores=$items}|ConvertTo-Json -Depth 7 -Compress))
    Assert-ImmuData ($bytes.Length -gt 0 -and $bytes.Length -le 16384) 'ledger-size'
    $destination=Join-Path $Context.Root 'owned-stores.json'
    if(Test-Path -LiteralPath $destination){
        $existing=Get-ProviderOrdinaryItem $destination
        Assert-ImmuData (-not $existing.PSIsContainer -and $existing.Length -le 16384) 'ledger-destination'
    }
    $temporary=Join-Path $Context.Root ('owned-stores.'+[Guid]::NewGuid().ToString('N')+'.tmp')
    $stream=$null;$claimed=$false
    try{
        $stream=[IO.FileStream]::new($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,
            4096,[IO.FileOptions]::WriteThrough)
        $claimed=$true
        $stream.Write($bytes,0,$bytes.Length)
        $stream.Flush($true)
        $stream.Dispose();$stream=$null
        # Same-directory rename publishes a complete flushed record, never truncated JSON.
        Publish-AuditDataLedger $temporary $destination
    }finally{
        if($null -ne $stream){$stream.Dispose()}
        if($claimed -and (Test-Path -LiteralPath $temporary)){
            $ordinary=Get-ProviderOrdinaryItem $temporary
            Assert-ImmuData (-not $ordinary.PSIsContainer -and $ordinary.FullName -ceq $temporary) 'ledger-temporary'
            [IO.File]::Delete($temporary)
        }
    }
}
