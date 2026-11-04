#requires -Version 7.3
. (Join-Path $PSScriptRoot 'NativeStoreFixture.ps1')
$script:nativeJournalImage='postgres:18.6@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336'
$script:nativeJournalTmpfs=@{
    '/var/lib/postgresql'='rw,noexec,nosuid,nodev,size=256m,uid=999,gid=999,mode=0700'
    '/var/run/postgresql'='rw,noexec,nosuid,nodev,size=16m,uid=999,gid=999,mode=0700'
    '/tmp'='rw,noexec,nosuid,nodev,size=32m,uid=999,gid=999,mode=0700'
}
function Get-NativeJournalArguments([string]$Session){
    Assert-NativeSigner ($Session -cmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') 'journal-identity'
    return @('run','-d','--rm','--name',('fleetory-native-journal-'+$Session.Replace('-','')),
        '--label',('fleetory.native-journal.session='+$Session),'--network','none','--read-only','--user','999:999',
        '--cap-drop','ALL','--security-opt','no-new-privileges','--memory','384m','--cpus','1','--pids-limit','128','--ulimit','core=0',
        '--tmpfs',('/var/lib/postgresql:'+$script:nativeJournalTmpfs['/var/lib/postgresql']),
        '--tmpfs',('/var/run/postgresql:'+$script:nativeJournalTmpfs['/var/run/postgresql']),
        '--tmpfs',('/tmp:'+$script:nativeJournalTmpfs['/tmp']),
        '--entrypoint','/bin/sh',$script:nativeJournalImage,'-c','exec /bin/sleep 3300')
}
function Assert-NativeJournal($Info,[string]$Id,[string]$Session,[string]$ImageId,[DateTimeOffset]$NotBefore,[switch]$CleanupOnly){
    $created=ConvertTo-ProviderTimestamp $Info.Created
    Assert-NativeSigner ($Id -cmatch '^[0-9a-f]{64}$' -and $Info.Id -ceq $Id -and
        $Info.Name -ceq ('/fleetory-native-journal-'+$Session.Replace('-','')) -and $Info.Config.Image -ceq $script:nativeJournalImage -and
        $Info.Image -ceq $ImageId -and $Info.Config.Labels['fleetory.native-journal.session'] -ceq $Session -and
        $created -ge $NotBefore -and $created -le [DateTimeOffset]::UtcNow.AddSeconds(5)) 'journal-ownership'
    if($CleanupOnly){return}
    Assert-NativeStoreRuntime $Info '999:999' 'journal'
    Assert-NativeSigner ($Info.HostConfig.NetworkMode -ceq 'none') 'journal-runtime'
    Assert-NativeSigner ((@($Info.HostConfig.Tmpfs.Keys|Sort-Object)-join '|') -ceq (@($script:nativeJournalTmpfs.Keys|Sort-Object)-join '|')) 'journal-tmpfs'
    foreach($path in $script:nativeJournalTmpfs.Keys){Assert-NativeSigner ($Info.HostConfig.Tmpfs[$path] -ceq $script:nativeJournalTmpfs[$path]) 'journal-tmpfs'}
}
