#requires -Version 7.3
# Fixed generated v2 operations. Caller owns state, bounded Docker and native observations.
function V2-Sql($Side,[string]$Database,[string]$Sql,[switch]$AllowFailure){
    Assert-Pair ($Database -cin @('postgres','fleetory','fleetory_signer')) 'v2-database'
    Read-PairStore $state $Side 'postgres'
    return Invoke-Docker @('exec','-i','-e','PGCLIENTENCODING=UTF8',$Side.Id,'psql','-XqAt','-v','ON_ERROR_STOP=1','-U','postgres','-d',$Database) ([Text.Encoding]::UTF8.GetBytes("\set VERBOSITY sqlstate`n"+$Sql)) -AllowFailure:$AllowFailure
}
function V2-Read($Side,[string]$Database,[switch]$Refusal){
    $r=V2-Sql $Side $Database $sqls[$Database] -AllowFailure:$Refusal
    if($r.ExitCode -ne 0){Assert-Pair ($Refusal -and $r.ExitCode -eq 3 -and $r.Stderr -match '\b22012\b') 'v2-native-profile-refusal';return}
    $parsed=Invoke-NativeBytes $Python @('-B',(Join-Path $repo 'eng/pilot/pg_inventory_v2.py'),'readback','--database',$Database) $r.StdoutBytes 20
    if($Refusal){Assert-Pair ($parsed.ExitCode -eq 1 -and $parsed.Stdout -ceq '' -and $parsed.Stderr.Trim() -ceq 'PostgreSQL v2 transcript refused; no contents logged.') 'v2-transcript-refusal';return}
    Assert-Pair ($parsed.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($parsed.Stderr)) 'v2-parser'
    return $parsed.Stdout|ConvertFrom-Json -AsHashtable -Depth 20
}
function V2-Same($Value,$Baseline){
    foreach($field in @('inventorySha256','securitySha256')){Assert-Pair ($Value.inventory[$field] -ceq $Baseline.inventory[$field]) ('v2-'+$field)}
    Assert-Pair ($Value.additionalSecuritySha256 -ceq $Baseline.additionalSecuritySha256 -and $Value.generatedRolePolicyAccepted -eq $true) 'v2-additional-role-state'
}
function V2-NewDatabase($Side,[string]$Database){
    Assert-Pair ($Database -cin @('fleetory','fleetory_signer')) 'v2-create-database'
    $owner=if($Database -ceq 'fleetory'){'fleetory_migrator'}else{'fleetory_signer_owner'}
    $runtime=if($Database -ceq 'fleetory'){'fleetory_server'}else{'fleetory_signer'}
    $null=V2-Sql $Side 'postgres' ("CREATE DATABASE $Database OWNER $owner;REVOKE ALL ON DATABASE $Database FROM PUBLIC;GRANT CONNECT ON DATABASE $Database TO $runtime;")
}
function V2-RestoreArguments([string]$Database,[switch]$List){
    Assert-Pair ($Database -cin @('fleetory','fleetory_signer')) 'v2-restore-database'
    Read-PairStore $state $target 'postgres'
    if($List){return @('exec','-i',$target.Id,'pg_restore','--list')}
    $owner=if($Database -ceq 'fleetory'){'fleetory_migrator'}else{'fleetory_signer_owner'}
    return @('exec','-i',$target.Id,'pg_restore','--exit-on-error','--single-transaction','--no-password',('--role='+$owner),'--username=postgres',('--dbname='+$Database))
}
function V2-Restore([string]$Database){
    $null=V2-Sql $target 'postgres' ("DROP DATABASE $Database;")
    V2-NewDatabase $target $Database
    $r=Invoke-Docker (V2-RestoreArguments $Database) $captured[$Database]
    Assert-Pair ([string]::IsNullOrWhiteSpace($r.Stdout+$r.Stderr)) 'v2-quiet-restore'
    V2-Same (V2-Read $target $Database) $expected[$Database]
    $script:restores++
}
function V2-Runtime([string]$Database,[string]$Password,[string]$Query,[string]$SslMode='verify-full'){
    Assert-Pair ($Database -cin @('fleetory','fleetory_signer') -and $SslMode -cin @('verify-full','disable')) 'v2-runtime-binding'
    $runtime=if($Database -ceq 'fleetory'){'fleetory_server'}else{'fleetory_signer'}
    Read-PairStore $state $target 'postgres'
    $null=Invoke-Docker @('exec','-i',$target.Id,'/bin/sh','-c','umask 077; cat > /tmp/pgpass') ([Text.Encoding]::UTF8.GetBytes("127.0.0.1:5432:${Database}:${runtime}:${Password}`n"))
    Assert-Pair ((Invoke-Docker @('exec',$target.Id,'stat','-c','%a:%u:%h','/tmp/pgpass')).Stdout.Trim() -ceq '600:999:1') 'v2-password-slot'
    return Invoke-Docker @('exec','-i','-e','PGCLIENTENCODING=UTF8','-e','PGPASSFILE=/tmp/pgpass','-e','PGCONNECT_TIMEOUT=3','-e','PGGSSENCMODE=disable','-e',('PGSSLMODE='+$SslMode),'-e','PGSSLROOTCERT=/tmp/ca.pem',$target.Id,'psql','-XqAt','-w','-v','ON_ERROR_STOP=1','-U',$runtime,'-h','127.0.0.1','-d',$Database) ([Text.Encoding]::UTF8.GetBytes("\set VERBOSITY sqlstate`n"+$Query)) -AllowFailure
}
