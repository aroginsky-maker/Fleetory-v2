#requires -Version 7.3
# Liveness only: this object never grants Docker custody or original-input authority.
if(-not (Get-Variable -Scope Script -Name retainedControllerPipeStates -ErrorAction SilentlyContinue)){
    $script:retainedControllerPipeStates=[Runtime.CompilerServices.ConditionalWeakTable[object,object]]::new()
    $script:retainedControllerPipeStarted=$false
}
function Get-RetainedControllerParentId{
    if($IsWindows){
        $items=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID) -ErrorAction Stop)
        Assert-ImmuData ($items.Count -eq 1 -and $items[0].ProcessId -eq $PID) 'controller-own-process'
        return [int]$items[0].ParentProcessId
    }
    Assert-ImmuData $IsLinux 'controller-platform'
    $text=[IO.File]::ReadAllText('/proc/self/stat',[Text.Encoding]::ASCII)
    $end=$text.LastIndexOf(')')
    Assert-ImmuData ($text.Length -le 4096 -and $end -gt 0 -and $text.StartsWith(([string]$PID+' ('),[StringComparison]::Ordinal)) 'controller-own-stat'
    $fields=$text.Substring($end+1).Trim().Split(' ',[StringSplitOptions]::RemoveEmptyEntries)
    Assert-ImmuData ($fields.Count -ge 20 -and $fields[1] -cmatch '^[1-9][0-9]{0,9}\z') 'controller-parent-stat'
    return [int]$fields[1]
}
function Get-RetainedControllerImageHash([string]$Path){
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{
        Assert-ImmuData ($stream.Length -gt 0 -and $stream.Length -le 16777216) 'controller-image-bound'
        return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
    }finally{$stream.Dispose()}
}
function New-RetainedControllerPipe([string]$Python,[Diagnostics.Stopwatch]$OwnerWatch){
    Assert-ImmuData (-not $script:retainedControllerPipeStarted) 'controller-pipe-one-use'
    $script:retainedControllerPipeStarted=$true
    Assert-ImmuData ([Console]::IsInputRedirected -and [Console]::IsOutputRedirected -and
        $null -ne $OwnerWatch -and $OwnerWatch.IsRunning -and $OwnerWatch.ElapsedMilliseconds -lt 600000) 'controller-pipe-start'
    $parentIdentifier=Get-RetainedControllerParentId
    Assert-ImmuData ($parentIdentifier -gt 0 -and $parentIdentifier -ne $PID) 'controller-parent-id'
    $parent=$null;$inputStream=$null
    try{
        $parent=[Diagnostics.Process]::GetProcessById($parentIdentifier)
        $null=$parent.Handle
        $birth=Get-HistoricalNativeBirth $parent
        $image=Get-RetainedControllerImageHash $parent.MainModule.FileName
        Assert-ImmuData ($image -ceq (Get-RetainedControllerImageHash $Python) -and -not $parent.HasExited) 'controller-parent-image'
        $inputStream=[Console]::OpenStandardInput()
        $buffer=[byte[]]::new(1)
        $pending=$inputStream.ReadAsync($buffer,0,1)
        $context=[object]::new()
        $held=@{ownerId=$PID;parent=$parent;birth=$birth;image=$image;input=$inputStream;buffer=$buffer;pending=$pending;
            clock=[Diagnostics.Stopwatch]::StartNew();remainingMilliseconds=(600000-$OwnerWatch.ElapsedMilliseconds);
            armed=$false;nonce=$null;lost=$false;lossKind=$null;checks=0;closed=$false}
        $script:retainedControllerPipeStates.Add($context,$held)
        $parent=$inputStream=$null
        return $context
    }finally{
        if($null -ne $inputStream){$inputStream.Dispose()}
        if($null -ne $parent){$parent.Dispose()}
    }
}
function Read-RetainedControllerPipeState($Context){
    $held=$null
    Assert-ImmuData ($null -ne $Context -and $script:retainedControllerPipeStates.TryGetValue($Context,[ref]$held)) 'controller-pipe-original-context'
    Assert-ImmuData ($held.ownerId -eq $PID -and -not $held.closed) 'controller-pipe-live-owner'
    return $held
}
function Assert-RetainedControllerPipe($Context){
    $held=Read-RetainedControllerPipeState $Context
    $held.checks++
    if(-not $held.lost){
        $reason=$null
        if($held.parent.HasExited){$reason='parent-exited'}
        elseif($held.clock.ElapsedMilliseconds -ge $held.remainingMilliseconds){$reason='owner-deadline'}
        elseif($held.pending.IsCompleted){
            try{$reason=if($held.pending.GetAwaiter().GetResult() -eq 0){'input-closed'}else{'unexpected-input'}}catch{$reason='input-error'}
        }
        if($null -ne $reason){$held.lost=$true;$held.lossKind=$reason}
    }
    if($held.lost){throw [OperationCanceledException]::new('Retained external controller is no longer admitted.')}
    $birth=Get-HistoricalNativeBirth $held.parent
    Assert-ImmuData ($birth.kind -ceq $held.birth.kind -and $birth.token -ceq $held.birth.token) 'controller-parent-birth'
}
function Arm-RetainedControllerPipe($Context,[string]$Nonce){
    Assert-RetainedControllerPipe $Context
    $held=Read-RetainedControllerPipeState $Context
    Assert-ImmuData (-not $held.armed -and $Nonce -cmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\z') 'controller-pipe-arm'
    $held.armed=$true;$held.nonce=$Nonce
    $frame=@{schema='fleetory.native-owner-controller-arm.v1';nonce=$Nonce;ownerPid=$PID;controllerPid=$held.parent.Id;
        controllerBirth=$held.birth;controllerImageSha256=$held.image;ownerBirth=(Get-HistoricalNativeBirth ([Diagnostics.Process]::GetCurrentProcess()));cleanupAuthorized=$false}
    [Console]::Out.WriteLine(($frame|ConvertTo-Json -Depth 4 -Compress))
    [Console]::Out.Flush()
}
function Get-RetainedControllerPipeSnapshot($Context){
    $held=Read-RetainedControllerPipeState $Context
    return @{schema='fleetory.retained-controller-pipe-observation.v1';ownerPid=$PID;controllerPid=$held.parent.Id;
        controllerBirth=$held.birth;controllerImageSha256=$held.image;armed=$held.armed;nonce=$held.nonce;
        lossObserved=$held.lost;lossKind=$held.lossKind;parentExited=$held.parent.HasExited;checks=$held.checks;
        controllerOriginAuthenticated=$false;cleanupAuthorized=$false;controllerDeathCleanupVerified=$false;phase7Complete=$false}
}
function Close-RetainedControllerPipe($Context){
    if($null -eq $Context){return}
    $held=Read-RetainedControllerPipeState $Context
    $held.closed=$true
    try{$held.input.Dispose()}finally{
        $held.parent.Dispose();$held.clock.Stop()
        $null=$script:retainedControllerPipeStates.Remove($Context)
    }
}
