#requires -Version 7.3
# Fixed public compiler invocation; no service, image, private material or arbitrary command.
function Invoke-HistoricalPublicPublication([string]$ExpectedPin,[string]$Python,[string]$Repository,[string]$Git,[string]$Dotnet){
    $stage='header';$stream=[Console]::OpenStandardInput()
    $helper=Join-Path $PSScriptRoot 'audit_native_publication.py'
    $oldRoot=$env:DOTNET_ROOT;$oldX64=$env:DOTNET_ROOT_X64;$oldMulti=$env:DOTNET_MULTILEVEL_LOOKUP
    try{
        $raw=Read-PreparationFrame $stream 24576
        $checked=Invoke-NativeBytes $Python @('-B',$helper,'header',$ExpectedPin) $raw 5
        Assert-ImmuData ($checked.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($checked.Stderr)) 'publication-header'
        $info=$checked.Stdout|ConvertFrom-Json -AsHashtable
        $header=[Text.Encoding]::UTF8.GetString($raw)|ConvertFrom-Json -AsHashtable
        $stage='git';Assert-PreparationGit $Git $info.gitSha256
        $stage='code';Assert-PreparationSnapshot $Repository $Git $info
        $stage='sdk'
        Assert-ImmuData ([IO.Path]::IsPathFullyQualified($Dotnet) -and [IO.Path]::GetFileName($Dotnet) -in @('dotnet','dotnet.exe')) 'publication-dotnet-path'
        $env:DOTNET_ROOT=Split-Path $Dotnet -Parent;$env:DOTNET_ROOT_X64=$env:DOTNET_ROOT;$env:DOTNET_MULTILEVEL_LOOKUP='0'
        Assert-ImmuData ((Get-HistoricalInputFileHash $Dotnet 67108864).sha256 -ceq $header.dotnetSha256) 'publication-dotnet-pin'
        $sdk=Invoke-NativeBytes $Dotnet @('--version') $null 5
        Assert-ImmuData ($sdk.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($sdk.Stderr) -and $sdk.Stdout.Trim() -ceq '10.0.402') 'publication-sdk'
        $readyBytes=Send-PreparationReady $info;$readyPin=Get-ImmuDataHash $readyBytes
        $reservation=$null
        function Invoke-PublicationAction([string]$Mode,[byte[]]$Frame){
            $body=@{schema='fleetory.native-publication-action.v1';headerBase64=[Convert]::ToBase64String($raw);
                frameBase64=[Convert]::ToBase64String($Frame);namespaceReady=$reservation}
            $result=Invoke-NativeBytes $Python @('-B',$helper,$Mode,$ExpectedPin,$readyPin,$PID.ToString()) ([Text.Encoding]::UTF8.GetBytes(($body|ConvertTo-Json -Depth 8 -Compress))) 5
            Assert-ImmuData ($result.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($result.Stderr)) 'publication-action'
            return $result.Stdout|ConvertFrom-Json -AsHashtable
        }
        $stage='reserve';$frame=Read-PreparationFrame $stream 2048
        $reservation=Invoke-PublicationAction 'reserve' $frame
        $null=Send-PreparationFrame $reservation
        $stage='publish';$frame=Read-PreparationFrame $stream 2048
        $null=Invoke-PublicationAction 'publish' $frame
        Assert-PreparationSnapshot $Repository $Git $info
        $output=Join-Path $Repository ('artifacts/native-probe-publication-'+$info.nonce+'/publish')
        $project=Join-Path $Repository 'eng/ServerBackendProbe/ServerBackendProbe.csproj'
        $published=Invoke-NativeBytes $Dotnet @('publish',$project,'-c','Release','--no-restore','--disable-build-servers','-p:UseAppHost=false','-o',$output) $null 20
        Assert-ImmuData ($published.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($published.Stderr)) 'publication-build'
        Assert-PreparationSnapshot $Repository $Git $info
        Assert-ImmuData ((Get-HistoricalInputFileHash $Dotnet 67108864).sha256 -ceq $header.dotnetSha256) 'publication-dotnet-changed'
        $stage='seal';$null=Send-PreparationFrame (Invoke-PublicationAction 'seal' $frame)
        $stage='close';$frame=Read-PreparationFrame $stream 2048
        Assert-ImmuData ($stream.ReadByte() -eq -1) 'publication-trailing-input'
        $null=Send-PreparationFrame (Invoke-PublicationAction 'close' $frame)
        return 0
    }catch{
        $null=Send-PreparationFrame @{schema='fleetory.native-publication-refused.v1';stage=$stage;privateInputsAccepted=$false;backendCreated=$false}
        [Console]::Error.WriteLine('Native public publication refused; no private input accepted.')
        return 1
    }finally{
        $env:DOTNET_ROOT=$oldRoot;$env:DOTNET_ROOT_X64=$oldX64;$env:DOTNET_MULTILEVEL_LOOKUP=$oldMulti
    }
}
