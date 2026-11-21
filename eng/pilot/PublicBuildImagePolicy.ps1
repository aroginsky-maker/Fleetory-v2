#requires -Version 7.3
# Fixed command construction only; a label or argument list does not grant custody.
if(-not ('Fleetory.Pilot.PublicBuildInstance' -as [type])){
    Add-Type -TypeDefinition @'
using System;
namespace Fleetory.Pilot {
    public static class PublicBuildInstance {
        public static void Validate(string value) {
            if(!Guid.TryParseExact(value,"D",out var parsed) || parsed==Guid.Empty || parsed.ToString("D")!=value)
                throw new InvalidOperationException("Public build instance refused.");
        }
    }
}
'@
}
function Get-PublicBuildImageArguments([string]$Instance){
    [Fleetory.Pilot.PublicBuildInstance]::Validate($Instance)
    # Distinct worker-minted instance changes the image config even on a cache hit.
    # The future live worker must consume that instance before its sole build call.
    return [string[]]@('build','--quiet','--network','none','--pull=false','--label',
        ('fleetory.public-build.instance='+$Instance),'-')
}
