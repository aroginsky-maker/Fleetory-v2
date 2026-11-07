# NuGet dependency audit gate

Baseline section 20 includes dependency scanning in the security gate. Fleetory
now records explicit solution-wide NuGet audit coverage alongside the existing
strict build and Sonar analysis. This checks known package advisories for the
resolved `Fleetory.sln` graph; runtime/OS images, separate tools outside that
solution and source-code SAST have their own scopes. The separate
[secret scan gate](SecretScanning.md) checks committed Git history.

Run the normal `eng/verify-quality.ps1` entry point. Its first step forces solution
restore with `NuGetAudit=true`, `NuGetAuditMode=all`, `NuGetAuditLevel=low`, static
graph evaluation disabled and MSBuild warnings promoted to errors. Direct and
transitive packages are audited. Feed failures (NU1900), low/moderate/high/critical
advisories (NU1901–NU1904) and a missing vulnerability database (NU1905) stop the
command. Audit exceptions or advisory suppressions were not added.

The project defaults are explicit in `Directory.Build.props`. `NuGet.Config`
sets the approved public NuGet v3 audit source independently of inherited
package-download sources; it neither embeds credentials nor changes those package
sources. NuGet uses its normal vulnerability metadata/cache behavior. A successful
run means no applicable known advisory was reported at that check, not that every
possible vulnerability is absent.

`Directory.Solution.targets` checks the restore task's actual
`RestoreProjectCount`, `RestoreProjectsAuditedCount` and `RestoreSkippedCount`
when `FleetoryRequireDependencyAudit=true`. The strict quality command requires a
positive graph, all projects audited and zero skipped projects. Missing counters,
partial coverage, weaker audit settings and static graph mode fail. A cached/no-op
restore cannot satisfy this particular gate; the entry point uses `--force`.
Static graph restore does not expose the required counters and is deliberately
unsupported in this verification path.

`DEPENDENCY AUDIT COVERAGE` in the log reports graph coverage only. Restore must
also finish successfully before build/tests continue; a coverage line alone
does not establish advisory success. The local check on 27 October 2026 covered
26/26 solution projects. An additional native `dotnet list Fleetory.sln package
--vulnerable --include-transitive --format json --output-version 1 --no-restore`
inspection reported no vulnerable packages across those 26 project entries.

`DependencyAudit.Tests.ps1` invokes the actual MSBuild target against an isolated
harness: full coverage is accepted, 13 incomplete/weakened configurations are
rejected, and all six audit warning codes fail under the same `-warnaserror`
switch. The warning probes are synthetic gate checks, not claims that a vulnerable
package was installed. Windows/Linux CI also runs the real solution restore.

Configuration and counter behavior follow Microsoft's
[NuGet audit documentation](https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages);
the supplementary report uses the official
[package-list command](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-package-list).
