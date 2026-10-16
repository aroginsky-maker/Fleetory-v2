# Fleetory v2 — PHASE 5 Implementation Report

**Phase:** PHASE 5 — Cross-platform Server Package  
**Status:** **IMPLEMENTED / VERIFICATION PENDING**  
**Source baseline:** current PHASE 4 working tree, user-confirmed `PHASE 4 = COMPLETE`

## 1. Incoming confirmed baseline

The PHASE 5 handoff explicitly confirms:

```text
PHASE 0             COMPLETE
PHASE 1             COMPLETE
PHASE 2             COMPLETE
PHASE 3             COMPLETE
PHASE 4             COMPLETE
STRICT BUILD        PASS
TESTS               PASS
ARCHITECTURE TESTS  PASS
SONAR ANALYSIS      PASS
SONAR QUALITY GATE  PASSED
```

PHASE 5 does not revisit those earlier architecture decisions.

## 2. Objective

PHASE 5 adds a reproducible Windows/Linux packaging and verification layer around the existing OS-neutral `Fleetory.Server` composition root.

It deliberately does not add persistence, Security Foundation, Agent functionality, service-manager integration or new bounded contexts.

## 3. Packaging model selected

The normative documents do not mandate framework-dependent versus self-contained deployment for PHASE 5.

This implementation selects the minimum technically sufficient option:

- **framework-dependent deployment**;
- target RIDs: `win-x64` and `linux-x64`;
- `--self-contained false`;
- `UseAppHost=false`;
- target servers require the supported **.NET 10 runtime**;
- identical runtime entry point on both platforms: `dotnet Fleetory.Server.dll`.

This avoids bundling a runtime that was not required by the baseline and keeps the package model lightweight. It does not change the approved deployment architecture.

**ARCHITECTURE DECISION REQUIRED: none.**

## 4. Files changed/created

```text
README.md
Fleetory_v2_PHASE4_Implementation_Report.md
Fleetory_v2_PHASE5_Implementation_Report.md
docs/architecture/ServerPackaging.md
eng/package-server.ps1
eng/package-server.sh
eng/verify-phase5.ps1
eng/verify-phase5.sh
src/Fleetory.Server/Fleetory.Server.csproj
tests/Fleetory.Architecture.Tests/ArchitectureBoundaryTests.cs
```

No bounded-context implementation or public contract was changed.

## 5. Server project packaging change

`src/Fleetory.Server/Fleetory.Server.csproj` remains RID-neutral and contains no Windows/Linux hosting dependency.

The only PHASE 5 project-file change excludes:

```text
appsettings.Development.json
```

from publish output. Development settings remain available in the source tree but are not shipped in native server packages.

No `RuntimeIdentifier`, `RuntimeIdentifiers`, `SelfContained`, Windows Service or systemd property/package is pinned in the common Server project.

## 6. Repository-local package scripts

Created:

- `eng/package-server.ps1` — primary Windows packaging path;
- `eng/package-server.sh` — Linux/CI equivalent.

Both scripts:

1. remove only `artifacts/server/`;
2. restore the solution unless explicitly skipped by the phase verifier;
3. perform an immediate RID-specific restore for `win-x64`;
4. publish Release `win-x64` framework-dependent output;
5. perform an immediate RID-specific restore for `linux-x64`;
6. publish Release `linux-x64` framework-dependent output;
7. create distributable archives;
8. return a non-zero exit code on failure.

Expected generated layout:

```text
artifacts/server/
├── win-x64/
├── linux-x64/
├── Fleetory.Server-win-x64.zip
└── Fleetory.Server-linux-x64.tar.gz
```

The generated `artifacts/` directory remains Git-ignored and is not embedded in the PHASE 5 source archive.

## 7. Package-content policy

`eng/verify-phase5.ps1` and `.sh` validate both publish directories.

Required runtime/configuration artifacts include:

- `Fleetory.Server.dll`;
- `Fleetory.Server.deps.json`;
- `Fleetory.Server.runtimeconfig.json`;
- `appsettings.json`;
- `appsettings.Production.json`.

Validation rejects:

- `appsettings.Development.json`;
- `.cs`, `.csproj`, `.sln` and developer-local files;
- `*.Tests.dll` / `*.Tests.pdb`;
- build/test/Sonar/coverage directories;
- secret-like keys in packaged JSON configuration.

No real credential, token, connection string or secret was added.

## 8. Startup/runtime verification

The published runtime command is:

```text
dotnet Fleetory.Server.dll
```

The PHASE 5 verification scripts run the package matching the current host OS and verify over real HTTP:

- Server startup without IDE;
- `/health/live`;
- `/health/ready`;
- `X-Correlation-ID` propagation.

The process working directory is the publish directory, not a developer source/build directory.

Runtime reporting is deliberately OS-specific:

- Windows runtime PASS is only reported from an actual Windows run;
- Linux runtime PASS is only reported from an actual Linux run;
- the non-current target is reported as `NOT VERIFIED (cross-publish only)`.

On Linux the smoke harness sends `SIGTERM` after verification, exercising normal Generic Host shutdown. PHASE 5 does not introduce Windows Service or systemd APIs to manufacture a service-specific shutdown test.

## 9. OS-neutral architecture guard

The existing Architecture Test for common server-side OS neutrality was strengthened to also reject:

- `OperatingSystem.IsLinux()`;
- `OSPlatform.Linux`;
- `UseWindowsService(`;
- `UseSystemd(`;
- project-level `linux-x64` / `linux-arm64` pinning;
- `RuntimeIdentifier` / `RuntimeIdentifiers` pinning;
- `Microsoft.Extensions.Hosting.Systemd`.

The existing Windows-specific checks remain in place.

The RIDs appear only in repository-local packaging scripts, not in common Server business/runtime code or project references.

No existing Architecture Test was removed or weakened.

## 10. Configuration

The package keeps the standard .NET configuration model already present in Fleetory:

- `appsettings.json`;
- `appsettings.Production.json`;
- `FLEETORY_` environment variables;
- normal .NET command-line configuration.

No Secret Provider is introduced in PHASE 5.

The inert future PostgreSQL provider name already present in configuration remains unchanged; no PostgreSQL package, connection string, database health check or persistence implementation was added.

## 11. CI / Docker decisions

No `.github/workflows` existed in the PHASE 4 source baseline. PHASE 5 therefore does not create a new CI system merely to satisfy the optional matrix suggestion.

The PowerShell and Bash scripts are CI-ready for later use from Windows and Ubuntu runners.

Docker remains optional and was not added. Native Windows/Linux publish paths exist independently, and no Docker Compose/PostgreSQL/Kubernetes artifact was introduced.

## 12. Explicitly deferred work

Not implemented in PHASE 5:

- PostgreSQL/Npgsql/EF Core/DbContext/repositories/migrations/SQL;
- database health checks;
- Authentication, RBAC implementation, JWT/cookies/MFA/WebAuthn;
- PKI/mTLS/Secret Provider;
- Windows Service/systemd daemon integration;
- Agent Protocol, enrollment, Agent Core or platform Agents;
- Command Plane;
- Docker/Kubernetes orchestration.

PHASE 6 was not started.

## 13. Verification scripts

Created:

```text
eng/verify-phase5.ps1
eng/verify-phase5.sh
```

They perform:

1. solution restore;
2. strict Release build;
3. all tests;
4. Architecture Tests separately;
5. Windows publish/package;
6. Linux publish/package;
7. package-content validation;
8. current-host published-server smoke test;
9. `/health/live`;
10. `/health/ready`;
11. CorrelationId propagation;
12. an explicit verification summary.

Full Sonar/coverage verification remains the established:

```powershell
.\eng\verify-quality.ps1
```

## 14. Static verification performed in the execution environment

The execution environment used to implement PHASE 5 does not contain the .NET 10 SDK and does not have access to the Fleetory Sonar project. Therefore build/publish/runtime/Sonar results are not fabricated.

Static checks completed here:

- source baseline extracted from the latest PHASE 4 archive produced in this execution chat;
- Server project remains OS/RID-neutral;
- all project-reference targets still resolve;
- no new project or bounded context was added;
- no PostgreSQL/Npgsql/EF Core/DbContext/SQL/migration implementation was added;
- no authentication/PKI/mTLS/Agent implementation was added;
- `appsettings.Development.json` is explicitly excluded from publish;
- packaging output is isolated under Git-ignored `artifacts/server/`;
- Bash scripts pass `bash -n` syntax validation;
- source archive is validated for integrity after creation.

PowerShell execution syntax and real dotnet publish must be verified on the Windows environment because PowerShell and .NET are not installed in this execution environment.

## 15. Post-change verification status

| Metric | PHASE 5 result in this execution environment |
|---|---:|
| STRICT BUILD | **NOT VERIFIED** |
| TESTS | **NOT VERIFIED** |
| ARCHITECTURE TESTS | **NOT VERIFIED** |
| WINDOWS PUBLISH | **NOT VERIFIED** |
| LINUX PUBLISH | **NOT VERIFIED** |
| WINDOWS RUNTIME TEST | **NOT VERIFIED** |
| LINUX RUNTIME TEST | **NOT VERIFIED** |
| HEALTH TESTS | **NOT VERIFIED** |
| COVERAGE | **NOT VERIFIED** |
| DUPLICATION | **NOT VERIFIED** |
| SECURITY ISSUES | **NOT VERIFIED** |
| OPEN ISSUES | **NOT VERIFIED** |
| SONAR ANALYSIS | **NOT VERIFIED** |
| SONAR QUALITY GATE | **NOT VERIFIED** |

These are PHASE 5 post-change values. The confirmed PHASE 4 PASS values are only the incoming baseline and are not reused as evidence for modified PHASE 5 source.

## 16. Required closure commands

On the real Windows verification environment:

```powershell
.\eng\verify-phase5.ps1
.\eng\verify-quality.ps1
```

`verify-phase5.ps1` should report Windows runtime PASS and Linux runtime `NOT VERIFIED (cross-publish only)` while still requiring both Windows and Linux publish/package validation to pass.

An actual Linux run of:

```bash
./eng/verify-phase5.sh
```

is required before separately claiming Linux runtime PASS.

## 17. Architecture decision status

**ARCHITECTURE DECISION REQUIRED: none.**

The framework-dependent packaging choice is explicitly permitted by the PHASE 5 task as the minimal technical option when self-contained vs framework-dependent deployment is not otherwise fixed.

## 18. Exit status

**PHASE 5 = IMPLEMENTED / VERIFICATION PENDING**

Do not mark PHASE 5 COMPLETE until the real strict/package/current-host runtime/Sonar checks satisfy the required criteria.

**PHASE 6 was not started.**
