# Fleetory v2 — Server Packaging Architecture (PHASE 5)

## Status and scope

This document defines the PHASE 5 packaging boundary for the OS-neutral `Fleetory.Server` application host.
It does not change bounded-context ownership, public contracts, persistence, Security Foundation or Agent architecture.

Supported server OS targets in this phase are:

- Windows x64 (`win-x64`);
- Linux x64 (`linux-x64`).

macOS is not a supported Fleetory Server target in the current baseline.

## Publish model

PHASE 5 uses two explicit RID publishes of the same OS-neutral server project:

```text
dotnet publish src/Fleetory.Server/Fleetory.Server.csproj -c Release -r win-x64   --self-contained false -p:UseAppHost=false
dotnet publish src/Fleetory.Server/Fleetory.Server.csproj -c Release -r linux-x64 --self-contained false -p:UseAppHost=false
```

The selected PHASE 5 packaging model is **framework-dependent deployment (FDD)** with no generated apphost.
This is the smallest technically sufficient choice because the normative documents require reproducible Windows/Linux packaging but do not require a bundled .NET runtime.
The runtime prerequisite is therefore the matching supported **.NET 10 runtime** on the target server.

This is a packaging choice, not a change to Fleetory bounded-context or deployment architecture. A future release/deployment profile may choose self-contained artifacts only if that becomes an explicit requirement.

`UseAppHost=false` keeps the runtime entry point identical on both platforms:

```text
dotnet Fleetory.Server.dll
```

No RID-specific business code is introduced.

## Repository-local workflow

Primary Windows workflow:

```powershell
.\eng\package-server.ps1
```

Linux/CI workflow:

```bash
./eng/package-server.sh
```

Both scripts:

1. delete only `artifacts/server/`;
2. restore dependencies;
3. perform a Release `win-x64` publish;
4. perform a Release `linux-x64` publish;
5. create distributable archives;
6. fail with a non-zero exit code on errors.

Generated layout:

```text
artifacts/server/
├── win-x64/
├── linux-x64/
├── Fleetory.Server-win-x64.zip
└── Fleetory.Server-linux-x64.tar.gz
```

`artifacts/` is ignored by Git and is not part of the source package.

## Package contents

Each publish directory must contain at least:

- `Fleetory.Server.dll`;
- `Fleetory.Server.deps.json`;
- `Fleetory.Server.runtimeconfig.json`;
- `appsettings.json`;
- `appsettings.Production.json`;
- the Fleetory module/runtime assemblies required by the Server.

The package must not contain:

- source files or project/solution files;
- test assemblies;
- `bin/` or `obj/` trees from unrelated projects;
- coverage or `.sonarqube` artifacts;
- `appsettings.Development.json`;
- repository secrets or production credentials.

`appsettings.Development.json` remains useful for source-tree development but is explicitly excluded from publish output by `Fleetory.Server.csproj`.

## Configuration model

Fleetory.Server keeps the standard .NET configuration stack already established by the solution:

- `appsettings.json`;
- environment-specific JSON such as `appsettings.Production.json`;
- environment variables with the existing `FLEETORY_` prefix;
- ordinary .NET command-line configuration.

PHASE 5 does not introduce a Secret Provider, connection string, database configuration, authentication material or other PHASE 6/7 concerns.

A published-server smoke test is executed with the working directory set to the publish directory. Nothing depends on an absolute developer-machine path.

## Startup and shutdown model

The runtime entry point is:

```text
dotnet Fleetory.Server.dll
```

`Fleetory.Server` remains the only composition root and continues to register the approved modules at compile time.
It uses the standard ASP.NET Core / Generic Host lifecycle and does not contain Windows Service or systemd-specific hosting logic.

Linux verification terminates the smoke-test process with `SIGTERM`, exercising the normal Generic Host shutdown path.
The Windows PowerShell smoke harness terminates its child process after HTTP checks as test cleanup; PHASE 5 does not add a Windows Service implementation merely to manufacture a service-lifecycle test.

Native Windows Service and systemd packaging/installers remain future deployment concerns outside this phase.

## Health and correlation verification

The published-server verification must preserve:

```text
GET /health/live
GET /health/ready
X-Correlation-ID propagation
```

`eng/verify-phase5.ps1` and `eng/verify-phase5.sh` run the current-host published package and test those behaviors over HTTP.

## Cross-platform verification semantics

Cross-publish and runtime verification are intentionally distinguished:

- publishing `linux-x64` successfully on Windows proves the Linux package can be produced;
- it does **not** prove the Linux package executed correctly on Linux;
- publishing `win-x64` on Linux similarly does not prove Windows runtime behavior.

`verify-phase5.ps1`/`.sh` therefore report current-host runtime status separately from the non-current target.
A Linux runtime PASS may only be claimed from an actual Linux run; a Windows runtime PASS may only be claimed from an actual Windows run.

No macOS Server runtime/package is produced.

## CI status

The PHASE 4 source baseline contains no existing GitHub Actions workflow. PHASE 5 therefore does not introduce a new CI system solely for this packaging task.
The repository-local PowerShell and Bash scripts are CI-ready and can be called from a later approved CI workflow on `windows-latest` and `ubuntu-latest` without changing application architecture.

## Docker

Docker remains an optional Fleetory deployment path. PHASE 5 does not add Docker artifacts because the normative task does not require Docker to establish native Windows/Linux package reproducibility.

No Docker Compose, PostgreSQL container, Kubernetes or orchestration dependency is introduced.

## Explicit non-goals

PHASE 5 does not implement:

- PostgreSQL/Npgsql/EF Core, schemas, repositories or migrations;
- database health checks;
- Authentication/RBAC/MFA/WebAuthn;
- PKI/mTLS, Agent enrollment or credentials;
- Secret Provider;
- Windows Service or systemd daemon integration;
- Agent Protocol or any Agent implementation;
- Docker/Kubernetes orchestration.

These remain deferred to their normative phases.
