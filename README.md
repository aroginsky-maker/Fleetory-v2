# Fleetory v2 — PHASE 2 Modular Monolith + Sonar Quality Hardening

This repository contains the Fleetory v2 source tree after completed PHASE 2 modular-monolith boundary hardening plus the approved cross-cutting Sonar Quality Gate preparation performed before PHASE 3.

PHASE 0, PHASE 1, and PHASE 2 are complete. PHASE 2 was verified on a real Windows environment with 11/11 tests passing. The Sonar-hardening changes in this artifact require a fresh strict verification and a real external Sonar Quality Gate before the quality-hardening task itself can be closed.

PHASE 3 has not been started in this artifact.

## Requirements

- .NET 10 SDK
- network access to NuGet for repository-local tool restore
- for Sonar verification: an existing SonarQube/SonarCloud project and protected runtime parameters
- no database, broker, cache, search engine, container runtime, or Agent runtime is required

## Strict Fleetory verification

```powershell
.\eng\verify-phase2.ps1
```

or:

```bash
./eng/verify-phase2.sh
```

The strict gate runs:

```text
dotnet restore Fleetory.sln
dotnet build Fleetory.sln -c Release --no-restore
dotnet test Fleetory.sln -c Release --no-build
```

Nullable, TreatWarningsAsErrors, and Architecture Tests remain enabled.

## Sonar quality verification

Repository-local tools are pinned in `.config/dotnet-tools.json`.

Required environment variables:

```text
SONAR_HOST_URL
SONAR_PROJECT_KEY
SONAR_TOKEN
```

Optional:

```text
SONAR_PROJECT_NAME
SONAR_QUALITYGATE_TIMEOUT
```

Run the complete Windows quality path:

```powershell
.\eng\verify-quality.ps1
```

Or run only the Sonar gate after independently verifying the strict build:

```powershell
.\eng\verify-sonar.ps1
```

Bash Sonar path:

```bash
./eng/verify-sonar.sh
```

Coverage is written to:

```text
artifacts/coverage/coverage.xml
```

Detailed policy and troubleshooting:

- `docs/quality/SonarQualityGate.md`
- `Fleetory_Sonar_Quality_Gate_Report.md`

## Run the Server

```bash
dotnet run --project src/Fleetory.Server/Fleetory.Server.csproj
```

Host-level health endpoints:

- `GET /health/live`
- `GET /health/ready`

## Modular-monolith dependency policy

```text
Fleetory.Server
  -> Fleetory.ModuleAbstractions
  -> Fleetory.Platform
  -> Fleetory.Core
  -> Fleetory.Assets
  -> Fleetory.ITSM
  -> Fleetory.CMDB
  -> Fleetory.Monitoring
  -> Fleetory.Integrations

Fleetory.Platform
  -> Fleetory.Platform.Contracts
  -> Fleetory.ModuleAbstractions

Each non-Platform module implementation
  -> its own *.Contracts
  -> Fleetory.Platform.Contracts
  -> Fleetory.ModuleAbstractions

Each *.Contracts
  -> Fleetory.SharedKernel

Fleetory.ModuleAbstractions
  -> no Fleetory project

Fleetory.SharedKernel
  -> no Fleetory project
```

Direct implementation-to-implementation references between bounded contexts are prohibited. Cross-context `*.Contracts -> *.Contracts` references remain prohibited in PHASE 2. Future approved contract dependencies belong to PHASE 3.

The full rule set is documented in `docs/architecture/ModularMonolith.md` and enforced by `tests/Fleetory.Architecture.Tests/ArchitectureBoundaryTests.cs`.

## Endpoint and configuration ownership

`Fleetory.Server` remains the single composition root. It supplies the host and configuration root, then delegates module service registration and endpoint registration through `IFleetoryModule`.

Module-specific endpoints must be mapped by their owning module. No business endpoints exist in PHASE 2. `/health/live` and `/health/ready` remain Server infrastructure endpoints.

## OS-neutral Server runtime

Architecture tests guard the shared Server/runtime projects against direct Windows-only dependencies and APIs. This protects future Windows Server/Linux Server parity.

## Intentionally not implemented

- PHASE 3 data ownership, Context Bridge DTOs, cross-module event/summary contracts
- PHASE 4 Identity, Authentication, RBAC, Audit, Licensing, Search, Notifications, Configuration service
- PHASE 5 native cross-platform Server packaging
- PHASE 6 PostgreSQL runtime, schemas, migrations, repositories, connection strings, v1 migration
- Agent Core, Windows/Linux/macOS Agent, Agent Protocol, enrollment, PKI/mTLS, Command Plane
- business/domain entities and workflows
- Redis, Kafka/RabbitMQ, OpenSearch/Elasticsearch, Kubernetes, distributed event bus, microservices

PHASE 3 must not begin until the approved cross-cutting Sonar Quality Gate hardening has passed both the fresh strict verification and the real external Sonar Quality Gate.
