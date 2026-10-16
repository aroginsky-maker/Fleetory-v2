# Fleetory v2 Modular Monolith Boundary Rules

**Stage:** PHASE 2 — Modular Monolith  
**Status:** Normative implementation note for the current Fleetory v2 codebase.  
**Higher authority:** Fleetory Development Baseline & Architecture Charter v1.0 and Fleetory v2 Development Start Plan & Execution Chat Protocol.

This document explains the compile-time boundaries enforced by `Fleetory.Architecture.Tests`. It does not replace those tests.

**PHASE 3 note:** `docs/architecture/DataOwnership.md` and `docs/architecture/InterModuleContractsAndEvents.md` now define data ownership and the first minimal public contract surface. The modular-monolith dependency policy remains unchanged, and the cross-context `*.Contracts -> *.Contracts` allowlist remains empty.

## 1. Bounded contexts

The Fleetory v2 modular monolith currently contains exactly these bounded contexts:

- Platform
- Core
- Assets
- ITSM
- CMDB
- Monitoring
- Integrations

Each bounded context has:

- one implementation assembly: `Fleetory.<Context>`;
- one public contract assembly: `Fleetory.<Context>.Contracts`.

The shared infrastructure projects are:

- `Fleetory.SharedKernel` — minimal cross-cutting primitives only;
- `Fleetory.ModuleAbstractions` — compile-time module registration contract;
- `Fleetory.Server` — the single composition root.

No additional bounded context is introduced in PHASE 2.

## 2. Permitted dependency directions

The permitted project-reference policy is:

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

The current allowlist contains no cross-context `*.Contracts -> *.Contracts` dependency.

## 3. Forbidden dependency directions

The following are forbidden in PHASE 2:

- implementation assembly of one bounded context -> implementation assembly of another bounded context;
- `*.Contracts` -> any bounded-context implementation assembly;
- one bounded-context `*.Contracts` -> another bounded-context `*.Contracts`;
- `Fleetory.SharedKernel` -> any Fleetory project;
- `Fleetory.ModuleAbstractions` -> a bounded-context implementation or contracts project;
- any bounded-context/common project -> `Fleetory.Server`.

Future cross-context contract dependencies may be introduced only after an explicit PHASE 3 ownership/contract decision. There are no hidden exceptions or pre-created allowlist entries in PHASE 2.

## 4. Server composition-root rule

`Fleetory.Server` is the single composition root.

It may:

- create the ASP.NET Core host;
- provide the configuration root;
- register infrastructure that belongs to the host itself;
- instantiate the approved compile-time module roots;
- invoke each module's registration hooks;
- expose host-level health endpoints.

It must not become a storage location for bounded-context business logic, module-specific services, module-specific options binding, repositories, or module-specific HTTP endpoints.

Module loading remains explicit and compile-time. PHASE 2 does not use dynamic DLL discovery, reflection-based module loading, a plugin loader, service mesh, broker, or network RPC between modules.

## 5. Contracts rule

A `Fleetory.<Context>.Contracts` project is the public boundary for that bounded context.

The permanent boundary rule is:

- each Contracts project references `Fleetory.SharedKernel`;
- it must not reference another bounded context's implementation;
- cross-context Contracts references require an explicit documented allowlist entry and Architecture Test coverage;
- PHASE 3 currently keeps that allowlist empty.

PHASE 3 introduces only the minimal semantic IDs and public summary contracts documented in `InterModuleContractsAndEvents.md`. No Context Bridge transport/read store or speculative event payload classes are introduced.

## 6. SharedKernel rule

`Fleetory.SharedKernel` must remain small and dependency-free.

It may contain only genuinely cross-cutting primitives such as correlation/time/value/result/event/provenance primitives when actually required.

It must not contain domain entities. In particular the architecture tests reject declarations named:

- `Device`
- `Asset`
- `Ticket`
- `CI`
- `Alert`
- `Person`
- `Service`

If code belongs to a bounded context, it stays in that bounded context rather than being moved to SharedKernel for convenience.

## 7. Module endpoint ownership

`IFleetoryModule` provides `MapEndpoints(IEndpointRouteBuilder)`.

The rule is:

- a future module-specific endpoint is registered by the owning module through `MapEndpoints`;
- `Fleetory.Server` calls the module registration hook and does not own module-specific endpoint mappings;
- `/health/live` and `/health/ready` remain host-level infrastructure endpoints in `Fleetory.Server`.

No business endpoints are added in PHASE 2.

## 8. Module configuration ownership

`IFleetoryModule` provides `RegisterServices(IServiceCollection, IConfiguration)`.

The rule is:

- `Fleetory.Server` supplies the configuration root;
- each module registers its own services and, in later phases, its own module-specific options inside its own boundary;
- module-specific configuration logic must not accumulate in `Fleetory.Server`.

PHASE 2 does not implement real module settings, a configuration service, credentials, secrets, or production connection strings.

## 9. OS-neutral Server rule

The shared Server/runtime code must remain OS-neutral so Fleetory Server can run on Windows Server and Linux.

The guard covers:

- `Fleetory.Server`;
- all seven bounded-context implementation projects;
- their `*.Contracts` projects;
- `Fleetory.ModuleAbstractions`;
- `Fleetory.SharedKernel`.

Direct use of Windows-only APIs in those projects is forbidden, including at minimum:

- `Microsoft.Win32`;
- `System.Management`;
- `System.ServiceProcess`;
- `WindowsIdentity` / Windows principal APIs;
- `OperatingSystem.IsWindows()` or an equivalent Windows-specific branch in common runtime code;
- Windows-only target frameworks/runtime identifiers/packages.

This rule does not prohibit future explicitly platform-specific projects. It protects the common Server business/runtime assemblies from acquiring platform coupling.

## 10. Module isolation rule

Do not create cross-context catch-all projects such as shared `Services`, `Models`, `Repositories`, or `Helpers` assemblies to bypass bounded-context ownership.

A type or service that belongs to one bounded context remains there. If an actual cross-module interaction is required, ownership and the public contract/read-model/event direction must be explicit and documented before a project-reference exception is added.

## 11. Intentionally deferred work

PHASE 2 intentionally does not define or implement:

### PHASE 3 — Data Ownership & Contracts

- final Device/Asset/Ticket/CI/Alert/Person contracts;
- `organizational_groups` ownership;
- Context Bridge DTOs;
- event payloads;
- inter-module summary/read models;
- approved cross-context contract dependencies.

### PHASE 4 — Platform Foundation

- Identity;
- Authentication;
- RBAC;
- Audit;
- Licensing;
- Search;
- Notifications;
- configuration service.

### PHASE 5 — Cross-platform Server Package

- native Windows Service/systemd production packaging and related deployment work.

### PHASE 6 — PostgreSQL v2

- PostgreSQL runtime wiring;
- schemas;
- migrations;
- repositories/DbContext;
- connection strings;
- v1 data migration.

### Later Agent phases

- Agent Core;
- Windows/Linux/macOS Agent;
- Agent Protocol;
- enrollment/PKI/mTLS;
- Command Plane.

PHASE 2 also does not add Redis, Kafka, RabbitMQ, OpenSearch, Elasticsearch, Kubernetes, distributed event buses, or microservice infrastructure.
