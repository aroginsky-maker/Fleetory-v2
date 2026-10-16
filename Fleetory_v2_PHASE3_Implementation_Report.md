# Fleetory v2 — PHASE 3 Implementation Report

**Phase:** PHASE 3 — Data Ownership & Contracts  
**Status:** **COMPLETE**  
**Source baseline:** `Fleetory-v2-sonar-quality-hardened.zip`

## 1. Entry status

PHASE 3 is closed. The user executed the strict and Sonar verification on the real Windows/Sonar environment after the nine-item cleanup. The confirmed closure baseline is:

| Metric | Result |
|---|---:|
| PHASE 0 | COMPLETE |
| PHASE 1 | COMPLETE |
| PHASE 2 | COMPLETE |
| PHASE 3 | COMPLETE |
| Strict build | PASS |
| Tests | 23 passed / 0 failed / 0 skipped |
| Architecture Tests | PASS |
| Sonar analysis | PASS |
| Sonar Quality Gate | PASSED |
| Sonar coverage | 93.2% |
| Duplications | 0.0% |
| Security Issues | 0 |
| Security Rating | A |
| Open Issues overall | 0 |

The earlier local PHASE 3 coverage measurement before the final Sonar cleanup was 93.94%; the authoritative external Sonar closure value is 93.2%. No suppression, source exclusion or Quality Gate weakening was used to obtain closure.

## 2. PHASE 3 objective implemented

PHASE 3 now formally defines:

- data ownership by bounded context;
- authoritative Fleetory representations;
- external source authority and provenance;
- Device / Asset / ConfigurationItem identity boundaries;
- legacy `organizational_groups` replacement semantics;
- Person / Directory ownership;
- Monitoring / ITSM boundary;
- public semantic identifiers;
- minimal public summary contracts;
- inter-module reference rules;
- an architectural event catalogue;
- a transport-neutral event envelope primitive;
- contract/versioning policy;
- explicit dependency allowlist rules.

No persistence, workflow, Platform security implementation, Agent, UI or broker was introduced.

## 3. Architecture documents created

### `docs/architecture/DataOwnership.md`

Contains the normative ownership matrix with:

- Concept;
- Owning bounded context;
- Authoritative representation;
- External/source authority;
- Other-module projections;
- Allowed references;
- Forbidden coupling;
- Notes.

It covers Platform, Core, Assets, ITSM, CMDB, Monitoring and Integrations concepts required by the PHASE 3 specification.

### `docs/architecture/InterModuleContractsAndEvents.md`

Defines:

- current public contract surface;
- actual dependency allowlist;
- event envelope semantics;
- provenance semantics;
- normative event catalogue;
- Device/Asset/CI reference rules;
- Monitoring/ITSM interaction rule;
- contract versioning policy;
- deferred implementation.

`docs/architecture/ModularMonolith.md` was updated only to acknowledge the PHASE 3 contract/ownership documents while preserving the PHASE 2 dependency policy.

## 4. Final ownership model

### Platform

Owns:

- Person / Directory projection;
- authorization/access Scope hierarchy;
- user preferences;
- Module Registry metadata.

AD/LDAP/Entra/1C/local Fleetory may be authoritative for individual Person attributes, but Platform owns the Fleetory unified Person projection and Fleetory scope/RBAC mapping semantics.

### Core

Owns:

- Device;
- Device technical identity;
- DeviceState;
- Agent state/capabilities representation;
- hardware/software/network inventory;
- technical telemetry current state;
- SMART/storage-health current state;
- Provider Catalog and provider values/state/capabilities;
- Field Catalog;
- technical Device lifecycle/status.

Fleetory Agent is the preferred live technical source when available. SCCM/Everest/AIDA-like sources are supplementary inventory/reconciliation sources.

### Assets

Owns Asset lifecycle including:

- stock/warehouse/reserve;
- custody/ownership;
- assignment;
- repair;
- return;
- retirement/disposal;
- warranty/vendor references;
- Fleetory projection of applicable 1C/accounting attributes.

Fleetory does not become a statutory accounting system.

### ITSM

Owns:

- Ticket / Request;
- Incident;
- Service Catalog;
- SLA/OLA;
- Work/Task;
- Problem;
- Change;
- Release;
- Knowledge;
- operational service finance context;
- contractor/service relationships.

### CMDB

Owns:

- ConfigurationItem;
- CI relationships;
- service topology;
- impact relations.

### Monitoring

Owns:

- Observation;
- Monitoring Event;
- Alert;
- correlation/root-cause state;
- maintenance/suppression state.

### Integrations

Owns:

- Connector metadata;
- synchronization/run state;
- external mapping metadata;
- integration delivery status.

Owning domain data remains owned by its destination bounded context.

## 5. Device / Asset / ConfigurationItem

PHASE 3 fixes the normative identity rule:

```text
Device != Asset != ConfigurationItem
```

One physical computer may have independently:

- `Fleetory.Core.Contracts.DeviceId`;
- `Fleetory.Assets.Contracts.AssetId`;
- `Fleetory.CMDB.Contracts.ConfigurationItemId`.

There is no common master object or inheritance tree. Cross-module database FKs are not used as the integration mechanism. Future relations are explicit public references/contracts/read models/events.

## 6. Legacy `organizational_groups`

The v1 concept is not promoted into one universal v2 entity.

Semantic migration rule:

- authorization/access hierarchy -> Platform Scope;
- operational Device navigation/grouping -> optional future Core Device Group/Collection if an actual Core use case requires it;
- asset hierarchy -> Assets-owned semantics;
- CI/service topology -> CMDB-owned semantics.

No migration implementation and no speculative DeviceGroup contract was added.

## 7. Person / Directory

Platform owns the unified Fleetory Person/Directory projection.

External sources can include AD/LDAP, Entra/OIDC, 1C, local Fleetory and other integrations. Source authority is per attribute via provenance.

External directory membership is source data. It is not the Fleetory RBAC model. Future external-group -> Fleetory role/scope mapping belongs to Platform.

No LDAP/AD/Entra connector was implemented.

## 8. Monitoring / ITSM boundary

Normative chain:

```text
Observation -> Event -> Alert -> Incident
```

- Monitoring owns Observation/Event/Alert/correlation.
- ITSM owns Incident.
- Alert != Incident.
- Mass Incident remains ITSM-owned.
- v1 `performance_incidents` must not be automatically migrated as ITSM Incident.

No workflow implementation was added.

## 9. Public contracts created

### Platform.Contracts

- `PersonId`
- `ScopeId`
- `PersonSummary`
- `ScopeSummary`

### Core.Contracts

- `DeviceId`
- `DeviceSummary`

### Assets.Contracts

- `AssetId`
- `AssetSummary`

### ITSM.Contracts

- `TicketId`
- `TicketSummary`

### CMDB.Contracts

- `ConfigurationItemId`
- `ConfigurationItemSummary`

### Monitoring.Contracts

- `ObservationId`
- `EventId` — Monitoring domain Event identity
- `AlertId`
- `AlertSummary`

### Integrations.Contracts

- `ConnectorId`

No common `GenericEntityId` was introduced.

Summary contracts deliberately contain only the semantic ID plus a stable human-readable label/name/title. They are not domain entities and not UI ViewModels.

## 10. SharedKernel additions

Only technical cross-cutting value primitives were added:

- `DataProvenance`;
- `EventEnvelope`;
- `EventSubject`.

Existing `CorrelationId` and `IClock/SystemClock` remain.

`EventEnvelope.EventId` is a technical published-envelope identity (`Guid`). It is intentionally distinct from `Fleetory.Monitoring.Contracts.EventId`, which identifies the Monitoring domain Event.

No Device, Asset, Ticket, ConfigurationItem, Alert, Person or other domain entity was added to SharedKernel.

## 11. Provenance rules

Common technical provenance fields:

- SourceSystem;
- SourceRecordId when applicable;
- ObservedAt;
- ReceivedAt/ImportedAt when applicable;
- Authority.

`DataProvenance` is a value contract, not a global business entity or repository.

Source authority fixed by PHASE 3:

- 1C -> applicable accounting/HR facts;
- AD/LDAP/Entra -> identity/membership source facts;
- Fleetory Agent -> preferred live technical source when available;
- SCCM/Everest/AIDA -> supplementary inventory/reconciliation;
- SCOM/Zabbix/Prometheus/SNMP/Syslog -> Monitoring inputs, not ITSM Incident owners.

## 12. Event catalogue

Normatively documented without creating speculative C# event classes:

### Platform

- `PersonChanged`
- `ScopeChanged`

### Core

- `DeviceRegistered`
- `DeviceStateChanged`
- `DeviceInventoryChanged`
- `DeviceProviderStateChanged`

### Assets

- `AssetCreated`
- `AssetAssigned`
- `AssetReturned`
- `AssetRepairStateChanged`
- `AssetRetired`

### ITSM

- `TicketCreated`
- `IncidentCreated`
- `IncidentStateChanged`
- `ChangeStateChanged`

### CMDB

- `ConfigurationItemChanged`
- `ConfigurationRelationChanged`

### Monitoring

- `ObservationAccepted`
- `EventRaised`
- `AlertRaised`
- `AlertResolved`
- `CorrelationChanged`

### Integrations

- `ConnectorSyncCompleted`
- `ExternalMappingChanged`

Event payload classes are deferred until an executable producer/consumer needs them.

## 13. Contract versioning policy

- additive compatible evolution is preferred;
- breaking semantic change requires a new contract/schema version;
- no silent semantic repurposing;
- deprecated fields/events require a transition period;
- producer/consumer lockstep is not assumed;
- compatibility requirements must be explicit;
- event `SchemaVersion` describes event schema semantics, not Fleetory product version.

## 14. Actual dependency allowlist

### Contracts -> foreign Contracts

**Empty.**

Every bounded-context Contracts project still references only `Fleetory.SharedKernel`.

### Implementation-level dependencies

The PHASE 2 policy is unchanged:

- Platform implementation -> own Contracts + ModuleAbstractions;
- each other module implementation -> own Contracts + Platform.Contracts + ModuleAbstractions;
- no implementation -> foreign implementation references;
- Server remains the only composition root.

No new implementation cross-context dependency was added in PHASE 3.

## 15. Architecture Tests changes

Existing PHASE 2/Sonar architecture tests were preserved and not weakened.

Added/strengthened checks for:

1. cross-context Contracts references must match the explicit PHASE 3 allowlist;
2. the Fleetory production project-reference graph must remain acyclic;
3. PHASE 3 semantic IDs/summaries must live only in their owning Contracts project;
4. public Contracts projects remain persistence-neutral and ASP.NET-neutral;
5. SharedKernel explicitly rejects domain IDs/summaries and `GenericEntityId` in addition to domain entity names.

Added contract-foundation behavior tests exercise:

- semantic identifier type separation/value preservation;
- summary contract construction;
- transport-neutral event envelope metadata;
- provenance value semantics.

No Architecture Test was deleted or converted to a warning.

## 16. Production behavior changes

None.

No business endpoint, domain workflow, database access, authentication, RBAC, Agent, connector or UI behavior was added.

The existing Server composition root and health/correlation behavior are unchanged.

## 17. Explicitly deferred work

Not implemented in PHASE 3:

- PostgreSQL packages/runtime;
- EF Core / DbContext;
- repositories;
- database schemas/migrations/connection strings;
- v1 data migration;
- Authentication;
- RBAC engine;
- Audit persistence;
- Licensing;
- Search/Notifications/Directory connector;
- Agent Core or platform Agents;
- Agent Protocol/PKI/mTLS/enrollment/Command Plane;
- UI;
- broker/outbox transport;
- real connectors;
- domain workflows.

## 18. PHASE 3 Sonar cleanup implemented

The cleanup changes are deliberately limited to the nine analyzer findings supplied by the user plus the corrected repository-local SonarCloud script. No module boundary, ownership decision, public contract semantics, persistence work or PHASE 4 functionality was changed.

| # | Rule | Location | Fix |
|---:|---|---|---|
| 1 | `roslyn:CA1873` | `src/Fleetory.Server/FleetoryApplication.cs`, module registration log | Added `IsEnabled(LogLevel.Information)` guard while preserving the exact message template and `{ModuleName}` structured property. |
| 2 | `roslyn:CA1859` | `tests/Fleetory.Architecture.Tests/ArchitectureBoundaryTests.cs`, `AllowedCrossContextContractReferences` | Changed private static readonly field declaration to concrete `Dictionary<string, IReadOnlyCollection<string>>`; allowlist contents unchanged. |
| 3 | `roslyn:CA1861` | `ArchitectureBoundaryTests.cs`, expected SharedKernel reference array | Replaced repeated constant array construction with class-local `private static readonly string[] SharedKernelOnly`. |
| 4 | `roslyn:SYSLIB1045` | `ArchitectureBoundaryTests.cs`, module endpoint regex | Replaced runtime compiled `Regex` with `GeneratedRegexAttribute`, preserving the exact pattern and `CultureInvariant`. |
| 5 | `roslyn:CA1859` | `ArchitectureBoundaryTests.cs`, `GetProjectReferences` | Return type changed from `IReadOnlyList<string>` to `string[]`; behavior unchanged and call sites remain type-safe. |
| 6 | `roslyn:CA1859` | `ArchitectureBoundaryTests.cs`, directory `GetDeclaredTypeNames` | Return type changed from `IReadOnlySet<string>` to `HashSet<string>` with the same ordinal comparer and contents. |
| 7 | `roslyn:CA1859` | `ArchitectureBoundaryTests.cs`, file `GetDeclaredTypeNames` | Return type changed from `IReadOnlyCollection<string>` to `string[]`; matching behavior unchanged. |
| 8 | `roslyn:SYSLIB1045` | `ArchitectureBoundaryTests.cs`, type-declaration regex | Replaced runtime compiled `Regex` with `GeneratedRegexAttribute`, preserving the exact pattern, named groups and `CultureInvariant`. |
| 9 | `roslyn:CA1859` | `tests/Fleetory.Server.Tests/FoundationPrimitiveTests.cs` | Test-local variable changed from `IClock` to inferred concrete `SystemClock`; production `IClock` remains unchanged. |

The supplied corrected `eng/verify-sonar.ps1` is included unchanged. It retains UTF-8 console handling, `DOTNET_CLI_UI_LANGUAGE=en-US`, `SONAR_ORGANIZATION` support and `/o:` in SonarScanner `begin`. No token or secret is embedded in the repository.

## 19. Final PHASE 3 verification

The cleanup tree was subsequently verified by the user on the real Windows/Sonar environment. Final observed results:

```text
STRICT BUILD        PASS
TESTS               PASS (23/23)
ARCHITECTURE TESTS  PASS
COVERAGE            93.2% (Sonar)
DUPLICATION         0.0%
SECURITY ISSUES     0
OPEN ISSUES         0
SONAR ANALYSIS      PASS
SONAR QUALITY GATE  PASSED
SECURITY RATING     A
```

The nine Roslyn/Sonar findings documented in section 18 were eliminated without `NOSONAR`, `SuppressMessage`, warning disables, source exclusions, analyzer weakening or Quality Gate changes.

## 20. Architecture decision status

No `ARCHITECTURE DECISION REQUIRED` blocker remains. PHASE 3 did not alter the approved bounded-context ownership model.

## 21. Exit status

**PHASE 3 = COMPLETE**

The next normative stage is **PHASE 4 — Platform Foundation**.
