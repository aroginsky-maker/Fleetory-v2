# Fleetory v2 — Inter-Module Contracts and Events

**Status:** PHASE 3 normative architecture document  
**Purpose:** define the minimal public contract surface and event catalogue without introducing persistence or transport infrastructure

## 1. Contract rules

Each bounded context publishes only its own public contract surface. The old v1 pattern of one broad `ApiContracts.cs` bag is not used.

Public contracts must be:

- immutable where practical;
- serialization-friendly where required;
- OS-neutral;
- persistence-neutral;
- transport-neutral unless a future contract is explicitly transport-specific;
- versionable;
- free of EF/SQL/ASP.NET types.

Summary contracts are stable inter-module context, not domain entities and not UI ViewModels.

## 2. PHASE 3 public contract surface

| Owning context | Semantic identifiers | Public summaries introduced now |
|---|---|---|
| Platform | `PersonId`, `ScopeId` | `PersonSummary`, `ScopeSummary` |
| Core | `DeviceId` | `DeviceSummary` |
| Assets | `AssetId` | `AssetSummary` |
| ITSM | `TicketId` | `TicketSummary` |
| CMDB | `ConfigurationItemId` | `ConfigurationItemSummary` |
| Monitoring | `ObservationId`, Monitoring domain `EventId`, `AlertId` | `AlertSummary` |
| Integrations | `ConnectorId` | none required yet |

No generic `EntityId` is introduced. Domain-semantic identifiers remain in the owning `*.Contracts` assembly.

The summary types intentionally contain only a stable minimum:

- semantic ID;
- human-readable display/name/title field.

Additional domain state is added only when an approved consumer requires a stable public field.

## 3. Actual dependency allowlist

### `*.Contracts -> foreign *.Contracts`

**Empty in PHASE 3.**

Every `*.Contracts` project references only `Fleetory.SharedKernel`. No cross-context Contracts project reference was added.

### implementation project references

PHASE 2 policy remains unchanged:

- `Fleetory.Platform` -> `Fleetory.Platform.Contracts`, `Fleetory.ModuleAbstractions`;
- each other bounded-context implementation -> its own `*.Contracts`, `Fleetory.Platform.Contracts`, `Fleetory.ModuleAbstractions`;
- no implementation -> foreign implementation dependency;
- `Fleetory.Server` is the only composition root and explicitly references module implementations.

The existing non-Platform implementation references to `Fleetory.Platform.Contracts` are the already-approved PHASE 2 dependency direction; PHASE 3 does not add any new implementation-level cross-context dependency.

## 4. Common technical event envelope

`Fleetory.SharedKernel.EventEnvelope` is a transport-neutral technical primitive for future application/integration events. It is not tied to Kafka, RabbitMQ, Azure Service Bus, Redis or a database transport.

Logical shape:

```text
EventId        Guid              unique published-envelope identity
EventType      string            stable event type name
SchemaVersion  int               event payload/schema version
OccurredAt     DateTimeOffset    producer occurrence timestamp
CorrelationId  CorrelationId     cross-operation correlation identifier
CausationId    Guid?             optional causing envelope identifier
Producer       string            producing bounded context/component
Subject        EventSubject?     optional subject type + opaque subject ID
```

Important distinction:

- `Fleetory.SharedKernel.EventEnvelope.EventId` identifies the published event-envelope instance.
- `Fleetory.Monitoring.Contracts.EventId` identifies the Monitoring domain `Event` entity.

They are not interchangeable identities.

`EventSubject` deliberately stores an opaque subject type/id pair so publishing an event does not force a Contracts project reference to the subject's owning bounded context.

## 5. Provenance value semantics

`Fleetory.SharedKernel.DataProvenance` carries technical source metadata:

```text
SourceSystem
SourceRecordId?
ObservedAt
ReceivedAt?
Authority
```

It is a value contract, not a globally-owned business entity. Owning contexts decide where it is required and how authority is evaluated.

## 6. Normative event catalogue

This catalogue defines names and ownership. PHASE 3 does **not** create a C# class for every event because no executable producer/consumer exists yet.

| Producer | Event | Architectural meaning |
|---|---|---|
| Platform | `PersonChanged` | Public Person/Directory projection materially changed. |
| Platform | `ScopeChanged` | Authorization Scope hierarchy/metadata changed. |
| Core | `DeviceRegistered` | A Device identity became registered in Core. |
| Core | `DeviceStateChanged` | Significant current Device state changed. |
| Core | `DeviceInventoryChanged` | Authoritative/current Device inventory materially changed. |
| Core | `DeviceProviderStateChanged` | Provider state/capabilities/values materially changed. |
| Assets | `AssetCreated` | An Asset lifecycle record was created. |
| Assets | `AssetAssigned` | Asset assignment/custody changed to assigned state. |
| Assets | `AssetReturned` | Asset return operation completed. |
| Assets | `AssetRepairStateChanged` | Asset repair lifecycle state changed. |
| Assets | `AssetRetired` | Asset lifecycle reached retirement/disposal state. |
| ITSM | `TicketCreated` | An ITSM Ticket/Request was created. |
| ITSM | `IncidentCreated` | ITSM created an Incident process. |
| ITSM | `IncidentStateChanged` | ITSM Incident lifecycle state changed. |
| ITSM | `ChangeStateChanged` | ITSM Change lifecycle state changed. |
| CMDB | `ConfigurationItemChanged` | Public CI state materially changed. |
| CMDB | `ConfigurationRelationChanged` | CI relationship/topology materially changed. |
| Monitoring | `ObservationAccepted` | Monitoring accepted a normalized/raw observation for processing. |
| Monitoring | `EventRaised` | Monitoring created a significant normalized Event. |
| Monitoring | `AlertRaised` | Monitoring created an attention-requiring Alert. |
| Monitoring | `AlertResolved` | Monitoring Alert transitioned to resolved. |
| Monitoring | `CorrelationChanged` | Correlation/root-cause grouping materially changed. |
| Integrations | `ConnectorSyncCompleted` | A connector synchronization run completed. |
| Integrations | `ExternalMappingChanged` | External/Fleetory mapping metadata materially changed. |

Event payloads are intentionally not specified until an actual producer/consumer pair requires them. This avoids speculative coupling and empty classes.

## 7. Monitoring -> ITSM interaction

Normative chain:

```text
Observation -> Event -> Alert -> Incident
```

Monitoring owns the first three concepts; ITSM owns Incident. A future Monitoring-to-ITSM integration may use a request/application contract or versioned event carrying an `AlertId`/summary/reference, but PHASE 3 does not create that dependency because no executable workflow exists yet.

Mass Incident is still an ITSM-owned Incident created because of correlated Monitoring context.

## 8. Device / Asset / ConfigurationItem references

`DeviceId`, `AssetId` and `ConfigurationItemId` are independent identities. PHASE 3 does not add direct project references among `Core.Contracts`, `Assets.Contracts` and `CMDB.Contracts`.

Future relationships must be explicit and minimal. Preferred order of coupling:

1. opaque semantic ID/reference in an approved application contract or event;
2. public summary/read model when context is needed;
3. direct Contracts project reference only when unavoidable, one-way, documented and Architecture-Test allowlisted.

Direct database FKs are not an inter-module integration mechanism.

## 9. Contract versioning policy

1. Prefer additive compatible evolution.
2. A breaking semantic change requires a new contract/schema version.
3. Never silently repurpose an existing field/event meaning.
4. Deprecated fields/events require a transition period and migration/compatibility note.
5. Producers and consumers must not assume lockstep deployment unless an explicit compatibility decision says otherwise.
6. Compatibility ranges/version handling must be explicit where multiple versions can coexist.
7. Event `SchemaVersion` versions the event schema/payload meaning, not the Fleetory product version.

## 10. Architecture enforcement

Architecture Tests enforce:

- bounded-context implementation isolation;
- Contracts -> implementation prohibition;
- empty undocumented cross-context Contracts allowlist;
- acyclic Fleetory production project graph;
- SharedKernel isolation and domain-model prohibition;
- ownership placement of PHASE 3 semantic IDs/summaries;
- persistence/ASP.NET neutrality of public Contracts;
- Server composition-root and endpoint-ownership rules;
- OS-neutral shared Server/runtime code.

No existing PHASE 2 rule is weakened.

## 11. Deferred implementation

Not implemented in PHASE 3:

- event bus/broker/outbox/inbox;
- event persistence;
- Context Bridge store/transport;
- PostgreSQL/EF/repositories/migrations;
- Platform identity/RBAC/Audit/Licensing implementation;
- Agent protocol/PKI/mTLS/commands;
- connectors;
- business workflows;
- UI.
