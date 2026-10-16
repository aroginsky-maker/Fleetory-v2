# Fleetory v2 — Data Ownership

**Status:** PHASE 3 normative architecture document  
**Scope:** data ownership, authority, projections, references and bounded-context boundaries  
**Persistence:** intentionally not defined in PHASE 3

## 1. Governing rules

1. Every business/operational concept has one owning bounded context.
2. Ownership means that the owning context defines the authoritative Fleetory representation and its semantic rules.
3. External systems may be authoritative for individual source attributes without becoming owners of the Fleetory bounded context.
4. Consumer modules use public IDs, summaries, contracts, events and future read-model/Context Bridge mechanisms. They do not read another module's tables or repositories.
5. A projection is non-authoritative outside its owning context and must retain source/provenance where required.
6. No universal `Entity`, `Item`, `Object`, master-record hierarchy or cross-module persistence model is introduced.
7. Database schemas, FKs, repositories and migrations are deferred to PHASE 6.

## 2. Data ownership matrix

| Concept | Owning bounded context | Authoritative representation | External/source authority if applicable | Other module projections | Allowed references | Forbidden coupling | Notes |
|---|---|---|---|---|---|---|---|
| Person / Directory projection | Platform | Fleetory unified Person/Directory projection identified by `PersonId` | AD/LDAP, Entra/OIDC, 1C, local Fleetory and other integrations may be authoritative per attribute | `PersonSummary`; module-local read projections | `PersonId`, public Platform contracts, provenance | AD/LDAP object as Fleetory RBAC model; direct directory calls in other modules | Attribute provenance is required where source authority matters. |
| Authorization Scope | Platform | Fleetory access-scope hierarchy identified by `ScopeId` | External group membership can be an input to mapping | `ScopeSummary` | `ScopeId`, public Platform contracts | Reusing Core navigation groups, Asset hierarchy or CMDB topology as access scope | Mapping external groups to Fleetory roles/scopes remains Platform responsibility. |
| User Preferences | Platform | Per-user presentation/preferences state | User input | Read-only preference projection where needed | User identity + preference contract | Treating preferences as domain semantics | Module semantic settings remain with the owning module. |
| Module Registry metadata | Platform | Registered Fleetory module metadata/state | Deployment/runtime registration | Read-only registry view | Public Platform contract | Dynamic plugin ownership or DLL-discovery model | Compile-time modular monolith remains normative. |
| Device | Core | Technical representation of a managed device identified by `DeviceId` | Fleetory Agent is preferred live source when available | `DeviceSummary`; future module-local read projections | `DeviceId`, Core contracts/events | Asset/CI as master record; cross-module SQL/FK | Device answers what the object technically is now. |
| Device technical identity | Core | Technical identity and stable device identity semantics | Agent/enrollment sources later | Device identity projection | `DeviceId` and future Core identity contract | Platform Person identity; Asset identity; generic global entity ID | Security/enrollment implementation is deferred. |
| DeviceState | Core | Current technical state of Device | Agent preferred; external inventory may supplement | `DeviceSummary` or future state summary | `DeviceId`, Core events | Monitoring Alert or Asset lifecycle status as the Device state | State evolution remains Core-owned. |
| Agent state / capabilities | Core | Current Agent connectivity/version/capability representation | Fleetory Agent | Device context projection | `DeviceId`, future Agent capability contract | Agent implementation details leaking into other bounded contexts | Agent itself is not implemented in PHASE 3. |
| Hardware inventory | Core | Current normalized hardware inventory for Device | Agent preferred; SCCM/Everest/AIDA-like sources supplementary | Device context/read model | `DeviceId`, Core public contracts/events, provenance | External inventory system becoming Core owner | Provenance distinguishes observed/imported sources. |
| Software inventory | Core | Current normalized software inventory for Device | Agent preferred; SCCM/Everest/AIDA-like sources supplementary | Device context/read model | `DeviceId`, Core contracts/events, provenance | Assets/ITSM owning technical software inventory | Product normalization details are deferred to later Core work. |
| Network inventory | Core | Current normalized network inventory for Device | Agent preferred; supplementary inventory sources allowed | Device context/read model | `DeviceId`, Core contracts/events, provenance | CMDB topology replacing raw technical inventory | CMDB may project relationships later; Core keeps technical network facts. |
| Technical telemetry current state | Core | Current operational telemetry state of Device | Agent preferred | Monitoring may consume observations/events later | `DeviceId`, public events/read models | Treating Monitoring Alert as Core telemetry row | Historical monitoring/event ownership is separate. |
| SMART / storage-health current state | Core | Current technical storage-health state | Agent/platform collector preferred | Monitoring may consume significant changes | `DeviceId`, Core events/provenance | Monitoring owning raw current SMART inventory | Monitoring owns attention/correlation semantics, not the technical current snapshot. |
| Provider Catalog | Core | Provider definitions/capability metadata | Built-in/configured provider definitions | Read-only provider summaries when needed | Core Provider contracts | Provider-specific tables as cross-module integration surface | AnyDesk/Cisco remain default provider concepts; implementation is later. |
| Provider values/state/capabilities | Core | Current detected/collected provider state for Device | Agent/provider collectors | Device summary/context where explicitly exposed | `DeviceId`, provider public contracts/events | Duplicated provider-specific canonical storage | One canonical Core provider model is the target. |
| Field Catalog | Core | Core field metadata and collection/search/history semantics | Fleetory configuration | Read-only field metadata where required | Core contracts | UI preference model becoming canonical field ownership | User display preferences remain Platform-owned. |
| Technical Device lifecycle/status | Core | Technical managed-device status only | Fleetory Core | Device summary/context | `DeviceId`, Core contracts/events | Asset lifecycle, disposal or CMDB operational status being collapsed into Device | Asset and CI lifecycle meanings remain independent. |
| Asset | Assets | Asset lifecycle record identified by `AssetId` | 1C/accounting may supply selected business/accounting fields | `AssetSummary`; future module-local projections | `AssetId`, Assets contracts/events | Device or CI as master Asset record | Asset answers what the organization does with the property. |
| Stock / warehouse / reserve | Assets | Asset inventory/warehouse state | 1C may be source for selected accounting facts | Asset context projection | `AssetId`, Assets contracts/events | Core Device groups or CMDB topology as warehouse hierarchy | Operational asset semantics remain Assets-owned. |
| Custody / ownership | Assets | Asset custody/ownership lifecycle state | HR/1C may supply reference data | Asset context projection | `AssetId`, `PersonId` through approved public reference mechanisms | Direct Platform persistence access | Exact cross-context contract is deferred until a consumer requires it. |
| Assignment | Assets | Asset assignment lifecycle | External HR/1C may provide source facts | Asset context projection | `AssetId`; future Person reference contract | Cross-module EF navigation/repository | No DB FK decision in PHASE 3. |
| Repair | Assets | Asset repair lifecycle | Vendor/service systems may provide external status | Asset context projection | `AssetId`, Assets events | ITSM Work/Ticket becoming Asset lifecycle owner | ITSM may reference Asset context; ownership stays Assets. |
| Return | Assets | Asset return lifecycle | External sources may inform | Asset context projection | `AssetId`, Assets events | Device technical state as return state | — |
| Retirement / disposal | Assets | Asset retirement/disposal lifecycle | 1C/accounting may be source for selected records | Asset context projection | `AssetId`, Assets events | Core Device technical lifecycle replacing legal/asset retirement | Core Device may remain technically known after Asset retirement. |
| Warranty | Assets | Asset warranty/business property | Vendor/1C may supply attributes | Asset context projection | `AssetId`, provenance | Core hardware inventory as business warranty owner | Technical serial/model may be sourced from Core later through contracts. |
| Vendor references | Assets | Asset vendor/business references | Vendor/1C | Asset context projection | `AssetId`, provenance | Integration connector metadata becoming Asset domain model | — |
| 1C/accounting projection | Assets | Fleetory read-mostly projection of asset/accounting facts | 1C is external authority for accounting attributes | Asset context projection | External source IDs/provenance | Fleetory becoming statutory accounting system | Targeted refresh may be supported later; not in hot-path UI. |
| Ticket / Request | ITSM | ITSM ticket/request process identified by `TicketId` | External service desks may be integration sources | `TicketSummary`; future Context Bridge projections | `TicketId`, ITSM contracts/events | Core/Assets/CMDB tables as ticket persistence | Ticket is an ITSM process object. |
| Incident | ITSM | Managed Incident process | Monitoring may initiate via Alert/Event context; external ITSM may integrate | `TicketSummary` or future IncidentSummary | `TicketId`, ITSM contracts/events | Monitoring Alert being the Incident entity | Alert != Incident. Mass Incident is still ITSM-owned. |
| Service Catalog | ITSM | Service/request catalog semantics | External catalog may synchronize | ITSM summaries | ITSM IDs/contracts | CMDB service topology becoming ITSM catalog persistence | Service catalog and CMDB service topology may relate but are not the same ownership. |
| SLA / OLA | ITSM | ITSM service-level policy/state | Contract systems may provide reference data | Ticket context projection | ITSM contracts | Platform configuration or Monitoring thresholds as SLA owner | — |
| Work Order / Task | ITSM | Execution/work item semantics | External work systems may integrate | Ticket/context projection | ITSM contracts/events | Generic shared Work entity in SharedKernel | Work remains ITSM-owned. |
| Problem | ITSM | Problem-management lifecycle | External ITSM may integrate | Ticket/context projection | ITSM contracts/events | Monitoring correlation state as Problem | Correlation may inform Problem creation, not own it. |
| Change | ITSM | Change-management lifecycle | External ITSM may integrate | Context projection | ITSM contracts/events | CMDB relation as Change entity | Change may consume CMDB impact later. |
| Release | ITSM | Release-management lifecycle | External release systems may integrate | Context projection | ITSM contracts/events | Software inventory becoming Release process | — |
| Knowledge | ITSM | Knowledge-management content/metadata | External KB may integrate | Context projection | ITSM contracts/events | SharedKernel/general content store ownership | — |
| Operational service finance/budget context | ITSM | Operational service cost context | 1C/accounting may be external authority for accounting facts | ITSM read projection | ITSM contracts + provenance | Fleetory statutory accounting | Limited to operational service finance. |
| Contractor/service relationship | ITSM | Service-delivery relationship in ITSM context | Vendor/contract systems may supply references | ITSM context projection | ITSM contracts/provenance | Assets vendor master as universal contractor model | Exact vendor master integration is deferred. |
| ConfigurationItem | CMDB | CI representation identified by `ConfigurationItemId` | Integrations may contribute CI facts | `ConfigurationItemSummary`; future context projections | `ConfigurationItemId`, CMDB contracts/events | Device/Asset as universal master CI | CI answers how an object participates in services/dependencies. |
| CI relationships | CMDB | Typed CI relations | Discovery/integration inputs may contribute | Service/impact projections | CI IDs, CMDB events | Core network tables as CMDB relation persistence | Relationship semantics are CMDB-owned. |
| Service topology | CMDB | Service map/topology | Discovery/integration sources may contribute | Impact/context projections | CI IDs, CMDB contracts/events | ITSM Service Catalog as topology owner | ITSM service process/catalog and CMDB topology are related but distinct. |
| Impact relations | CMDB | Impact/dependency model | Derived from CMDB relations | ITSM/Monitoring read projections later | CI IDs, CMDB contracts/read models | Direct reads from Core/Assets persistence | — |
| Observation | Monitoring | Raw accepted monitoring observation identified by `ObservationId` | Agent telemetry, SCOM, Zabbix, Prometheus, SNMP, Syslog, external APIs | Monitoring internal/read projections | Monitoring IDs/contracts/events | ITSM Incident ownership | Raw observation is not an Incident. |
| Event | Monitoring | Significant normalized state change identified by Monitoring `EventId` | Derived from observations/integrations | Monitoring/consumer read projections | Monitoring IDs/contracts/events | Shared technical event-envelope ID being used as domain Event ID | Monitoring `EventId` is a domain identity; envelope `EventId` identifies a published message instance. |
| Alert | Monitoring | Attention-requiring monitoring state identified by `AlertId` | Derived from Monitoring Events/correlation | `AlertSummary`; ITSM context later | `AlertId`, Monitoring contracts/events | ITSM Incident as the Alert row/entity | Alert != Incident. |
| Correlation/root-cause state | Monitoring | Correlation and root-cause analysis state | Monitoring observations/events + CMDB context later | Monitoring summaries | Monitoring contracts/events; future CMDB summaries | CMDB relation ownership or ITSM Incident ownership | CMDB supplies topology; Monitoring owns correlation state. |
| Maintenance windows | Monitoring | Monitoring suppression/maintenance semantics | Admin/integration input later | Monitoring read projection | Monitoring contracts | Platform configuration as domain owner | Implementation deferred. |
| Suppression state | Monitoring | Monitoring alert/event suppression semantics | Monitoring rules/maintenance | Monitoring read projection | Monitoring contracts/events | ITSM workflow state | — |
| Connector metadata | Integrations | Connector identity/configuration metadata identified by `ConnectorId` | Installation/admin configuration | Platform health/module projections later | `ConnectorId`, Integrations contracts/events | External system schema as Fleetory domain ownership | Secrets will use Platform Secret Provider later; no secret implementation now. |
| Synchronization state | Integrations | Connector synchronization state | External system responses | Integration status projection | `ConnectorId`, Integrations events | Owning module tables as sync-control store | Domain data remains owned by its target module. |
| Execution/run state | Integrations | Integration job/run lifecycle | Connector runtime | Integration status projection | `ConnectorId`, Integrations events | Worker/job state becoming target-domain authority | Runtime implementation is deferred. |
| External mapping metadata | Integrations | Mapping between external IDs and Fleetory references | External systems + Fleetory mapping config | Consumer read projection where needed | `ConnectorId`, external reference metadata/events | Replacing owning module identity with external ID | External IDs never become universal Fleetory IDs. |
| Integration delivery status | Integrations | Delivery/retry outcome metadata | Connector transport | Integration status projection | `ConnectorId`, Integrations events | Domain state inferred solely from transport delivery | Broker/outbox/retry implementation is deferred. |

## 3. Device, Asset and ConfigurationItem

`Device != Asset != ConfigurationItem` is a P0 identity boundary.

One physical computer may simultaneously have:

- `Fleetory.Core.Contracts.DeviceId`;
- `Fleetory.Assets.Contracts.AssetId`;
- `Fleetory.CMDB.Contracts.ConfigurationItemId`.

These IDs are independent and none is a universal master identifier. No inheritance hierarchy is introduced between these concepts.

A future relation can be expressed through explicit public references/contracts/read models, but PHASE 3 deliberately does not add `Assets.Contracts -> Core.Contracts` or `CMDB.Contracts -> Core.Contracts` project references. The current `*.Contracts -> foreign *.Contracts` allowlist remains empty. Persistence-level FKs are not designed here.

## 4. Legacy `organizational_groups` replacement semantics

The v1 `organizational_groups` concept is not migrated as one universal v2 entity.

Its semantics must be split during migration planning according to actual use:

- authorization/access hierarchy -> **Platform Scope**;
- operational Device navigation/grouping -> optional future **Core Device Group / Device Collection**, only if Core use cases require it;
- asset hierarchy -> **Assets-owned** structures;
- service/CI topology -> **CMDB-owned** relations/topology.

PHASE 3 defines only this semantic mapping rule. It does not create migration code or a Core DeviceGroup contract because no concrete PHASE 3 consumer requires one.

## 5. Person / Directory and external membership

Platform owns the Fleetory Person/Directory projection. Source systems can be authoritative for individual attributes; authority is recorded through provenance rather than by transferring Fleetory ownership to the external directory.

External AD/LDAP/Entra membership is source information. It is not the Fleetory role/permission model. Future external-group -> Fleetory role/scope mapping belongs to Platform.

## 6. Monitoring / ITSM boundary

Normative lifecycle:

```text
Observation -> Event -> Alert -> Incident
```

Ownership:

- Monitoring owns `Observation`, Monitoring domain `Event`, `Alert`, correlation/root-cause, maintenance and suppression state.
- ITSM owns `Incident` as a managed service process.

Monitoring may later request or link an Incident through an approved contract/event. An Alert and an Incident are never the same entity. A mass Incident remains an ITSM Incident created from correlated Monitoring data.

The v1 `performance_incidents` data therefore cannot be migrated automatically as ITSM Incident records. Semantic migration requires classification during the later migration phase.

## 7. External source authority

- **1C**: external accounting/HR authority for applicable attributes. Fleetory does not become a statutory accounting system.
- **AD/LDAP/Entra**: external identity and membership sources. Fleetory RBAC remains Fleetory-owned.
- **Fleetory Agent**: preferred live technical source when available.
- **SCCM/Everest/AIDA-like inventory**: supplementary inventory/reconciliation sources.
- **SCOM/Zabbix/Prometheus/SNMP/Syslog**: Monitoring inputs. They do not own ITSM Incident.

## 8. Provenance principle

`Fleetory.SharedKernel.DataProvenance` is a technical value contract, not a global domain entity. It carries:

- `SourceSystem`;
- `SourceRecordId` when applicable;
- `ObservedAt`;
- `ReceivedAt` when applicable;
- `Authority`.

Owning modules decide which fields require provenance and how source precedence is applied. No global provenance repository is introduced in PHASE 3.

## 9. Inter-module reference rules

Allowed mechanisms:

- owning-context semantic IDs;
- public summaries;
- public contracts;
- versioned application/integration events;
- future approved read models / Context Bridge projections.

Forbidden mechanisms:

- implementation -> foreign implementation references;
- direct foreign-table SQL;
- cross-module repository access;
- cross-module EF navigation;
- hidden shared domain models in SharedKernel/Common/Helpers projects.

The actual PHASE 3 `*.Contracts -> foreign *.Contracts` allowlist is **empty**. Future exceptions require explicit documentation and Architecture Test allowlisting.

## 10. Deferred decisions

PHASE 3 intentionally does not define:

- PostgreSQL schemas, tables, FKs, repositories or migrations;
- detailed domain aggregates/workflows;
- Context Bridge transport/read-store implementation;
- Agent protocol/PKI/mTLS/Command Plane;
- authentication/RBAC/Audit/Licensing/Search/Notifications implementation;
- connector implementation;
- UI models;
- broker/outbox transport.

## 11. PHASE 6 persistence realization note

PHASE 6 realizes only two minimal persistence examples required to prove the already-approved ownership model:

- Platform persists a minimal Person/Directory projection in the `platform` schema;
- Core persists a minimal Device record in the `core` schema.

This does not change ownership from PHASE 3. The remaining context schema names (`assets`, `itsm`, `cmdb`, `monitoring`, `integrations`) are reserved for their owning bounded contexts but no empty DbContext/model is created before a concrete persistence requirement exists.

There are no cross-context database foreign keys. `DeviceId`, `PersonId` and future context-specific semantic IDs remain application/domain references rather than a shared database identity model. Legacy v1 data migration remains deferred.

