# Fleetory Platform Foundation

**Phase:** PHASE 4 — Platform Foundation  
**Status:** normative implementation document for the PHASE 4 source tree

## 1. Purpose

`Fleetory.Platform` is the common platform bounded context. It provides narrowly scoped, OS-neutral, persistence-neutral capabilities that other Fleetory modules can consume through `Fleetory.Platform.Contracts`.

PHASE 4 establishes interfaces and the minimum executable coordination needed for the platform foundation. It does **not** implement the later Security Foundation, database persistence, external identity connectors, search engines, notification transports, licensing cryptography, Agent functionality or domain workflows.

PHASE 3 ownership remains normative. Platform does not own Device, Asset, ConfigurationItem, Ticket, Alert or other bounded-context domain entities.

## 2. Dependency boundary

Production dependency policy remains unchanged:

```text
Fleetory.Platform
  -> Fleetory.Platform.Contracts
  -> Fleetory.ModuleAbstractions

Fleetory.Platform.Contracts
  -> Fleetory.SharedKernel
```

`Fleetory.Platform` has no implementation reference to Core, Assets, ITSM, CMDB, Monitoring or Integrations. The cross-context `*.Contracts -> *.Contracts` allowlist remains empty.

`Fleetory.Server` remains the only composition root and still composes the seven approved bounded-context implementation modules explicitly.

## 3. Implemented PHASE 4 capabilities

### 3.1 Module Registry

Public surface:

- `ModuleRegistration`
- `IModuleRegistry`

Runtime implementation:

- `ModuleRegistry` in `Fleetory.Platform`

The registry projects the statically composed `IFleetoryModule` collection into stable platform metadata. The existing module `Name` is the stable module identifier and current display name. The registry:

- exposes registered module metadata;
- provides lookup by module identifier;
- rejects duplicate module identifiers;
- does not discover assemblies dynamically;
- does not load plugins.

There is intentionally no DLL scanning, reflection-based auto-loading or plugin runtime.

### 3.2 Identity / current actor abstraction

Public surface:

- `ActorKind`
- `ActorReference`
- `ICurrentActorAccessor`

This models the actor visible to later Platform/security code. It does not authenticate anyone and does not issue sessions, cookies, JWTs, bearer tokens or credentials.

`PersonId` from PHASE 3 can optionally associate a person actor with the Platform Person/Directory projection. System/service actors do not require a `PersonId`.

### 3.3 Authorization abstraction

Public surface:

- `AuthorizationRequest`
- `AuthorizationDecision`
- `IAuthorizationService`

`AuthorizationRequest` carries an actor, permission identifier and optional existing `ScopeId`. PHASE 4 does not implement an RBAC evaluator, role store, external-group mapping or persistent policy engine.

`ScopeId` remains the authorization/access hierarchy identity. It is not a Core Device Group, Asset hierarchy or CMDB topology node.

### 3.4 Audit abstraction

Public surface:

- `AuditTarget`
- `AuditRecord`
- `IAuditWriter`

`AuditRecord` provides the future persistence boundary with:

- actor;
- action;
- optional target;
- `CorrelationId`;
- timestamp;
- small string metadata context.

No audit database, table, file sink, SIEM transport or WORM export is implemented in PHASE 4.

### 3.5 Notifications abstraction

Public surface:

- `NotificationSeverity`
- `NotificationMessage`
- `INotificationPublisher`

No SMTP, Teams, Telegram, WebSocket, push or other transport is implemented.

### 3.6 Licensing abstraction

Public surface:

- `LicenseRuntimeState`
- `LicenseSnapshot`
- `ILicenseStateProvider`

The contract is runtime-facing only. PHASE 4 does not define a license-file format and does not implement signature validation, activation, hardware fingerprinting, vendor keys, grace calculations or entitlement persistence.

### 3.7 Search abstraction

Public surface:

- `SearchRequest`
- `SearchResult`
- `ISearchProvider`
- `ISearchService`

Runtime implementation:

- `SearchService` in `Fleetory.Platform`

The coordinator aggregates explicitly registered `ISearchProvider` implementations and enforces the caller result limit. A provider returns opaque public search results identified by source module/type/id; Platform does not read another module's tables or repositories.

No Elasticsearch, OpenSearch, PostgreSQL FTS, Lucene or external search service is introduced.

### 3.8 Clock and correlation

PHASE 4 reuses the existing SharedKernel primitives:

- `IClock` / `SystemClock`
- `CorrelationId`

No competing clock or correlation identifier was introduced.

## 4. Module registration

`PlatformModule.RegisterServices` registers only executable PHASE 4 Platform services:

- `IModuleRegistry -> ModuleRegistry`
- `ISearchService -> SearchService`

The remaining capabilities are contract-level extension points until their implementation phase. This is deliberate: PHASE 4 must not disguise no-op placeholders as production security, audit, licensing or notification behavior.

Module endpoint ownership is unchanged. Platform does not add business endpoints in PHASE 4.

## 5. Explicit non-goals

PHASE 4 intentionally does not add:

- PostgreSQL, Npgsql, EF Core, DbContext, repositories, schemas, migrations or SQL;
- authentication/login/session/token implementation;
- MFA/WebAuthn;
- AD/LDAP/Entra/OIDC authentication or directory connectors;
- persistent RBAC or authorization policy storage;
- Audit persistence/export;
- licensing cryptography/activation;
- notification transports;
- dedicated search engine/index storage;
- Secret Provider implementation;
- PKI, mTLS, enrollment or command signing;
- Agent Core or platform Agents;
- module-specific business workflows;
- dynamic plugins or microservice infrastructure.

## 6. OS neutrality

Platform code remains part of the OS-neutral Server runtime. It must not directly use Windows-only APIs such as Registry, WMI/System.Management, Windows Service APIs, Windows identity/principal types or Windows-specific runtime checks.

Future platform-specific hosting/adapters may exist in dedicated projects when their normative phase requires them. They are not part of PHASE 4.

## 7. Relation to PHASE 3 ownership

PHASE 3 remains authoritative for data ownership and public domain summaries/identifiers:

```text
Device != Asset != ConfigurationItem
Observation -> Event -> Alert -> Incident
```

Platform continues to own:

- Person/Directory projection;
- authorization/access Scope hierarchy;
- user preferences;
- Module Registry metadata.

The PHASE 4 abstractions do not move foreign domain data into Platform and do not change the empty cross-context Contracts dependency allowlist.

## 8. Extension points for later phases

Later phases may provide implementations behind the PHASE 4 interfaces, but must preserve their ownership boundaries:

- Security Foundation: current actor/authentication/RBAC enforcement and security policy;
- PostgreSQL phase: owning Platform persistence without cross-module SQL;
- Audit: durable local storage and asynchronous export;
- Licensing: signed offline-first entitlement evaluation;
- Notifications: transport-specific dispatch adapters;
- Search: module search providers and, only if measured need exists, a dedicated indexing engine.

Any future cross-context contract dependency still requires an explicit documented allowlist change and Architecture Test update.
