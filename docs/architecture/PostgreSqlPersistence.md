# PostgreSQL Persistence — PHASE 6

## 1. Purpose

PHASE 6 establishes Fleetory v2 PostgreSQL persistence foundations without implementing the complete future domain model. PostgreSQL is the primary server database. Persistence follows bounded-context ownership and does not become a shared universal model.

The PHASE 3 ownership model remains normative. `Device != Asset != ConfigurationItem`; persistence does not merge those identities or transfer ownership between bounded contexts.

## 2. Technology and pinned versions

Production persistence uses:

- Entity Framework Core `10.0.12`;
- Npgsql `10.0.3`;
- Npgsql.EntityFrameworkCore.PostgreSQL `10.0.3`.

Integration-test infrastructure uses only the dedicated persistence test project:

- Testcontainers.PostgreSql `4.15.0`;
- PostgreSQL Docker image `postgres:18.6`.

Testcontainers is not referenced by any production project and is not a runtime dependency of Fleetory.Server.

## 3. Database and schema ownership

Fleetory uses one PostgreSQL database topology at this modular-monolith stage, with bounded-context ownership expressed through PostgreSQL schemas.

Executable PHASE 6 schemas:

| Schema | Owner | PHASE 6 physical model |
| --- | --- | --- |
| `platform` | Platform | `person_projections`, PHASE 7 `audit_events` and `audit_export_queue`, Platform migration history |
| `core` | Core | `devices`, Core migration history |

Reserved by Data Ownership but intentionally not materialized without a real persisted model:

- `assets`;
- `itsm`;
- `cmdb`;
- `monitoring`;
- `integrations`.

`public` does not own Fleetory business tables. SharedKernel owns no database schema. No cross-context foreign key is used as a module-integration mechanism.

## 4. DbContext boundaries

PHASE 6 introduces only the DbContexts backed by an actual minimal persisted model:

- `Fleetory.Platform.Persistence.PlatformDbContext`;
- `Fleetory.Core.Persistence.CoreDbContext`.

There is no global `FleetoryDbContext`. Other bounded contexts do not receive empty/speculative DbContexts for symmetry.

## 5. Minimal persisted models

### Platform

`PersonProjectionRecord` is internal Platform persistence for the unified Person/Directory projection. It stores:

- semantic `PersonId` as PostgreSQL `uuid`;
- display name;
- UTC `updated_at`;
- optimistic `revision` concurrency token.

It is not an authentication or RBAC persistence model.

### Core

`DeviceRecord` is internal Core persistence. It stores:

- semantic `DeviceId` as PostgreSQL `uuid`;
- display name;
- UTC `updated_at`;
- optimistic `revision` concurrency token.

It contains no Asset or CMDB fields.

Table and column metadata stays on each module's internal persistence record. The owning DbContext retains schema selection, semantic-ID conversion, and the revision default. This avoids repeating the same column configuration in runtime model builders while keeping Platform and Core persistence separate. The checked-in migration snapshots remain unchanged; EF Core's pending-model-change check verifies that the mappings still match them.

## 6. Migrations

Migrations are owned by their DbContext/module and have separate history tables:

```text
Platform: 202609280001_InitialPlatformPersistence
Platform: 202610160001_AddPlatformAuditOutbox (PHASE 7)
Platform: 202610160002_AddPlatformAuthorization (PHASE 7)
Platform: 202610160003_AddAuditExportLease (PHASE 7)
Platform: 202610180001_RestrictAuthorizationRoleDeletion (PHASE 7)
Platform: 202610190001_AddAuthorizationRoleVersions (PHASE 7)
Platform: 202610190002_AddAuthorizationScopeVersions (PHASE 7)
Core:     202609280002_InitialCorePersistence
Core:     20261016212919_AddAgentCertificateBindings (PHASE 7)
Core:     20261017051549_AddAgentEnrollmentGrants (PHASE 7)
Core:     20261018134130_EnforceAgentIdentityCollision (PHASE 7)
Core:     20261018182619_AddAgentRotationIntents (PHASE 7)
Core:     20261018192451_AddAgentCertificateRecovery (PHASE 7)

platform."__EFMigrationsHistory"
core."__EFMigrationsHistory"
```

Production startup does not call `EnsureCreated`, automatic `Migrate`, destructive reset, or legacy v1 `Schema.sql`.

PHASE 7 audit and authorization storage is written through parameterized Npgsql transactions rather than EF entity models. Platform migrations own those tables; the EF snapshot continues to describe the EF-owned Person projection. Audit events and their export queue entries commit together. Role-version snapshots retain each API-created permission set and predecessor ID; the migration backfills the current roles present when it runs. Direct database bootstrap and recovery scripts also write a snapshot in their transaction. Scope-version snapshots retain the stable scope ID, revision, parent and name; the scope migration backfills revision 1 for existing scopes.

Design-time migration operations use the non-repository environment value `FLEETORY_MIGRATION_CONNECTION_STRING`. This value is not a production secret store.

## 7. Semantic IDs, timestamps and concurrency

`PersonId` and `DeviceId` remain strongly typed at application/contract boundaries and are explicitly converted to PostgreSQL `uuid` by the owning EF model.

Persisted timestamps use PostgreSQL `timestamp with time zone`; application-created values are normalized to UTC. Existing `IClock` remains the application time abstraction where application logic creates timestamps.

The minimal updateable records use a `revision bigint` concurrency token. Stale writes raise `DbUpdateConcurrencyException`; no distributed locking system is introduced.

## 8. Runtime configuration

Production and other non-development Server deployments set the absolute directory path:

```text
FLEETORY_Fleetory__Secrets__Directory=/run/secrets/fleetory
```

The directory contains a UTF-8 `fleetory-postgresql` file supplied by a secret manager or OS secret mount. Linux permissions must exclude group and other access; Windows deployments must restrict ACLs to the service identity. Startup reads and caches the secret and validates Host and Database. Restart to pick up a rotated value. Direct connection strings are rejected in non-development environments.

Development and isolated tests may still use:

```text
ConnectionStrings:Fleetory
```

No production credential or connection string is committed to repository files.

## 9. Health/readiness semantics

The Platform module owns the PostgreSQL readiness check.

```text
/health/live  -> process liveness; independent of PostgreSQL
/health/ready -> application readiness; requires PostgreSQL connectivity
```

Integration tests verify readiness while real PostgreSQL is available. With the disposable Testcontainers environment, the PostgreSQL container is also stopped temporarily and the tests verify that liveness remains healthy while readiness becomes unhealthy, then restart the container before the fixture continues.

## 10. Integration-test project

`tests/Fleetory.Persistence.Tests` is retained as the dedicated PostgreSQL integration-test project. It is not mixed into Architecture or unit-test projects. The project alone references `Testcontainers.PostgreSql`; production projects are protected by an Architecture Test that rejects Testcontainers dependencies under `src/`.

The integration suite covers:

1. real PostgreSQL connectivity;
2. explicit test-database identity;
3. actual EF migration application;
4. `platform` and `core` schemas/tables;
5. separate migration-history tables and migration IDs;
6. absence of cross-context database foreign keys;
7. semantic `PersonId`/`DeviceId` round-trip;
8. UTC timestamp round-trip;
9. optimistic-concurrency rejection of stale writes;
10. readiness healthy with PostgreSQL available;
11. liveness healthy and readiness unhealthy when PostgreSQL is unavailable.

SQLite and EF InMemory are not used as PostgreSQL substitutes.

## 11. Default disposable PostgreSQL test strategy

The default integration-test path requires no manually created database, user, schema or migration state.

For every test fixture run:

1. Testcontainers uses the pinned `postgres:18.6` image.
2. A new container is created with generated test-only database/user/password values.
3. PostgreSQL is exposed through Testcontainers' dynamically mapped host port.
4. The fixture obtains the generated connection string.
5. The real Platform and Core EF migrations are applied.
6. Tests inspect the actual PostgreSQL schemas and migration history.
7. Readiness is tested against that PostgreSQL instance.
8. The container is disposed after the collection and is removed; no persistent volume is configured.

This is test infrastructure only. Docker is **not** required to run native Fleetory.Server packages in production.

Two successive test runs do not depend on the database state from the prior run because the default path creates a fresh disposable PostgreSQL environment each time.

## 12. Docker prerequisite

For the default path, Docker must be available to the test process. `eng/verify-phase6.ps1` and `eng/verify-phase6.sh` check Docker before running the suite.

If neither Docker nor an explicit external test database is available, verification fails with a clear message and does not claim PostgreSQL PASS:

```text
PostgreSQL integration verification requires Docker or an explicit FLEETORY_TEST_CONNECTION_STRING.
```

On Windows this normally means Docker Desktop (or another compatible Docker endpoint) is running. Linux CI may use the same Testcontainers mechanism against its Docker service.

## 13. Optional external test PostgreSQL

An explicitly supplied external **test** PostgreSQL remains available as an override:

```text
FLEETORY_TEST_CONNECTION_STRING
```

Example:

```powershell
$env:FLEETORY_TEST_CONNECTION_STRING = '<explicit external test PostgreSQL connection string>'
```

Safety rules:

- there is never a fallback to production `ConnectionStrings:Fleetory`;
- the database name must contain `test`;
- protected default database names such as `postgres`, `template0`, and `template1` are rejected;
- only Fleetory-owned `platform` and `core` schemas are reset;
- the external database itself is not dropped;
- the connection string is not printed by Fleetory verification scripts.

The external override is useful for diagnosis or controlled CI environments, but it does **not** satisfy the updated PHASE 6 completion criterion by itself. Final PHASE 6 closure requires at least one successful default disposable Testcontainers PostgreSQL run.

## 14. Verification scripts

Default Windows verification requires only .NET, Docker, and the previously configured Sonar variables for the later quality pass:

```powershell
.\eng\verify-phase6.ps1
.\eng\verify-quality.ps1
```

Default Linux/CI verification:

```bash
./eng/verify-phase6.sh
./eng/verify-sonar.sh
```

No PostgreSQL database/user/schema must be provisioned manually on the default path.

`verify-phase6` reports a separate `POSTGRESQL CONTAINER` status. A successful external override is reported as `NOT RUN (external override)` and exits with a non-completion status after the checks, because final PHASE 6 closure requires the disposable-container path.

## 15. Package regression

PHASE 5 native framework-dependent packages remain independent from Docker/Testcontainers. PHASE 6 verifies:

- `win-x64` publish;
- `linux-x64` publish;
- expected EF/Npgsql runtime assemblies;
- absence of test/source/development artifacts and committed credentials;
- current-host published server startup, liveness, and CorrelationId behavior.

Database ready/unready semantics are verified by the PostgreSQL integration suite against real PostgreSQL rather than coupling package execution to a manually provisioned database.

## 16. CI strategy

The current source baseline contains no existing GitHub Actions workflow to extend, so PHASE 6 does not invent a new CI architecture in this task. When a CI workflow is introduced/approved, the persistence integration tests are designed to use the same Testcontainers mechanism on Linux CI without a permanently running CI database.

## 17. Explicit non-goals and deferred work

PHASE 6 does not implement:

- the full persistence model for all bounded contexts;
- legacy v1 data migration;
- authentication/RBAC enforcement/JWT/cookies/MFA/WebAuthn;
- secret provider;
- PKI/mTLS/enrollment;
- Agent Protocol or Agent implementations;
- automatic production schema migration at Fleetory.Server startup;
- cross-context SQL/repository access;
- mandatory Docker production deployment;
- Kubernetes.
