# Fleetory v2 — PHASE 6 Implementation Report

## Status

**PHASE 6 = IMPLEMENTED / DISPOSABLE POSTGRESQL VERIFICATION PENDING**

This report continues the existing PHASE 6 implementation. It does not restart PHASE 6 and does not begin PHASE 7.

## 1. Incoming baseline

The source baseline is the current execution-chat PHASE 6 working tree, which already contains the PostgreSQL/EF Core persistence foundation on top of the user-confirmed closed PHASE 5 baseline.

Incoming closed baseline before PHASE 6 changes:

```text
PHASE 0             COMPLETE
PHASE 1             COMPLETE
PHASE 2             COMPLETE
PHASE 3             COMPLETE
PHASE 4             COMPLETE
PHASE 5             COMPLETE
STRICT BUILD        PASS
TESTS               PASS
ARCHITECTURE TESTS  PASS
SERVER PACKAGING    PASS
SONAR ANALYSIS      PASS
SONAR QUALITY GATE  PASSED
OPEN ISSUES         0
SECURITY ISSUES     0
```

The earlier PHASE 6 tree had a correct real-PostgreSQL integration suite but required the user to provision an external test database manually. This continuation replaces that manual prerequisite with disposable Testcontainers PostgreSQL by default.

## 2. Persistence packages and test-infrastructure versions

Production persistence versions remain unchanged:

| Package | Version | Scope |
| --- | ---: | --- |
| Microsoft.EntityFrameworkCore | 10.0.12 | Platform/Core production persistence |
| Microsoft.EntityFrameworkCore.Design | 10.0.12 | design-time migrations in owning modules |
| Npgsql | 10.0.3 | PostgreSQL provider/runtime |
| Npgsql.EntityFrameworkCore.PostgreSQL | 10.0.3 | Platform/Core production persistence |

Added test-only dependency:

| Package / image | Version | Scope |
| --- | ---: | --- |
| Testcontainers.PostgreSql | 4.15.0 | `Fleetory.Persistence.Tests` only |
| PostgreSQL Docker image | `postgres:18.6` | disposable integration-test infrastructure only |

No production project references Testcontainers.

## 2.1. Files/projects changed by this continuation

The Testcontainers continuation changes only PHASE 6 test infrastructure, verification, architecture enforcement, and documentation:

- `Directory.Packages.props` — pins `Testcontainers.PostgreSql` for test infrastructure;
- `tests/Fleetory.Persistence.Tests/Fleetory.Persistence.Tests.csproj` — adds the test-only Testcontainers package reference;
- `tests/Fleetory.Persistence.Tests/PostgreSqlTestFixture.cs` — default disposable PostgreSQL lifecycle plus explicit external-test override;
- `tests/Fleetory.Persistence.Tests/PostgreSqlPersistenceTests.cs` — real migration/persistence/readiness verification, including database-unavailable behavior;
- `tests/Fleetory.Persistence.Tests/PostgreSqlFactAttribute.cs` — removed because PostgreSQL tests no longer depend on a manually provisioned environment;
- `tests/Fleetory.Architecture.Tests/ArchitectureBoundaryTests.cs` — enforces that Testcontainers remains test-only;
- `eng/verify-phase6.ps1` and `eng/verify-phase6.sh` — Docker prerequisite detection, automatic disposable PostgreSQL verification, package regression, and explicit summaries;
- `eng/verify-quality.ps1` — recognizes the default Docker/Testcontainers persistence-test path without requiring a manually provisioned database;
- `eng/verify-sonar.sh` — preserves SonarCloud organization support parity with the PowerShell path;
- `docs/architecture/PostgreSqlPersistence.md` — documents production PostgreSQL, explicit external test PostgreSQL, and disposable Testcontainers PostgreSQL as distinct concerns;
- `docs/quality/SonarQualityGate.md` and `README.md` — update the PHASE 6 developer verification path;
- `Fleetory_v2_PHASE6_Implementation_Report.md` — records this continuation and its verification status.

No production bounded-context project receives a Testcontainers dependency, and the production persistence topology is unchanged.

## 3. Test-project decision

The existing `tests/Fleetory.Persistence.Tests` project was already a dedicated PostgreSQL integration-test project and contained no Architecture/unit test responsibilities. It is therefore retained instead of being renamed or duplicated as `Fleetory.Persistence.IntegrationTests`.

This avoids unnecessary solution churn while satisfying the requirement that PostgreSQL integration tests remain isolated from Architecture/unit tests.

## 4. Default disposable PostgreSQL lifecycle

When `FLEETORY_TEST_CONNECTION_STRING` is **not** set, `PostgreSqlTestFixture` now:

1. builds a Testcontainers PostgreSQL instance from pinned image `postgres:18.6`;
2. generates a unique `fleetory_test_*` database name;
3. generates a unique test-only username and password;
4. lets Testcontainers bind PostgreSQL to a dynamic/free host port;
5. starts the real PostgreSQL container;
6. obtains its generated connection string;
7. registers the real Platform/Core persistence services;
8. applies the real Platform and Core EF migrations;
9. runs persistence/readiness integration tests;
10. disposes/removes the container when the xUnit collection ends.

No persistent volume is configured. A normal second test run gets a new isolated PostgreSQL environment and does not depend on the previous run's data.

## 5. Optional external test PostgreSQL override

The only explicit override is now:

```text
FLEETORY_TEST_CONNECTION_STRING
```

There is no fallback to runtime/production `ConnectionStrings:Fleetory`.

Safety validation for the external override requires:

- a parseable PostgreSQL connection string;
- an explicit database name;
- database name contains `test`;
- `postgres`, `template0`, and `template1` are rejected;
- only Fleetory-owned `platform` and `core` schemas are reset;
- the external database itself is never dropped.

The old manual default variables `FLEETORY_TEST_POSTGRES_CONNECTION_STRING` and `FLEETORY_TEST_POSTGRES_ALLOW_RESET` are no longer the PHASE 6 test strategy.

An external override is diagnostic/optional. It cannot by itself close PHASE 6 because the updated success criteria require an actual disposable Testcontainers run.

## 6. Real PostgreSQL integration tests

The persistence suite still verifies the existing PHASE 6 foundation and now runs automatically against Testcontainers by default:

- PostgreSQL connectivity and explicit test database identity;
- actual Platform/Core migration application;
- `platform` and `core` schemas;
- `platform.person_projections` and `core.devices`;
- separate migration history tables;
- expected migration IDs;
- zero cross-context PostgreSQL foreign keys;
- strongly typed `PersonId` and `DeviceId` round-trip;
- UTC timestamp semantics;
- optimistic revision concurrency behavior;
- `/health/live` and `/health/ready` healthy while PostgreSQL is available.

A new availability-transition test additionally verifies database failure semantics. On the default Testcontainers path it stops the disposable PostgreSQL container, checks that liveness remains HTTP 200 while readiness becomes HTTP 503, and then restarts PostgreSQL in `finally` so the shared fixture remains valid regardless of test order. With an explicit external database override, the test never stops the external service; it validates the same application semantics using an unreachable connection derived only for that test.

## 7. Architecture enforcement

Existing PHASE 0–6 architecture rules are preserved.

A new Architecture Test explicitly enforces that:

- no project under `src/` references `Testcontainers`;
- `Fleetory.Persistence.Tests` contains the `Testcontainers.PostgreSql` dependency.

No bounded-context ownership, DbContext ownership, Server deployment architecture, contract dependency rule, SharedKernel rule, or PHASE 3 data-ownership decision changed.

## 8. verify-phase6 changes

`eng/verify-phase6.ps1` and `eng/verify-phase6.sh` now use this policy:

### Default path

- verify Docker CLI/daemon availability;
- run restore/build/tests;
- allow the integration fixture to create disposable PostgreSQL automatically;
- mark `POSTGRESQL CONTAINER PASS` only after the real integration suite succeeds;
- verify migrations, persistence behavior and database readiness;
- run the existing PHASE 5 Windows/Linux package regression;
- run current-host published server startup/liveness/CorrelationId smoke checks.

If Docker is unavailable, the scripts stop with:

```text
PostgreSQL integration verification requires Docker or an explicit FLEETORY_TEST_CONNECTION_STRING.
```

and do not report PostgreSQL PASS.

### External override path

When `FLEETORY_TEST_CONNECTION_STRING` is supplied, the scripts validate its explicit test marker and run the same integration suite against it. Summary output shows:

```text
POSTGRESQL CONTAINER     NOT RUN (external override)
```

Even if the external checks pass, `verify-phase6` exits with a non-completion status because the updated PHASE 6 closure requires the disposable container path to have been executed successfully.

## 9. Quality verification integration

`eng/verify-quality.ps1` no longer requires a manually provisioned PostgreSQL database/reset marker. When PHASE 6 persistence tests are present it now accepts:

- Docker/Testcontainers by default; or
- explicit `FLEETORY_TEST_CONNECTION_STRING` override.

Therefore normal coverage/Sonar test execution can exercise the same real PostgreSQL test path without manual DB setup.

Existing Sonar credentials and Sonar organization handling are unchanged. No token or database secret is embedded in repository files.

## 10. PHASE 5 packaging remains independent of Docker

Docker/Testcontainers are not added to Fleetory.Server or any production package dependency graph.

Native `win-x64` and `linux-x64` packages remain framework-dependent .NET server packages exactly as established in PHASE 5/earlier PHASE 6 packaging.

Package validation still rejects test assemblies, source files, development artifacts, development settings and secret-like configuration keys.

The current-host package smoke test uses a non-secret unreachable test-only PostgreSQL connection string only so the Server can build its composition root; it verifies startup, `/health/live`, and CorrelationId without requiring a persistent database. Real ready/unready database behavior is owned by the Testcontainers integration suite.

## 11. Documentation changes

Updated:

- `docs/architecture/PostgreSqlPersistence.md`;
- `docs/quality/SonarQualityGate.md`;
- `README.md`;
- this PHASE 6 report.

The persistence document now explicitly distinguishes:

1. production PostgreSQL;
2. optional manually supplied external test PostgreSQL;
3. default disposable PostgreSQL via Testcontainers.

## 12. CI

No GitHub Actions workflow exists in the current source tree, so this continuation does not invent a new CI architecture. The integration suite itself is Windows/Linux portable and is designed to use the same Testcontainers mechanism when a future Linux CI workflow with Docker is approved.

No permanently running CI database is introduced.

## 13. PowerShell encoding

Repository PowerShell policy remains:

- UTF-8 with BOM;
- CRLF;
- English script-owned console output;
- `DOTNET_CLI_UI_LANGUAGE=en-US` where used.

The modified PowerShell verification scripts are normalized to this policy.

## 14. Explicitly unchanged production architecture

This continuation changes only test infrastructure, verification behavior, and related documentation.

It does **not** change:

- bounded-context ownership;
- Platform/Core DbContext ownership;
- PHASE 3 Device / Asset / ConfigurationItem separation;
- Contracts dependency rules;
- SharedKernel domain neutrality;
- production PostgreSQL topology;
- production Server packaging/deployment architecture;
- authentication/RBAC/Security Foundation;
- Agent Protocol/Agent implementation.

PHASE 7 was not started.

## 15. Static verification performed in this execution environment

The execution environment used to prepare this continuation has neither the .NET 10 SDK nor Docker. Therefore no real Testcontainers/PostgreSQL/build/Sonar PASS is claimed.

Static checks performed before delivery include:

- 21 project files parse as XML;
- the static test surface contains 44 test methods/attributes (24 Architecture, 8 Platform, 6 Server, 6 PostgreSQL integration);
- all `ProjectReference` targets resolve;
- `Testcontainers.PostgreSql` is centrally pinned at `4.15.0`;
- only `Fleetory.Persistence.Tests` references Testcontainers;
- pinned PostgreSQL test image is `postgres:18.6`;
- no old manual PHASE 6 test environment variable remains in active code/scripts/docs;
- existing production package references remain unchanged;
- Bash scripts pass `bash -n`;
- PowerShell scripts are UTF-8 BOM + CRLF;
- ZIP integrity is checked.

## 16. Post-change verification status

| Metric | Result in this execution environment |
| --- | ---: |
| STRICT BUILD | **NOT VERIFIED** |
| TESTS | **NOT VERIFIED** |
| ARCHITECTURE TESTS | **NOT VERIFIED** |
| POSTGRESQL CONTAINER | **NOT VERIFIED** |
| POSTGRESQL CONNECTIVITY | **NOT VERIFIED** |
| MIGRATIONS | **NOT VERIFIED** |
| PERSISTENCE TESTS | **NOT VERIFIED** |
| DATABASE READINESS | **NOT VERIFIED** |
| SERVER PACKAGE | **NOT VERIFIED** |
| COVERAGE | **NOT VERIFIED** |
| DUPLICATION | **NOT VERIFIED** |
| SECURITY ISSUES | **NOT VERIFIED** |
| OPEN ISSUES | **NOT VERIFIED** |
| SONAR ANALYSIS | **NOT VERIFIED** |
| SONAR QUALITY GATE | **NOT VERIFIED** |

The closed PHASE 5 metrics are incoming baseline only and are not reused as evidence for this changed PHASE 6 tree.

## 17. Required real verification

With Docker running, no PostgreSQL setup variables are needed:

```powershell
.\eng\verify-phase6.ps1
.\eng\verify-quality.ps1
```

The PHASE 6 script itself will validate Docker and the integration tests will create/remove the PostgreSQL test environment.

Optional explicit external test database:

```powershell
$env:FLEETORY_TEST_CONNECTION_STRING = '<external PostgreSQL test database>'
.\eng\verify-phase6.ps1
```

This external path does not satisfy final disposable-container closure by itself.

## 18. Updated PHASE 6 completion criteria

PHASE 6 may be marked COMPLETE only after an actual default Testcontainers run demonstrates:

```text
POSTGRESQL CONTAINER     PASS
MIGRATIONS               PASS
PERSISTENCE TESTS        PASS
DATABASE READINESS       PASS
```

and the remaining PHASE 6 criteria are also green:

```text
STRICT BUILD             PASS
TESTS                    PASS
ARCHITECTURE TESTS       PASS
SERVER PACKAGE           PASS
SONAR ANALYSIS           PASS
SONAR QUALITY GATE       PASS
OPEN ISSUES              0
SECURITY ISSUES          0
COVERAGE                  >= 80%
DUPLICATION               <= 3%
```

## 19. Architecture decision status

**ARCHITECTURE DECISION REQUIRED: none.**

The updated Testcontainers strategy is explicitly required by the PHASE 6 task addition and is isolated to test infrastructure.

## 20. Exit status

**PHASE 6 = IMPLEMENTED / DISPOSABLE POSTGRESQL VERIFICATION PENDING**

PHASE 7 was not started.
