# Fleetory v2 — PHASE 7 Security Foundation in progress

PHASE 6 PostgreSQL persistence is complete. PHASE 7 has started with the signed-command verification foundation in Core; see `docs/architecture/SecurityFoundation.md` for its boundaries and remaining work.

PHASE 6 was verified on 16 October 2026: 44/44 tests, disposable PostgreSQL migrations and readiness, Windows/Linux server packages, and Sonar Quality Gate passed. Sonar reported 85.9% new-code coverage, 0.0% new-code duplication, 88.1% overall coverage, and 0.0% overall duplication. See `Fleetory_v2_PHASE6_Implementation_Report.md` for the full evidence.

## Incoming baseline

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

## PHASE 6 scope

PHASE 6 introduces only the persistence foundation required to prove PostgreSQL ownership boundaries:

- PostgreSQL + Npgsql + EF Core with repository-pinned versions;
- `platform` and `core` executable persistence boundaries;
- minimal internal Person projection and Device persistence records;
- per-DbContext EF migrations and per-schema migration history;
- strongly typed semantic-ID mapping to PostgreSQL `uuid`;
- UTC timestamp and optimistic concurrency semantics;
- PostgreSQL-aware readiness while liveness remains database-independent;
- real-PostgreSQL integration tests;
- safe PHASE 6 verification scripts;
- PHASE 5 Windows/Linux package regression checks.

No Security Foundation, authentication, Agent, v1 data migration or cross-context database access is introduced.

## Runtime configuration

The mandatory runtime configuration key is:

```text
ConnectionStrings:Fleetory
```

With Fleetory's configuration prefix it can be supplied as:

```text
FLEETORY_ConnectionStrings__Fleetory
```

Do not put production credentials in repository files.

## PostgreSQL integration-test environment

The default PHASE 6 integration-test path is self-contained: `Fleetory.Persistence.Tests` uses Testcontainers for .NET to create a fresh real PostgreSQL container automatically.

Pinned test infrastructure:

```text
Testcontainers.PostgreSql 4.15.0
postgres:18.6
```

No PostgreSQL database, user, schema, or migration state must be created manually. Docker must be available; the container uses generated test-only credentials and a dynamically mapped host port, applies the real EF migrations, and is removed after the test collection.

Docker/Testcontainers are test infrastructure only. Fleetory.Server Windows/Linux packages do not depend on Docker.

An explicit external test PostgreSQL can be supplied only as an override:

```powershell
$env:FLEETORY_TEST_CONNECTION_STRING = '<explicit test connection string>'
```

The database name must contain `test`. There is never a fallback to production `ConnectionStrings:Fleetory`. An external override does not by itself satisfy final PHASE 6 closure; at least one successful default disposable Testcontainers run is required.

## Verification

Windows:

```powershell
.\eng\verify-phase6.ps1
.\eng\verify-quality.ps1
```

Linux/CI:

```bash
./eng/verify-phase6.sh
./eng/verify-sonar.sh
```

`verify-phase6` checks Docker automatically when no external override is supplied. If Docker is unavailable it reports that PostgreSQL integration verification requires Docker or `FLEETORY_TEST_CONNECTION_STRING`; it never reports PostgreSQL PASS from static inspection.

For full Sonar verification, keep the existing Sonar environment variables configured. The Sonar/coverage test run uses the same PostgreSQL test strategy.

See `docs/architecture/PostgreSqlPersistence.md` for the normative persistence rules and migration workflow.

The PHASE 6 verification used .NET 10, a disposable PostgreSQL container, and the connected GitHub Actions SonarCloud project. PHASE 7 is in progress and is not yet eligible for completion status.
