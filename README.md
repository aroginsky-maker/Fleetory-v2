# Fleetory v2 — PHASE 7 Security Foundation in progress

PHASE 6 PostgreSQL persistence is complete. PHASE 7 now includes signed-command verification, Agent/Admin mTLS gateways, certificate enrollment and revocation, durable audit with optional immudb export, RBAC, secret providers and an Admin OIDC gate. It remains in progress; see `docs/architecture/SecurityFoundation.md` and `docs/architecture/SecurityLab.md` for boundaries and remaining work.

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

PHASE 7 Security Foundation work is in progress. The Admin OIDC gate is available, while Agent command execution, v1 data migration and cross-context database access are not introduced.

## Runtime configuration

In Production and other non-development environments, configure the absolute path to a mounted secret directory:

```text
FLEETORY_Fleetory__Secrets__Directory=/run/secrets/fleetory
```

The directory must contain `fleetory-postgresql`, a UTF-8 file holding the PostgreSQL connection string. On Linux the file must be readable only by its owner (`0400` or `0600`); on Windows, grant read access only to the Fleetory service identity through ACLs. Provision the file through an operating-system secret mount or external secret manager. The path is configuration; the secret value is never passed as a command-line argument or environment variable. Fleetory reads and caches it for the process lifetime; rotation requires a restart.

For local Development and tests only, the previous configuration key remains available:

```text
ConnectionStrings:Fleetory
```

Non-development startup rejects direct connection strings and fails if the secret file is missing or invalid. Do not put production credentials in repository files.

The initial Agent identity listener is disabled by default. To enable it, set `Fleetory:AgentGateway:Enabled=true`, `Fleetory:Web:Port` and a different `Fleetory:AgentGateway:Port`, and add three PEM files to the same secret directory: `agent-gateway-root-ca`, `agent-gateway-server-cert` and `agent-gateway-server-key`. The server certificate must chain directly to the root CA and the private key must match it. The root CA private key belongs in a separate CA service. The Agent port requires a client certificate issued by that CA and an active Core binding; `GET /agent/identity` is currently the only Agent route. The web port is plain HTTP at Kestrel, so deploy it behind a protected HTTPS ingress or within a trusted network. The Agent port expects end-to-end mTLS at Kestrel.

The optional administrative revocation listener uses `Fleetory:AdminGateway:Enabled=true`, a distinct `Fleetory:AdminGateway:Port`, and `admin-gateway-root-ca`, `admin-gateway-server-cert`, `admin-gateway-server-key` in the same secret directory. By default it binds to `127.0.0.1`; set `Fleetory:AdminGateway:BindAddress` to a specific management-network IP for remote access. Its CA must differ from the Agent CA. An Admin client certificate issued by this CA must contain `urn:fleetory:admin:<guid>` in SAN; the corresponding RBAC actor is `person:<guid-without-hyphens>`. Only that actor with a global `core.agent_certificate.revoke` grant can call `POST /admin/devices/{deviceId}/certificates/{fingerprint}/revoke`. No grant or Admin certificate is created automatically. Keep both CA private keys outside Fleetory Server and restrict the Admin port to a management network. Certificate issuance and enrollment are not yet available through this listener.

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

The full PHASE 7 suite additionally builds and runs the restricted signer image
in Docker, including when this PostgreSQL override is set. See the
[signer container profile](docs/operations/CommandSignerDeployment.md#restricted-linux-container-profile)
for packaging, runtime limits and the exact process-isolation checks.

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
