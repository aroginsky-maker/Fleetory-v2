# Fleetory Sonar Quality Gate Policy

**Scope:** cross-cutting quality hardening after PHASE 2 and before PHASE 3.  
**Architecture status:** PHASE 2 remains COMPLETE. This quality work does not introduce PHASE 3 data ownership/contracts, PHASE 4 Platform functionality, PHASE 6 persistence, Agent code, UI, or distributed infrastructure.

## 1. What Sonar verifies

Fleetory uses Sonar analysis as an additional static-quality gate, not as a replacement for the normal .NET compiler/test gate.

The target server-side policy is the built-in **Sonar Way** Quality Gate without weakening thresholds to fit the code. For the current greenfield codebase the quality targets are:

- no new Sonar issues;
- Security Hotspots reviewed = 100%;
- new-code coverage >= 80%;
- new-code duplication <= 3%;
- overall production-code coverage target >= 80%;
- overall duplication target <= 3%;
- no unresolved applicable Security or Reliability issues;
- no unresolved applicable Maintainability issues when fixing them does not violate Fleetory architecture.

The actual assigned Quality Gate and Quality Profile are server-side Sonar configuration. They must be confirmed during real external verification and recorded in `Fleetory_Sonar_Quality_Gate_Report.md`.

## 2. SonarQube for IDE versus Server Quality Gate

SonarQube for IDE is useful for fast local feedback while editing. It does not prove that the repository passed the server Quality Gate.

A Fleetory quality closure requires the server analysis sequence:

1. SonarScanner begin;
2. clean/non-incremental build;
3. tests with coverage generation;
4. SonarScanner end;
5. server-side Quality Gate result.

The repository script sets `sonar.qualitygate.wait=true`, so scanner completion fails when the server Quality Gate fails.

## 3. Two independent build gates

### Gate A — strict Fleetory verification

Run:

```text
dotnet restore Fleetory.sln
dotnet build Fleetory.sln -c Release --no-restore
dotnet test Fleetory.sln -c Release --no-build
```

This gate preserves repository settings including:

- Nullable enabled;
- TreatWarningsAsErrors enabled;
- all Architecture Tests enabled.

### Gate B — Sonar analysis

SonarScanner for .NET can modify MSBuild analysis behavior. Therefore a successful Sonar analysis build is not accepted as evidence that Gate A passed.

Run Gate B only after Gate A is green.

## 4. Repository-local toolchain

The repository pins tools in `.config/dotnet-tools.json`:

- `dotnet-sonarscanner` 11.3.0;
- `dotnet-coverage` 18.11.2.

Restore them with:

```text
dotnet tool restore
```

No global installation is required. The verification scripts invoke local tools through `dotnet tool run` and allow runtime roll-forward where supported by the .NET SDK.

No Sonar credential is stored in the manifest or repository.

## 5. Coverage provider

Fleetory uses `dotnet-coverage` and writes:

```text
artifacts/coverage/coverage.xml
```

The report format is XML compatible with Visual Studio Code Coverage. Sonar imports it through:

```text
sonar.cs.vscoveragexml.reportsPaths=artifacts/coverage/coverage.xml
```

Test projects remain part of Sonar analysis as test code. Production projects are not excluded from coverage to inflate percentages.

`eng/verify-quality.ps1` also calculates a local overall production line-coverage value from Fleetory production modules in `coverage.xml`. This local figure is diagnostic; the authoritative new-code coverage result remains the Sonar server Quality Gate result.

## 6. Required runtime parameters

Set these outside the repository:

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

`SONAR_QUALITYGATE_TIMEOUT` defaults to 300 seconds and must be a positive integer.

The scripts do not echo `SONAR_TOKEN`. Do not enable shell/PowerShell tracing around the Sonar invocation when secrets may be visible.

## 7. Local Windows invocation

Strict + coverage + Sonar when credentials are available:

```powershell
.\eng\verify-quality.ps1
```

Sonar-only gate, after an independently verified strict build:

```powershell
.\eng\verify-sonar.ps1
```

If all three required Sonar environment variables are absent, `verify-quality.ps1` still performs strict restore/build/test and local coverage, but reports:

```text
SONAR ANALYSIS      NOT VERIFIED
SONAR QUALITY GATE  NOT VERIFIED
```

and exits with code 2 so CI cannot mistake incomplete external verification for a full Quality Gate PASS.

If only some Sonar parameters are set, verification fails as a configuration error.

## 8. Bash invocation

On a supported Linux/macOS .NET environment:

```bash
./eng/verify-sonar.sh
```

The same external Sonar environment variables are required.

## 9. Sonar analysis semantics

The Sonar path is intentionally non-incremental:

```text
dotnet clean Fleetory.sln -c Release
dotnet sonarscanner begin ...
dotnet build Fleetory.sln -c Release --no-incremental --disable-build-servers
dotnet-coverage collect "dotnet test Fleetory.sln -c Release --no-build --no-restore" -f xml -o artifacts/coverage/coverage.xml
dotnet sonarscanner end ...
```

The repository scripts use the equivalent repository-local tool invocation rather than requiring global tools.

Generated/transient paths may be excluded from Sonar analysis:

- `**/bin/**`;
- `**/obj/**`;
- `artifacts/**`;
- `.sonarqube/**`.

Production `src/**`, module registrations, architecture code, and test projects are not excluded to manufacture a green result.

## 10. Finding handling policy

Every real finding is handled according to its actual category:

- **REAL DEFECT** — fix the code;
- **MAINTAINABILITY** — fix when doing so preserves Baseline/module boundaries;
- **SECURITY / HOTSPOT** — review individually and record the result;
- **INTENTIONAL ARCHITECTURAL PATTERN** — verify that the rule does not apply before considering suppression;
- **FALSE POSITIVE** — only after evidence is recorded.

A justified false positive must record at minimum:

- Sonar rule ID;
- file and line;
- why the finding is incorrect;
- why any suppression is safe.

## 11. Forbidden ways to obtain a green gate

Do not:

- disable Nullable;
- disable TreatWarningsAsErrors;
- remove Architecture Tests;
- exclude production projects or production source from analysis/coverage;
- mass-add `SuppressMessage` or `NOSONAR`;
- disable Sonar rules without a documented reason;
- mark real issues as false positives;
- lower coverage thresholds;
- increase duplication thresholds;
- weaken the Quality Gate;
- ignore Security Hotspots.

Small duplication across bounded contexts is preferable to introducing an incorrect shared abstraction only to satisfy duplication metrics.

## 12. Current code-hardening changes before external Sonar analysis

No Sonar finding is claimed without a real server analysis. The following objective pre-analysis hygiene changes were made:

- removed unused empty `AssemblyMarker` types from the seven empty Contracts projects;
- removed the unused empty public partial `Program` marker class while preserving the top-level Server entry point;
- refactored duplicated Server smoke-test startup code into a local test helper;
- added behavioral tests for invalid/oversized CorrelationId replacement and approved module registration;
- added behavioral tests for existing SharedKernel `CorrelationId` and `SystemClock` primitives.

These changes are not reported as Sonar findings. They are ordinary maintainability/testability hardening and must pass the strict Fleetory gate before acceptance.

## 13. CI-ready behavior

Recommended current sequence for PHASE 6:

```text
1. start Docker (default Testcontainers PostgreSQL path)
2. eng/verify-phase6.ps1
3. eng/verify-quality.ps1 with protected Sonar environment variables
```

When `Fleetory.Persistence.Tests` is present, `verify-quality.ps1` requires:

```text
Docker available for Testcontainers (default)
# or explicit override:
FLEETORY_TEST_CONNECTION_STRING=<external test PostgreSQL>
```

This prevents a Sonar/coverage run from silently treating skipped PostgreSQL integration tests as a complete PHASE 6 quality result. The connection string is not printed or stored by the script.

A full quality PASS is valid only when strict verification, real PostgreSQL tests and the external Sonar Quality Gate are green.

## 14. Troubleshooting

### `.NET SDK was not found`

Install/use the repository-required .NET 10 SDK and rerun. Do not change target frameworks just to run Sonar.

### local tools do not restore

Check NuGet connectivity and run `dotnet tool restore` from the repository root. Do not replace the pinned repository tools with arbitrary global versions.

### coverage file missing

Confirm that the Sonar build completed before coverage collection and that tests run successfully with `--no-build`. The scripts treat a missing or empty coverage file as a failure.

### Sonar cannot import coverage

Confirm the report exists at `artifacts/coverage/coverage.xml` and that `sonar.cs.vscoveragexml.reportsPaths` points to that path.

### Quality Gate timeout

Increase `SONAR_QUALITYGATE_TIMEOUT` only when the Sonar server legitimately needs more processing time. Do not disable `sonar.qualitygate.wait`.

### Quality Gate fails

Read the server findings and fix the actual issues. Do not alter the gate or exclusions merely to obtain PASS.
