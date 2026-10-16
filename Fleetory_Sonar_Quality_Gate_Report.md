# Fleetory Sonar Quality Gate Report — PHASE 3 Closure Baseline

**Status:** **COMPLETE**  
**Baseline consumed by:** PHASE 4 — Platform Foundation

## 1. Final verified result

The PHASE 3 cleanup tree was verified on the real Windows/Sonar environment after all nine Roslyn/Sonar findings were corrected.

| Metric | Final result |
|---|---:|
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

The local PHASE 3 coverage measurement before the final cleanup verification was 93.94%. The authoritative external Sonar closure measurement is 93.2%.

## 2. Findings resolved during PHASE 3 Sonar cleanup

| # | Rule ID | File / location | Fix | Final verification |
|---:|---|---|---|---|
| 1 | `roslyn:CA1873` | `src/Fleetory.Server/FleetoryApplication.cs`, module-registration log | Guarded structured Information log with `IsEnabled(LogLevel.Information)` without changing the message/property. | Closed; Open Issues final = 0. |
| 2 | `roslyn:CA1859` | `tests/Fleetory.Architecture.Tests/ArchitectureBoundaryTests.cs`, `AllowedCrossContextContractReferences` | Used concrete `Dictionary<string, IReadOnlyCollection<string>>` for the private field. | Closed. |
| 3 | `roslyn:CA1861` | `ArchitectureBoundaryTests.cs`, SharedKernel expected references | Reused class-local `private static readonly string[] SharedKernelOnly`. | Closed. |
| 4 | `roslyn:SYSLIB1045` | `ArchitectureBoundaryTests.cs`, module endpoint regex | Replaced runtime compiled regex with `GeneratedRegex`, preserving pattern and `CultureInvariant`. | Closed. |
| 5 | `roslyn:CA1859` | `ArchitectureBoundaryTests.cs`, `GetProjectReferences` | Return type changed to `string[]`. | Closed. |
| 6 | `roslyn:CA1859` | `ArchitectureBoundaryTests.cs`, directory `GetDeclaredTypeNames` | Return type changed to `HashSet<string>` with the same comparer. | Closed. |
| 7 | `roslyn:CA1859` | `ArchitectureBoundaryTests.cs`, file `GetDeclaredTypeNames` | Return type changed to `string[]`. | Closed. |
| 8 | `roslyn:SYSLIB1045` | `ArchitectureBoundaryTests.cs`, type-declaration regex | Replaced runtime compiled regex with `GeneratedRegex`, preserving pattern/named groups and `CultureInvariant`. | Closed. |
| 9 | `roslyn:CA1859` | `tests/Fleetory.Server.Tests/FoundationPrimitiveTests.cs` | Test-local clock variable now uses concrete `SystemClock`; production `IClock` is unchanged. | Closed. |

No suppressions, `NOSONAR`, `#pragma warning disable`, analyzer rule changes, source/coverage exclusions, Quality Profile changes or Quality Gate weakening were used.

## 3. Repository-local Sonar toolchain

The repository keeps the pinned toolchain and SonarCloud organization support established during quality hardening:

- `dotnet-sonarscanner` 11.3.0;
- `dotnet-coverage` 18.11.2;
- `SONAR_ORGANIZATION` support;
- `/o:` in SonarScanner `begin`;
- UTF-8 console handling;
- `DOTNET_CLI_UI_LANGUAGE=en-US`;
- external runtime credentials only; no token stored in repository files.

## 4. PHASE 4 quality baseline

PHASE 4 starts from the following verified floor and must not weaken it:

```text
STRICT BUILD        PASS
TESTS               PASS
ARCHITECTURE TESTS  PASS
COVERAGE            93.2%
DUPLICATION         0.0%
SECURITY ISSUES     0
OPEN ISSUES         0
SONAR ANALYSIS      PASS
SONAR QUALITY GATE  PASSED
SECURITY RATING     A
```

Any PHASE 4 post-change values require a fresh strict/Sonar run and must not be inferred from this baseline.

## 5. PHASE 6 external verification — 2026-10-16

[GitHub Actions run 38958778154](https://github.com/aroginsky-maker/Fleetory-v2/actions/runs/38958778154) analyzed PR #1 at commit `e6f2f85` with the existing Sonar Way Quality Gate. The current PHASE 6 values are separate from the historical PHASE 3 closure above.

| Metric | PHASE 6 result |
| --- | ---: |
| Strict build | PASS, 0 warnings and 0 errors |
| Tests | PASS, 44/44 |
| Local production line coverage | 90.62% |
| Sonar overall coverage | 88.1% |
| Sonar coverage on new code | 85.9% (required >= 80%) |
| Sonar overall duplication | 0.0% |
| Sonar duplication on new code | 0.0% (required <= 3%) |
| New issues | 0 |
| Security Hotspots | 0 |
| Sonar analysis | PASS |
| Sonar Quality Gate | PASS |

The `.NET` coverage collector cannot instrument PowerShell or shell scripts in `eng/`; those scripts remain in Sonar issue and duplication analysis but are excluded from the Sonar coverage denominator. Their behavior is checked by the phase verification and package smoke scripts. The EF mapping refactor kept the Platform and Core DbContexts separate; both EF models still match their checked-in migration snapshots. No Quality Gate threshold or rule was changed.
