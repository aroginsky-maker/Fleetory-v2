# Distinct existing four-input purpose

`historical/original_four_use.py` adds a trusted library purpose, `existing-original-four-private-consumer.v1`, around the existing closed retained-service reader. It does not change the generic reader's purpose, artifact categories, metadata checks, packet format or native callback API. The only shared ledger change is one fixed `original-four-use-` prefix; no wildcard or reset operation is added.

The trusted caller supplies the fixed root and exactly four typed artifact commitments: application PostgreSQL, signer PostgreSQL, immudb backup and audit export. The wire plan must match those independently supplied paths, lengths and hashes, plus the existing service-plan digest, current revision/image/probe/configuration, execution-inventory digest and actual held parent's identity digest. A report or PID cannot substitute for the held parent object. The policy file itself stays pinned throughout the live context. The inventory callback must belong to the trusted host and continuously check its real execution inventory; a serialized assertion is insufficient.

Before raw capture, a separate bounded exclusive attempt is created, sealed and flushed. The legacy consumed attempt is also retained. Each context is registered to its original process/thread and cannot be reconstructed from a copy or report. Capture and dispatch burn their attempts before checking liveness/inventory or performing I/O, so repairing a failed check cannot reopen the operation. Exactly the existing four frozen packets reach the trusted consumer, including the canonical four-event audit snapshot. File changes after capture cannot alter those packets.

The outer original monotonic and wall clocks begin before admission and keep the existing 108-second ceiling. No method renews them. The native caller must also preserve its existing target window75s, observed-call15s, ready lease5s and256 status-check ceiling. Parent loss, source/inventory drift, expiry, backwards time, category/root/runtime-binding changes and copied/fabricated/cross-thread contexts refuse use. Records remain consumed after closure; local records do not provide independent rollback resistance.

This library does not authenticate session consent, execution-inventory origin or native results and does not grant native launch, restoration or cleanup rights. Existing explicit consent for the retained four files is a separate prerequisite enforced by the trusted operator. It cannot be inferred from this plan, a generated test, a local JSON record or a passing report. Original resource custody remains with the actual live native creator and its complete replies.

The required Windows/Linux gate rehearses ten cases on generated inputs with an actual read-only held parent and real exclusive records. It checks pre-open refusals and exact frozen-packet transfer; it starts no native service and reads no original backups. The private native-consumer bridge, its exact generated native-target rehearsal, current accepted CI/source/probe/image/configuration binding and the protected original four-file execution plan remain required before opening the already-authorized originals. No original root, artifact names or byte pins are embedded in repository code.

Provider/identity inputs, original credentials or private PKI, live issuers and production tokens are excluded. Independent WORM/custody and real external actors, accepted original release/configuration continuity and full-system RPO/RTO remain separate open Baseline requirements. This purpose does not complete Phase7.


## Fixed private exchange integration

`retained_private_session.serve` owns the common capture/status/result/close exchange. The existing retained peer now uses this shared loop with its original factory; its header, four modes, command set, frame bounds and 256-status ceiling remain unchanged. A wire message cannot select a factory or new purpose. Only trusted host code supplies the use factory, actual held parent, source check and private I/O functions.

The distinct-purpose context now exposes its inner reader's actual held identity for the same bound frame. Six exchange tests exercise both use factories with real generated admission and an actual held parent; private packet bytes stay in memory. The tests enforce unchanged frame schemas, exact four-packet transfer, nonce checks and refusal of factory selectors, status replay and result mismatch. This shared loop is not yet a new original-data peer entry point or a completed native-consumer bridge; neither generated exchange tests nor legacy wire compatibility authorize original input reads.

The two generated held-parent suites run beneath a live Python parent using the current interpreter and a bounded 45-second subprocess. This avoids treating the CI PowerShell installation as the trusted parent executable: CI434 refused its writable ancestor directories before admission. The child still opens and validates the actual parent image, birth identity and complete directory ancestry; no parent identity is mocked and no directory check is relaxed. This test-only parent has no native resource or secret authority.

## Separate actual private peer

The trusted host can call `Open-OriginalFourServiceUsePeer` with a separately supplied `ExpectedBinding`. The existing `Open-RetainedServiceUsePeer` and its five bootstrap CLI targets remain available with their original request/header/command shapes. Shared source-bound setup is a library callback selected by reviewed entry-point code; no wire field selects a factory, executable or new artifact category.

The dedicated `original_four_source_bootstrap.py` loads the common bootstrap directly from source, then selects the single literal original peer entry. That peer requires two independent startup pins: its frozen expected-binding frame and the existing service header. The binding carries the exact four commitments, original-purpose plan, policy hash and source-code-plan hash. The source lease, actual parent image/birth and original-purpose consumed attempt are held during the exchange. The parent checks the bound original-plan hash. Capture/status/result/close frames, 108-second lifetime, 256-status limit and actual CWT peer ownership are unchanged.

`ExpectedBinding` must come from the trusted operator's independently checked protected records, rather than from a received selection as evidence of consent. Serialization and matching SHA-256 values establish byte commitments; they do not authenticate user permission, inventory origin, native results or resource custody. The current child inventory callback checks the live public source lease. The trusted native host must still bind and check the complete actual executable/command/resource inventory before original execution. An opaque native creator/client and complete create replies remain necessary for cleanup.

Eight generated binding/bootstrap tests and three actual parent/child cases are mandatory on each OS. The latter transfer four generated packets, reject copied/replaced peer objects, observe actual child exit37 and reject source-namespace drift. Their execution-inventory digest is a generated placeholder, not original execution evidence. On Linux the public PowerShell fixture is privately copied without changing shared installation permissions. No native target is invoked by these three transport cases.

This completes the separate private-channel entry, not the native target integration. The same generated PostgreSQL/immudb target must next exercise the new entry with a concrete host inventory before any already-consented original file is opened. Original credentials/PKI/provider/identity inputs are not added by this change.

## Native-host binding route under qualification

The native data-stage host accepts a separately supplied trusted `OriginalExpected` binding and selects the fixed original private entry. Before opening that peer it compares root/revision/image/probe/configuration against the host commitments and actual supplied image context. Missing fields or drift refuse use. The existing native target, result checks, original lifetime and owned cleanup remain shared. This branch still requires the concrete executable/command/resource inventory and generated same-target native rehearsal before original execution.

The mandatory `OriginalFourDataHostBinding.Tests.ps1` checks 24 refusals across normal, parent-loss and expiry modes. No peer is opened and no native target is called. The pre-existing 15 generated-callback root refusals remain mandatory. Windows fixture preparation resolves the temporary root before constructing metadata, preserving strict equality in the actual peer. A separate local regression passed all eight binding/bootstrap tests with a real distinct Windows 8.3 temporary-directory alias; the fix does not relax path checks.

## Observed native dispatch boundary

Observed Docker calls now parse only the fixed `exec` prefix, supported `-i`/`-d` flags and explicit `-e` entries. The target must have the canonical 64-hex shape; actual resource ownership remains separately established by the original live CWT/client/create reply. The 14 observed programs form a closed set. `dotnet` must enter `/tool/ServerBackendProbe.dll`; the shell branch accepts only the existing fixed configuration-write script. Environment purposes are limited to the actual HOME/encoding/TLS/app-name slots with fixed or bounded values; duplicate entries refuse use. These syntax checks never grant container, process or cleanup authority.

The existing mandatory native-process observation gate calls the shared command-shape and native-profile-forwarding tests. The latter extracts the real Linux forwarding branch, exercises 12 profile/failure-point/original-purpose combinations through an argv sink and reproduces the old scalar-splat error. Windows used a real Python argv sink. The isolated local Linux boundary check used an explicitly identified shell/PowerShell argv adapter because that cached image has no Python; actual Linux Python integration remains required in CI. Explicit array construction preserves `--original-purpose` as one argument.

The changed guard passed the normal generated native PostgreSQL/immudb/Server regression, with two PostgreSQL restores, audit four events/five transactions, two Server starts/stops and nine independent owned-resource absence checks. Earlier loss/expiry proofs predate this guard change and are not transferred to it automatically. Full per-purpose argv semantics, executable/runtime provenance and complete resource inventory remain open; this boundary does not authorize reading original backups or establish production readiness.

The PostgreSQL and audit dispatchers supply a literal role and compare the parsed Docker exec target directly with the ID obtained from their live opaque owner. Their role restricts the allowed programs and configuration slots. An owned ID elsewhere in argv or an environment value is insufficient. The mandatory process-observation gate runs the command catalog and actual dispatcher/backend-builder regressions on each OS.

| Boundary | Accepted cases | Refusal coverage |
| --- | --- | --- |
| Target position | 2 exact-target cases | 4 misplaced owned-ID cases |
| Role/program/slot dispatch, native calls stubbed | Role-appropriate PostgreSQL and audit calls | 4 cross-role program and 2 configuration-slot substitutions refused before native work |
| Actual dispatcher wiring, custody/native calls stubbed | 4 calls | 4 cross-role substitutions before native work; 2 old-membership mutants reproduced |
| Utility paths/options | 25 cases, including 19 configuration slots | 15 foreign path, option and signal cases |
| PostgreSQL utilities and daemon launch | 9 profiles: initdb, readiness, fast stop, 4 restores and 2 daemon launches | 102 changed, missing or extra arguments, including TLS/network settings |
| Actual backend builder, native calls stubbed | 2 launch/readiness profiles | Both builders must satisfy the command guard |
| immudb/immuadmin | 5 existing builders with exact Docker/environment/TLS/action argv | 75 argument mutations |
| ServerBackendProbe | 9 modes with fixed Docker/TLS prefix; only 2 expectation modes take pin/nonce argv | 24 mode, pin, nonce and extra-argument cases |
| Configuration/login private stdin | 22 file slots and 1 generated immuadmin login bound to the owner's immutable configuration | 92 changed/missing bytes, unknown-key and mutable-value-map cases refused before native dispatch |
| Restore private stdin | 4 captured-pin PostgreSQL/immudb verify/restore calls | 16 changed, wrong, missing bytes or missing-pin cases refused before native dispatch |
| psql | 5 profiles: 3 retained databases as postgres, late-refusal postgres probe, exact generated lock statement | 45 changed, missing or extra arguments |

These tests establish command-shape and dispatch regression boundaries. Restore archives are rechecked immediately before native dispatch against a read-only snapshot of the independently validated capture pins, including archive format and size. Synthetic-header tests establish byte/pin binding, not archive restore or source-origin acceptance. Configuration-file and immuadmin-login bytes are also compared at dispatch with the immutable owner configuration. These byte bindings do not authenticate SQL stdin or the original source of passwords/configuration, pin/nonce origin, daemon identity, original PKI, executable/transitive runtime provenance, live custody or independent cleanup. Those requirements retain separate acceptance evidence. Complete executable/command/resource inventory remains open before original backup execution; Phase 7 remains open.


### Generated external controller loss

`native_controller_loss.py` runs the existing generated original-purpose native
fixture in a surviving PowerShell owner. The Python controller owns only its
stdin write end; stdout/stderr remain connected to the root test harness. The
owner creates and removes its own PostgreSQL/immudb targets using the same live
CWT custody and original native client/create replies. No serialized IDs or
labels become removal authority.

The owner derives its actual OS parent, holds its original process handle and
birth/image observations, and admits only an opaque one-use pipe context. EOF,
unexpected input, parent exit or the original owner deadline revoke work;
neither rearming nor a new clock renews that context. These observations do not
authenticate the complete controller source/runtime origin.

The native fault is armed only after both recovery targets were created and
inspected, before native SQL/configuration work. The required Linux native job
tests EOF and termination of the root harness's actual held controller process.
The root harness holds a read-only OS observation handle for the owner, verifies
its terminal exit and independently checks ten exact resource absences, own
payload removal and preservation of the shared PostgreSQL base image. The owner
must refuse a late SQL request before dispatch and remove both targets once.
Portable process contracts also exercise live/EOF/unexpected-byte handling and
18 context/replay/sticky-loss refusals on Windows and Linux.

The existing 15-minute native job and fixture/native deadlines remain in force.
Run the focused native checks with `python3 -B
tests/Fleetory.Tools.Tests/native_controller_loss.py --powershell /path/to/pwsh
--case eof` and `--case death`, in the existing generated native fixture
environment. No original backups, retained credentials, PKI, provider or VPS are
used. This is a pre-work controller-loss rehearsal: active SQL interruption,
owner/creator death, unknown create outcomes, full original execution inventory,
original restoration and full-system RPO/RTO remain unverified. In particular,
`independentCreatorDeathCleanupVerified` and full recovery/Phase 7 flags remain
false. The existing normal, admission-loss and original-expiry jobs are retained.

A malformed test-controller request also revokes its pipe and waits for the
actual native owner; it must never kill that resource creator as a shortcut.
A failed root harness retains its public runtime and diagnostic directory when
owner exit/cleanup is unverified. Their retention is an explicit failure ledger,
not successful cleanup. A real child-process regression covers this path.


CI #443 for `11c9790` ended cancelled at the 35-minute strict-job boundary.
Six specialized jobs passed, but the second full .NET run was incomplete:
the log contains 1,043 completed Linux test executions, no native coverage
result and no submitted official Sonar analysis. This run is not accepted as a
complete code gate. No historic coverage percentage is assigned to it.

The actual Linux publication-fault check consumed 549 seconds in that run.
It now runs unchanged, with `--continuation-image --owned-cleanup`, in the
required `native-publication-faults` job. The job has its own pinned cold-runner
SDK/strict dependency-audit build, standard `ubuntu-24.04`, read-only repository
permission and a 15-minute limit. The existing 35-minute strict job, six other
specialized jobs and all their checks/deadlines remain. The aggregate requires
all eight execution jobs; omission, soft failure, a larger runner or a changed
publication deadline/bootstrap are rejected by layout regressions.

The repository remains public. Standard GitHub-hosted runners are free for
public repositories under the [GitHub Actions billing rules](https://docs.github.com/en/actions/concepts/billing-and-usage).
No artifact uploads, paid runners, visibility changes or billing-setting
changes are introduced; the Actions budget remains $0.


The first independent publication job in CI #444 exposed one implicit cold-runner
dependency: three initial fault cases passed, then the unchanged Docker preflight
refused the absent pinned Python base. The standalone job now explicitly pulls
`recovery_isolation.IMAGE` from its existing reviewed constant, with a 120-second
bound, before fault execution. It does not duplicate or replace the digest and
does not weaken local-endpoint, namespace, Engine-version or image checks. A
regression executes the actual workflow preparation against an empty image-cache
model, confirms preflight refusal before preparation and admission afterwards,
and rejects omitted, duplicated, floating-image or unbounded preparation.


CI #444's Linux pre-work EOF case passed (owner exit and ten absences), while
the death result was rejected by the verifier. A separate real-process Linux
reproduction showed EOF arriving after SIGKILL while the first parent exit
snapshot was still false; the same held parent subsequently reported exit.
The owner now refreshes its final snapshot from that original handle only after
owned target removal. This is a nonblocking observation, not a new admission or
deadline; sticky loss remains sticky and the required final parent-exit check
is retained. A portable actual-parent-death regression checks both snapshots and
refuses a final observation before loss. Generated native evidence is emitted in
bounded full form after validation so CI retains identities/source hashes and
actual cleanup results; mismatch diagnostics contain only fixed boolean names.
