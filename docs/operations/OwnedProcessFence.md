# Owned process identity and lifetime fence

`eng/pilot/audit_process_fence.py` authenticates an actually created child image
and OS birth identity before releasing bounded input. It adds a consumed launch
attempt to the [held control identity](AuditControlIdentity.md). Reservation,
launch attempt and the separate PID assertion are exclusive, flushed records.
Neither record grants permission or authenticates external CI, consent or data.
A failed spawn or lost response cannot obtain a second launch from that session.

The public `native_refusal_probe` has one fixed entrypoint and argument model:
the existing `Invoke-HistoricalAuditObservation.ps1`, pinned PowerShell/Python
locations supplied by trusted host configuration, one expected native-plan hash,
and a constant malformed admission packet. It accepts no caller-selected packet,
command, arguments, environment, endpoint or root CLI. The actual native owner
must return its typed pre-admission refusal, before payload/container creation.
This is an actual owner-startup contract, not a positive restore or backend
cleanup acceptance. Its full transitive toolchain, source bundle and backend
probe are not authenticated by this startup probe; those remain integration work.

Runtime and entrypoint files are canonicalized from trusted host locations,
checked as ordinary single-link files, hashed with a 64 MiB bound and retained
through checked read-only descriptors and parent-directory identities. Windows
denies write/delete sharing. Linux executes the held runtime through its passed
descriptor and compares the observed process image's device/inode with that pin.
Pins are checked again after creation and before input release. This assumes a
trusted host account and installed runtime dependencies, not an adversarial
administrator or an authenticated software supply chain. Runtime dependency and
transitive-code continuity flags remain false.

Windows observations use the owned process handle, `GetProcessId`,
`QueryFullProcessImageNameW` and `GetProcessTimes`. A new unnamed,
non-inheritable Job Object is assigned before input; its actual limit flags are
queried and must be exactly `KILL_ON_JOB_CLOSE`, with no breakaway flags.
Cleanup terminates that job and queries zero active members. Ordinary
`CreateProcess` descendants inherit the job. Broker/service-created processes,
including Docker-daemon containers, are outside this acceptance scope. The
[Windows Job Object contract](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
describes this boundary. Kill-on-close is configured; this suite does not claim
to have tested abrupt death of the supervisor itself.

Linux uses a new session/process group, an owned pidfd and the observed
`/proc` image/start token. Exit is observed with `waitid(..., WNOWAIT)` so the
owned leader is not reaped before group cleanup. Its birth/group/session are
checked again before signalling; an unrelated recycled group ID is not used.
After `SIGKILL`, selected `/proc` state fields verify no running members in that
owned session/group. Zombie entries are counted separately. A process group
does not prevent session escape and has no automatic kill-on-supervisor-death
guarantee here; both flags remain false. The fence covers trusted children that
remain in the owned group. It never signals a guessed or scanned PID.

Input is frozen and bounded to 128 KiB, stdout to 256 KiB and stderr to 4 KiB.
The private primitive has an integer deadline up to 600 seconds; the fixed
pre-admission probe uses 30 seconds. Existing native600/container660/fixture3300
limits are unchanged. The OS creation syscall itself cannot be interrupted by
this loop; no input is released while it is pending. Bounded pipe pumps begin
only after OS observations, pin checks, fencing and control binding. Owner exit
also triggers fence termination, including descendants still holding pipe ends.
Timeout, input backpressure and output overflow retain the consumed attempt;
exception categories contain no input or output contents. The environment is a
fixed trusted-host allowlist; Docker endpoint overrides, `PYTHONPATH`, tokens and
unrelated caller variables are not inherited.

The result separates the authenticated OS process/fence evidence from opaque
application bytes. Nonzero child exit is not success of the application. Native
payload/result acceptance, backend namespace/cleanup, transitive code/runtime
dependencies, gate origin, data consent, original-key continuity, launch
authority and full-system readiness are not promoted. A native backend could
survive outside the process fence; backend cleanup still requires its own known
namespace, immutable ownership and independent absence checks.

```powershell
python -B tests/Fleetory.Tools.Tests/audit_process_fence_tests.py
```

CI requires 19 actual generated process contracts on each OS: image/birth
observation before input, a flushed one-use launch attempt, failed spawn,
claim/binding/pin refusal, an actual impostor image, deadline and backpressure,
typed stdout/stderr bounds, owner death and descendant termination, preservation
of a foreign process, environment filtering and the actual fixed native-owner
pre-admission refusal. Tests use synthetic bytes and no original files, private
PKI, source VPS, provider root or issuer. No generic process CLI is provided.

The next integration must measure the complete approved toolchain/code/probe,
bind the native owner's payload and resource intents to retained control
identity, and prove actual owner death after container creation and after
restore with ownership-checked backend absence. The existing eight-case fixture
needs distinct child nonces before deterministic payload/image names are added.
Original audit dispatch still requires current authenticated gates, original
public checkpoint trust and the existing consumed audit-only transaction. This
component creates no new original-data, secret, private-PKI or provider scope.
Phase 7 remains open; PR #2 stays draft and unmerged.
