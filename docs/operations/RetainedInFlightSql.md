# Bounded in-flight SQL cancellation

`NativeServerPair.Tests.ps1 -Profile v2-retained-inflight -Python <python>`
uses four frozen generated inputs and creator-owned PostgreSQL/audit resources.
It restores both databases and the audit archive before issuing one uniquely
marked `pg_sleep` query. No original input, source VPS, private PKI/provider
material, production token or issuer is used. This is a distinct single-case
profile, separate from the six-case strict/historical Server profiles.

Observed Docker calls are restricted to the `exec` purpose; create/run/build
requests are refused before client launch. This guard grants no resource
ownership: the retained caller must still hold its original native custody.

The existing bounded binary native helper accepts an optional trusted process
observer. No observer is supplied by JSON or retained data. Default callers
retain their original path. The observer receives the actual `Process` returned
by the helper's own launch and a cancellation token from the original native
timeout. It is called periodically while the operation runs and again before
the final result is accepted. Successful observer output is discarded. Expired
observer returns and observation failures are refused; existing native cleanup
then terminates that launched process. Fixed observers must use the token for
their own blocking I/O; this is not a facility for untrusted callbacks or a hard
real-time guarantee.

The retained observer checks its held coordinator through the fixed bounded
work-status exchange. It preserves the existing 15-second native budget,
90-second recovery work limit, 105-second supervisor and 108-second transport
limits, plus the 256-status-frame bound. No process or resource is adopted from
a serialized PID, name, label, birth record or report.

The fault is injected only after PostgreSQL reports exactly one matching active
query waiting in `PgSleep`, while the launched Docker client remains live. Its
original birth identity is checked through a second local process observer.
Only then does a projection-bound, fixed-purpose frame ask the surviving
supervisor to close its own held coordinator fence. Other flows and altered
projections cannot use this frame. The actual nonzero coordinator exit and
whole-fence absence proof are required before the observer refuses the operation.

The native client must be observed exited after cancellation. A fixed later SQL
request must be refused before native dispatch. Cleanup removes the owned audit
child before its PostgreSQL parent, then the owned untagged image. Existing
copied-claim and removal-replay refusals remain required. The profile emits only
its own measured claims: it does not claim the separate lease-expiry or
inspection-boundary cases were executed by this single-case profile.

On Linux, observed work uses `/usr/bin/docker` directly under the runner identity,
with a newly created private empty client-config directory and the fixed local
Unix socket. A shell/sudo PID is not substituted for the client. Ambient API or
custom-header overrides are refused. The temporary config directory is removed
without recursive deletion. Existing unobserved calls retain their prior wrapper.
Windows retains the configured `desktop-linux` endpoint. Per-OS runtime evidence
is recorded separately; a Windows execution does not prove Linux behavior.

Seven native process tests run on Windows and Linux in required CI steps. They
check normal/final observations, actual live-process cancellation, preservation
of another held process, final-result refusal, default calls and original
deadline-token behavior, including an expired observer that returns normally.
Eight additional purpose refusals check creation/build, null/empty/case and incomplete exec requests.
Portable protocol tests separately cover flow/projection/held-identity refusal.
The three retained native profiles run in a dedicated required 15-minute Linux
job with a cold probe restore; all original jobs and deadlines remain required.
The aggregate requires all six execution jobs, including the new lane.

This proves the tested generated SQL/client interruption and resource cleanup.
It does not prove interrupted `pg_restore`/immudb restore, SQL rollback on client
disconnect, arbitrary in-flight application transactions, native creator death,
unknown create outcomes, Docker daemon or host loss. The creator remains alive
to perform cleanup. Original service/configuration/provider/PKI continuity,
independent custody/actors, human login, physical Agent and full RPO/RTO remain
open. Phase 7 is incomplete and PR #2 remains draft/unmerged.
