# Read-only cleanup supervisor handoff

Baseline section 17 still needs an independent cleanup enforcer before real
service recovery can depend on a lifetime bound. This step verifies one smaller
boundary: a fixed Python worker observes its actual controller parent and itself,
then binds the exact bytes of a generated asserted create receipt to that exchange.
No Docker operation is available in this worker.

`audit_supervisor_identity.py` selects only the current process or its actual OS
parent. The wire PID must match that selection before opening an OS object.
Windows retains a non-inheritable process handle with query-limited-information
and synchronize rights; creation FILETIME and the pinned executable path/hash
must match. Linux retains a non-inheritable pidfd, checks `/proc` start ticks and
executable device/inode against the held executable descriptor, and rechecks
liveness. A changed caller after fork cannot use an existing observer. Closing an
observer closes its own handle/pidfd without signaling a process or closing the
caller's executable pin.

`Observe-CleanupSupervisor.py` accepts one bounded stdin JSON frame, with exactly
47 named source pins and immutable base64 ticket/receipt/resource bytes. It has
no command arguments or caller-selected path. Its repository root comes from the
fixed script location. Both peers must use the pinned Python entry executable;
the worker checks its actual parent, its own birth/image identity, the ticket
hash and the cleanup protocol's complete receipt/resource consistency. The
parent holds all source pins while it starts the fixed worker under the existing
OS lifetime fence and sends the frame. The worker rechecks those pins and both
live OS identities before returning its bounded result.

This is a read-only observation at the handshake, not continuous supervision.
The Python interpreter, standard library and already-imported modules remain
part of the trusted host; these file pins do not establish an authenticated
interpreter/import closure. The parent fixture supplies generated receipt and
resource assertions. Hashing those bytes proves transport binding, not a
successful Docker create or ownership of any actual resource. The underlying
metadata model still reports `actualProcessIdentityVerified=false`; the separate
handoff result reports the actual OS observations without upgrading that model.

`supervisor_identity_tests.py` contains eight contracts for held self identity,
PID rejection before opening, birth/image mismatch, closed schemas, observer
closure, returned-value mutation, wrong OS-token kind and forked caller refusal.
`native_supervisor_observation.py` starts six real fixed workers: one accepted
handoff and five refusals for controller PID/birth, supervisor birth, source pin
and receipt mutation. Input/output and execution time are bounded; each owned
worker is fenced and its process members are verified absent afterward. The
fixture temporarily supplies the unchanged CI SDK selector only when absent and
removes its own copy. Both test gates are mandatory on Windows and Linux.

No actual resource is created or removed; no original input, secret, private PKI,
provider or VPS is accessed. Independent supervisor lifetime, actual create
receipt origin, durable attempt consumption before action, immutable-ID resource
reobservation, expiry/controller-death cleanup and cleanup after supervisor death
remain open. Operational leases, full recovery, Phase 7 and PR #2 remain open.
