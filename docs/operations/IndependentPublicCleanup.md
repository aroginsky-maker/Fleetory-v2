# Independent cleanup of fixed public test workers

The fixed `PublicCleanupGuard` owns a separate idle controller process and one
network-none public Python sleep container. The guardian remains alive when the
controller exits. It enforces a three-second test lease independently, then
removes only its own full immutable container ID after a fresh runtime check.
This profile is separate from the retained native publication controller and
does not extend the original-service recovery permission.

The trusted host supplies the repository and an already protected operator
directory. Sixty-one fixed public source inputs, the current Python executable
and the local Docker CLI are held and checked. The controller runs a fixed
entrypoint with `-I -B`, no caller command or argument vector. Before readiness,
the guardian obtains its actual owned process birth/image using a Windows Job
or Linux unreaped leader/pidfd fence. The controller checks its actual parent
and self through retained read-only OS process objects. The guardian retains
the sole stdin writer; EOF releases the otherwise idle controller.

Three exclusive-create, flushed records are retained: start before any controller
or container creation; ready after the exact successful Docker create reply and
fresh observation; cleanup before inspection/removal. A reused nonce, partial
record, failed write/flush, failed validation or lost response cannot retry or
reset that stage. The private record primitive is shared with the existing
eighteen consumed-attempt contracts. Windows directory ACLs, privileged
tampering, deletion/restoration of the ledger and independent anti-rollback
storage remain outside this local proof.

The guardian selects the already cached pinned public `recovery_isolation.IMAGE`,
resolves its immutable image ID and uses `--pull=never`. It supplies the name and
five labels binding nonce, profile, public source pins and real process
identities. It never adopts a name, caller-selected ID or wire receipt. Inspection
requires its complete create-returned ID, exact image ID/name/labels/creation
window and fixed runtime parameters. Only then can `container rm --force` receive
that ID. A bounded subsequent lookup must observe absence. Every Docker RPC has
bounded output and an eight-second timeout; failed or ambiguous calls stay
consumed. No broad prune, label/name sweep, foreign process signal or Docker
socket mount is used.

The fixed worker has UID/GID 65534, a read-only root, no network, mounts, ports or
credentials, ALL capabilities dropped, no-new-privileges, 64 MiB memory, 0.25 CPU,
32 PIDs, no restart and automatic removal. Its fixed command exits after thirty
seconds. This passive fallback is tested separately by killing the guardian:
the idle controller exits and the worker eventually auto-removes without a
cleanup executor. It is not a general independent supervisor-death cleanup
guarantee. Docker/host failure, a paused worker, malicious replacement and the
pre-receipt create crash gap remain unverified; no success is inferred from an
unknown result. The active action uses both wall and monotonic deadlines, refuses
clock rollback and has a bounded reaction window.

Portable contracts require exact runtime fields, integer resource limits,
unknown/duplicate JSON key refusal, full IDs, canonical UUIDs, fixed launch
arguments, source-pin refusal, durable stage consumption, flush failures,
restart refusal, lost/wrong removal replies, pre-action flush failure, clock rollback and actual controller identity/EOF/parent
refusal on Windows and Linux. The mandatory Linux Docker gate verifies live
controller expiry, actual controller death, immutable-ID deletion, restart and
cleanup replay refusal, foreign-observation refusal without touching the
sentinel, and passive worker exit after actual guardian death. Local Docker
Desktop runs the same native fixture. Original inputs, private PKI, provider,
VPS and production credentials are never used.

This result closes only the fixed public-worker cleanup rehearsal. Integrating
the retained publication controller, real services, provider/PKI/revocation,
post-restore human login, physical Agent, complete RPO/RTO and independent
WORM/custody/approvals remains open. Phase 7 and draft PR #2 remain open.
