# Generated native outbox worker lifecycle

`tests/Fleetory.Tools.Tests/NativeServerBackend.Tests.ps1` extends the synchronous
[pump acceptance](NativeOutboxPump.md) with the actual registered
`AuditExportWorker : BackgroundService`. It selects exactly one instance of the
fixed worker type from the production application's `IHostedService` registrations.
The fixture calls that instance's `StartAsync` and `StopAsync`; it never calls the
pump directly in the worker cases. The HTTP host, other hosted services and issuer
remain unstarted during these worker cases. A later separate
[HTTP host stage](NativeServerHost.md) starts the complete application.

The existing fresh PostgreSQL/immudb/worker sandbox, generated TLS, File-provider
slots, strict role/transport checks and verified cleanup are retained. No original
dump, credential, PKI, provider share/token or VPS access is involved.

## Four worker processes

1. The real audit writer commits a new `Fixture.Worker.Read` event/outbox pair.
   A peer administrator ages only that disposable queue entry by six minutes.
   Neither the production clock nor `next_attempt_at` is overridden. The actual
   registered `audit_export_backlog` health check must report `Degraded`.
2. Revoke queue UPDATE and start the registered worker. A private logger provider
   observes one categorical PostgreSQL failure from that exact worker category;
   it stores no formatted log text or exception. Stop the worker while its native
   error-delay path is active. Independent reads require an unchanged queue at
   attempt zero and no immudb key for the event.
3. Restore queue UPDATE and start a new native process with a wrong generated
   immudb credential. Observe the actual worker leave attempt one with both lease
   fields cleared, then stop it. The backlog remains degraded and the event must
   still be absent from immudb. The valid credential is restored in `finally`.
4. Start another native process with the valid credential. Poll observed queue
   state while the unmodified worker waits for its native retry and drains the
   event. Stop it and require a completed, non-faulted execution task. Backlog
   health must now be `Healthy`. In this same process, use the real audit writer
   to enqueue `Fixture.Worker.AfterStop`; it must remain unclaimed beyond the
   ordinary one-second worker poll interval. A fourth worker process then starts,
   drains that event and stops, with healthy backlog and an empty final queue.

Every stop has an independent five-second deadline; completing `StopAsync` alone
does not pass unless `ExecuteTask` has also completed without fault. Normal
cancellation is allowed. Four distinct native process IDs bind the restart proof.
The global probe deadline, bounded external process timeout and independent
container expiry remain in effect.

## Independent evidence

Administrator readbacks verify queue counts, attempts and cleared leases after
each stopped process. Only PostgreSQL queue metadata is used by the real backlog
health check. Independent immudb scans/readbacks verify the exact full key set,
revision one and all ten PostgreSQL event fields. The direct-sink event and prior
pump event are revalidated along with both new worker events: four total keys.
All three immutable PostgreSQL events must remain unchanged, including the event
created after worker shutdown.

The worker-stage result reports four starts/completed stops, maximum observed stop duration,
claim failure, retained sink failure, degraded-to-healthy backlog, post-stop
quiescence, new-process delivery, two worker revisions, four final audit keys and
zero queue rows at this stage. The later host case adds a fifth key. Secret
canaries must be absent from probe output.

This worker-only proof does not establish generic-host/Kestrel startup, HTTP readiness routing, process
crash or multi-node lease races, original credential/PKI admission, post-restore
human login, common capture point or whole-VPS recovery. Independent WORM/key
custody/approvals, physical Agent/current revocations and full RPO/RTO remain
open. Phase 7 is incomplete; PR #2 stays draft and unmerged.
