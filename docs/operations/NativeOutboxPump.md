# Generated native outbox pump acceptance

`tests/Fleetory.Tools.Tests/NativeServerBackend.Tests.ps1` now extends the
[native Server component fixture](NativeServerBackend.md) with the actual
`IAuditWriter -> PostgreSqlAuditExportPump -> IAuditExportSink` chain. All data,
credentials and PKI are newly generated in the existing owned network-none
PostgreSQL/immudb/worker sandbox. No retained dump, original key/token/share,
VPS, source-root session or issuer is involved.

The probe resolves the exact internal pump type from the Platform assembly and
its actual application-DI registration. It invokes the fixed public
`ExportNextBatchAsync(int, CancellationToken)` entry point with batch size one.
No production visibility or implementation is changed for the probe. The HTTP
host and background `AuditExportWorker` remain unstarted during this pump-only
stage. A separate [worker lifecycle stage](NativeOutboxWorker.md) then starts the
registered exporter. Every direct pump call first
proves native PostgreSQL role/session/database identity and verified TCP TLS.

## Refusal, retry and acknowledgement

The real audit writer has already committed one generated event/outbox pair.
The operator fixture independently captures that PostgreSQL event's ten public
fields before invoking the pump. It verifies this sequence:

1. Without queue UPDATE, the real pump refuses its claim with PostgreSQL
   `42501`. The event, queue row and zero attempt count remain unchanged.
2. Grant UPDATE only on `audit_export_queue`. A native zero-row DELETE probe
   still fails with `42501`; immutable `audit_events` UPDATE/DELETE remain
   unavailable. With a wrong generated immudb password, the pump returns zero,
   retains the event/outbox, increments attempts to one, clears both lease fields
   and schedules the native two-second retry. An independent immudb scan proves
   that the pipeline event was not written.
3. Restore the valid writer credential and wait until the observed retry is due.
   Keep queue DELETE unavailable. The pump durably writes the event to immudb,
   but cannot acknowledge it in PostgreSQL. It returns zero, retains the outbox
   at attempt two, clears the lease pair and schedules the four-second retry.
   Independent readback must already find all ten event fields at revision one.
4. Grant DELETE only on the queue and wait for the observed due time. The real
   pump retries the same event, returns one and removes the acknowledged queue
   row. Its immutable PostgreSQL audit event stays byte-for-byte unchanged.
   immudb still has exactly one key/revision for that pipeline event.
5. Another batch returns zero. PostgreSQL remains event one/outbox zero and
   immudb remains unchanged.

The fixture's earlier direct-sink test has its own event ID. Independent scans
therefore expect two total audit keys: the direct-sink event and the one pipeline
event. Both must stay at revision one; the fixed event is also revalidated.
The pipeline event's ten fields are compared with the separately captured
PostgreSQL inventory, using timestamp values rather than textual date formatting.

Queue checks use a database-clock observation before each failed call and a
post-call observation to bound the native retry schedule. Polling waits at most
20 seconds for the observed due time. The fixture neither rewrites
`next_attempt_at` nor overrides a production clock, and it does not rely on a
fixed sleep being long enough.

## Evidence and limits

Five native pump calls cover the refused claim, two failed deliveries, one
successful acknowledgement and one empty batch. The output separately records
the two queue privilege refusals, two- and four-second schedules, cleared leases,
durable write before acknowledgement failure, ten cross-store fields, one
pipeline revision, two total keys at this stage and empty outbox. The subsequent
worker stage adds two separately verified events. Unclassified exceptions
or unexpected delivery counts fail the fixture. Credentials enter only through
private File-provider slots or bounded stdin; native output remains categorical
and checked for generated secret canaries. Existing runtime ownership, resource
limits, expiry and verified cleanup remain mandatory.

This proves synchronous generated-data delivery, rescheduling and deduplication
through the real pump. It does not prove process-crash recovery, multi-node lease
races, production background-worker operation, original credential/PKI admission,
signed immudb checkpoints, WORM, a coordinated original restore point or VPS loss.
Human login, physical Agent, independent custody/approvals and full RPO/RTO remain
open. Phase 7 is incomplete and PR #2 is not merged.
