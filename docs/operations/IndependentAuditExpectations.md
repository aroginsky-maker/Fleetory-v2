# Independent audit value expectations

Before a retained audit is observed, expected event values must come from an
independent source. Hashing the same immudb `Get` response being checked would
only establish self-consistency. The new producer accepts a pinned PostgreSQL
audit snapshot and uses the existing production `ImmudbAuditExportSink` to obtain
the exact serialized key/value expectations, without contacting immudb.

`ServerBackendProbe audit-expectations <snapshot-sha256> <nonce>` reads the
snapshot from bounded stdin. The pin and canonical nonzero UUID nonce are
separate arguments; paths, endpoints, credentials and observed values are not
accepted. Input is at most 128 KiB. Its exact byte hash must match before parsing.
The fixed `fleetory.audit-snapshot.v1` profile requires four sorted unique
canonical event IDs and zero pending export rows. It does not assert that the
native archive has four keys or four transactions.

Each row has exactly ten PostgreSQL fields: event ID, actor subject/kind, action,
target type/ID, correlation ID, occurred/recorded times and context JSON. Duplicate
or extra fields, noncanonical integers, invalid actor kinds, incomplete targets,
text/UTF-16 length violations and NUL characters are refused. Timestamps follow
the existing SQL export's UTC `Z` format with exactly six fractional digits;
unsupported precision or offsets are refused rather than guessed. Context is
null or a JSON object of strings, with unique keys, sixteen entries at most,
64-character keys, 1024-character values and a 16 KiB UTF-8 JSON text bound.
Null and empty contexts remain distinct.

The production sink runs with an injected `AuditExpectationCapture` handler.
This handler has no delegating handler or network fallback. It accepts only four
fixed in-memory requests per event: synthetic login, database selection, the
conditional set, and synthetic readback of the captured set. No host is started
and no real backend is contacted. Generated credentials and the synthetic token
are internal to this memory exchange; source credentials are not consumed.

The captured wire value is checked semantically against all ten original source
fields, independently of the reconstructed event model. Its context property
order must match ordinal UTF-16 ordering, including supplementary Unicode keys.
The exact serialized bytes are then hashed, preserving the production sink's
escaping, date formatting, property order and null behavior. No second serializer
is introduced into production. Values larger than the observer's shared
8192-byte limit receive a distinct typed profile-bound refusal; source-format
refusals and operational/capture failures remain distinguishable.

Output contains the source snapshot hash, nonce and four known-event key/value
digests with expected revision one. It is compatible with the
[bounded observer](BoundedAuditObservation.md)'s expectation frame; the signed
native point and producer measurement remain the caller's separate bindings.
Raw event values are not emitted. The producer keeps source-origin and
source-independence authentication, signature verification, execution authority
and full-system recovery false. An externally supplied pin is a declaration; it
does not authenticate a PostgreSQL origin, MVCC window, capture time or custody.
Using current production code also does not prove that a retained deployment
used that serializer revision; establish compatibility and provenance separately.

Run the generated contract on Windows or Linux:

```powershell
./tests/Fleetory.Tools.Tests/AuditEventExpectations.Tests.ps1 -Python python3
```

The wrapper explicitly restores its probe project before publishing, so the step
also works in a clean checkout before other native fixtures. It publishes and
measures the native probe, invokes nineteen generated
contract methods and removes its owned public payload. Tests include independent
ASCII golden wire hashes, every field's effect on the expected value, Unicode
escaping and ordinal context order, microsecond timestamps, null/empty context,
stale/mixed byte pins, UUID/count/order/type/length/duplicate/depth/UTF-8/bound
refusals, invariant culture/timezone behavior, sanitized output and strict CLI
arity. A synthetic five-transaction point checks frame compatibility only; no
native audit is observed in this test. Unrelated .NET/native local suites and
closed original recovery operations need not be repeated. Production/test C# is
unchanged; changed probe code is built, published and executed.

The separate [PostgreSQL source reader](PostgreSqlAuditExpectationSource.md)
now exercises export selection, pinned extraction and the producer's golden
values on generated data. Before original execution, that separately
scoped reader must bind already permitted source records, ordinary-file and byte
pins, independent lineage and the specific missing-evidence purpose to a
measured owned isolated plan. The [audit-only byte adapter](AuditArchiveInput.md)
does not itself provide these event expectations. Existing application/audit
data consent is preserved; consumed secret/PKI/provider permissions are not
renewed. Original key continuity, unknown native state review, original services,
independent WORM/custody/approvals and complete RPO/RTO remain open. Phase 7 remains
incomplete and PR #2 remains draft/unmerged. Quality gates, budget, visibility,
runners, timeouts and TUX are unchanged.
