# Read-only historical audit expectations

`ServerBackendProbe audit-history-expectations <snapshotSha256> <nonce>` is an
explicit comparison profile for four ordered audit events with exactly one
literal null member inside an object context. It preserves that null value;
it does not delete the member or replace it with an empty string or `"null"`.
The ordinary `audit-expectations` command continues to reject null members.
Production writer and export-pump code are unchanged.

The profile shares the existing 128 KiB input bound, SHA-256/nonce binding, exact
ten-field mapping, canonical nonzero UUID/order checks, UTC microseconds, zero
pending count, actor/target/text validation, 16 KiB context bound, 16-member
limit, key/value limits and 8192-byte serialized-value limit. Other member
types and non-object JSON context roots remain rejected. Zero or multiple null
members do not match this specific profile. There is no JSON or environment
switch that widens the strict command.

After validating context shape and bounds, deserialization uses the same
`JsonSerializer.Deserialize<Dictionary<string, string>>` operation as the
production PostgreSQL export pump. Exact production sink serialization runs
through the existing closed in-memory HTTP handler. All ten fields have an
independent source-row witness. Context keys retain ordinal ordering. No
database, file source, real backend, host, identity issuer or original signing
key is opened by the producer.

The response has its own category `audit-history-expectations`, schema
`fleetory.audit-historical-expectations.v1` and profile
`historical-one-null-member-readonly.v1`. It contains four known-event hashes
and reports the preserved null count. `historicalComparisonOnly` is true;
`strictContextValueTypesCompatible`, `writerAdmissionVerified`,
`stateMutationAuthorized`, `originalExpectationsAccepted` and all origin,
independence, signature, execution and full-recovery authority flags are false.
These hashes are for read-only recovery comparison. They do not prove that a
record could pass the current writer, explain its creation or authenticate a
deployed image or source. The strict diagnostic contract rejects this response.

The [historical observation protocol](HistoricalAuditObservation.md) preserves
these limitations when binding known hashes to a bounded native audit read.

The native expectation wrapper runs fifteen generated historical methods on
Windows and Linux, in addition to the existing strict and diagnostic contracts.
An independent ASCII golden vector checks the exact bytes of all four values,
including the literal null. Tests distinguish missing, empty and text null,
preserve Unicode ordering and SQL NULL context, reject every other member kind,
keep all existing bounds, verify strict-mode rejection and authority separation,
and exercise the scoped generated source with cleanup. No original data are
test fixtures.

An original use needs a distinct purpose, current gates, code/probe/input pins,
existing consent for those data and a separate one-use ledger. It must preserve
earlier consumed operations and store only private metadata outside Git/logs.
This profile does not authorize an original read, native restore or service
operation by itself. Original native observation, unknown additional state,
independent custody/WORM/approvals, source creation/provenance and full RPO/RTO
remain separate controls. Phase 7 remains incomplete; PR #2 stays draft and
unmerged. Existing thresholds, exclusions, timeouts, budgets, visibility and
TUX are unchanged.
