# Bounded expectation compatibility diagnostics

`eng/pilot/audit_expectation_diagnostic.py` diagnoses a saved PostgreSQL audit
snapshot with the existing closed production-serialization probe. It does not
change the producer's admission rules or serialization. It reports fixed native
failure categories and advisory counts for seven source-shape profiles. No
source identifiers, strings, timestamps, context values, expected wire hashes
or keys are copied into the diagnostic. The caller's nonce and snapshot hash
bind the report to the measured invocation.

The controller accepts one immutable snapshot of at most 128 KiB and an external
SHA-256 pin. Existing archive validation admits exactly four ordered events and
zero pending exports. The module delegates exactly one native invocation to a
trusted, caller-owned runner; it has no process or connection API. The runner
must pin the probe, select only `audit-expectations`, bound its lifetime and
output, and retain no raw output. A bytearray input is frozen before the callback.
Callback exceptions are sanitized. Nonzero exit status alone cannot prove a
data rejection: exit 0 and 1 have separate, exact result contracts. Stderr,
unexpected exit types/codes, duplicate fields, output above 16 KiB, stale
binding, counters, malformed event metadata and authority claims fail closed.

Native error type, cause and location are mapped to fixed allowlists. Unknown
names become `OTHER` and cannot be echoed. Unclassified native errors are
explicitly incomplete diagnostics. Input, serialized-value bounds, capture
protocol and operational failures remain distinct. Advisory profile counts
are not an authoritative reimplementation of the native parser. They cannot
turn native refusal into acceptance. Even native success discards all expected
values and reports `originalExpectationsAccepted: false`.

`capture_diagnostic` uses the separate pinned
[source reader](PostgreSqlAuditExpectationSource.md): one selected source open,
then one native callback. Invalid callbacks fail before source access. Source
rejection cannot invoke the native callback. Other retained references are not
opened, and the native three-artifact selection is unchanged.

```powershell
python -B tests/Fleetory.Tools.Tests/audit_expectation_diagnostic_tests.py
```

Eighteen portable generated methods cover fixed error categories, operational
versus input failure, unknown-name redaction, malformed output, stale bindings,
authority mutations, frozen input, source-open/invocation bounds, advisory
profiles and absent file/process/socket effects in the pure policy. The native
expectation wrapper additionally runs seven generated source/probe cases: one
valid diagnostic, five input refusals and one serialized-value-bound refusal.
Generated fixtures and published payloads must be removed.

An original-data diagnostic needs a concrete new reason, a measured controller,
metadata/file pins, current gates, existing consent for those data and a separate
one-use ledger. Preserve a consumed failed operation; never reset its ledger or
silently retry it. This diagnostic grants no new permission and is not a
successful expectation derivation, native restore, signature verification,
service recovery or production acceptance. Original secret/PKI/provider access
requires its own current permission. Phase 7 remains open; PR, quality gates,
budgets, visibility, timeouts and TUX remain unchanged.
