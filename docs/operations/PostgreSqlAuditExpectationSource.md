# Scoped PostgreSQL audit expectation source

`eng/pilot/audit_expectation_source.py` selects the saved `audit-export` for a
specific event-expectation purpose. This is separate from the three native
application/signer/immudb references; that native selection is not broadened.
Existing audit-data consent is not revoked by excluding an auxiliary export from
the native-archive capture purpose.

The reader freezes two bounded metadata packets and their external SHA-256 pins:
the retained six-reference manifest and the historical offline audit checkpoint.
Only the manifest's `audit-export` entry may be opened. All manifest references
receive the existing lexical/type/unique-path/hash checks, but other files are
not inspected. The selected path must have the fixed audit-export profile. The
checkpoint's size, export hash, observation/event counts, last receipt hash and
historical status/limit fields must match. Those historical declarations remain
operator metadata, not new custody or origin authentication.

The operator owns the root. CLI input cannot replace it. The checkpoint's
absolute path is compared component by component with the selected path under
that root; it is never resolved or opened independently. On Windows, valid long
and 8.3 names are obtained only from already checked operator-root prefixes.
Mixed short-ancestor/long-leaf paths do not require following metadata paths or
accepting another root. The actual file is opened through the existing
rooted descriptor, ordinary single-link file, no-follow/reparse, canonical
containment, size/state and streaming-digest guards. The declared size is the
read limit, with an absolute 1 MiB export bound. The broad six-file verifier and
source-host/archive capture routines are never invoked.

The new consumer validates the frozen export's receipt chain, its pinned final
receipt, snapshot binding, four-event profile and zero pending count. It extracts
an immutable canonical PostgreSQL snapshot of at most 128 KiB, preserving all ten
source fields and the exact `context_json` string. This feeds the separately
validated [production expectation producer](IndependentAuditExpectations.md).
Source-format details unsupported by that producer still fail closed there.
Raw events stay in memory; CLI output is a metadata receipt without paths or
event bodies.

The reader reports matched operator metadata pins, not authenticated source
origin, independent administration, WORM, signatures, current freshness, global
atomicity or execution authority. Historical restore checks are reused; this
source extraction does not repeat an original restore or crypto operation.
The producer's own source-origin/independence flags remain false. Known values
come from the selected PostgreSQL export, not the immudb `Get` being checked.

```powershell
python -B tests/Fleetory.Tools.Tests/audit_expectation_source_tests.py
```

Seventeen portable synthetic methods cover one-file-only access, frozen metadata
and pins, wrong/stale metadata, excluded-reference relabelling, absolute-path
mismatch, false readiness promotion, changed bytes, broken receipt/snapshot
bindings, event counts/order/duplicates/pending state, input bounds, links,
replacement at open, root-descriptor mismatch and sanitized CLI output. The
capture path is exercised with the broad verifier, process/socket APIs and
source capture routines disabled.

The existing native expectation wrapper additionally runs a generated source
export through this reader and the published producer, compares all four exact
ASCII golden values, and verifies cleanup. The two source and native payloads
are disposable generated fixtures. Local successful backend/.NET suites and
closed original recoveries need not be rerun; required CI/static gates remain.

Before an original-data use, preserve a concrete purpose, the metadata/file pins,
existing audit-data consent, measured code and bounded process plan. A single
read of the already permitted static export can compute new expectations without
contacting a VPS, restoring a database or reusing private PKI/provider material.
Keep resulting private metadata outside Git/logs/chat. Compare serializer source
blobs against the retained deployment's declared source separately. Source-byte
equality does not authenticate the deployed image/build inputs or establish
original key continuity. Native observation, unknown additional state review,
original services, independent custody/WORM/approvals and full RPO/RTO remain open.
Phase 7 remains incomplete; PR #2 stays draft and unmerged. Gates, budgets,
visibility, runners, timeouts and TUX remain unchanged.
