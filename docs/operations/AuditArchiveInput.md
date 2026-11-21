# Audit-only pinned byte capture

`eng/pilot/audit_archive_input.py` is the byte boundary between the accepted
[native input selection](RetainedNativeInputSelection.md) and a future native
audit observation. It captures only the `audit-immudb` reference. The application
and signer dump references remain metadata; identity, provider and auxiliary
export artifacts are outside this capture's purpose.

The caller supplies the exact selector report and an independently retained
SHA-256 pin. Before any filesystem access, the adapter freezes the metadata
buffer and pin, verifies the digest, and reconstructs the selector's full report.
The three native kinds, order, path profile, distinct paths/digests, sizes,
metadata pins and all scope/authority flags must match. False flags cannot be
substituted with numeric zero. A selector report is a declaration, not permission
to read a new category of data or execute a recovery.

The invoking operator owns the filesystem root. The CLI uses its current
directory and accepts no root/path override; the bounded selector report arrives
on stdin. At the actual open, the adapter reuses `recovery_files.rooted` and
`inspect_file`, preserving ordinary-directory checks, lexical and canonical
containment, descriptor identity, no-follow/reparse rejection, single-link
regular-file checks, and size/state checks across streaming reads. Windows
opens deny write/delete sharing and validate the handle's final path; POSIX uses
root-relative descriptors and no-follow directory/leaf opens. The existing broad
six-component verifier is never invoked.

Only the selected audit file is opened, with its declared length as the read
bound and an absolute maximum of 8 MiB. Its exact size and SHA-256 must match,
and the bytes must begin with `IMMUBACKUP`. The immutable library result retains
those bounded bytes in memory. This magic check does not verify a native
checksum, transaction content or signature. The CLI emits a receipt without raw
archive bytes or paths. Parser errors are sanitized too, including attempted
root overrides.

```powershell
python -B tests/Fleetory.Tools.Tests/audit_archive_input_tests.py
```

Dedicated Windows/Linux CI steps run seventeen synthetic methods. They cover
opening exactly one artifact with absent unrelated artifacts, scope and type
mutations, mixed/stale metadata, traversal and relabelled excluded paths,
same-size byte corruption, wrong magic after a matching digest, hardlinks,
reparse leaves/parents/roots, a leaf swap at the open boundary, a borrowed root
descriptor, growth during reading, Windows short-root aliases, frozen caller
buffers and sanitized CLI output. The capture path is also exercised with the
broad verifier, process and socket APIs disabled. Synthetic files stay within
the fixture's temporary directory; no native service or Docker resource is
created by these tests.

This step does not open an original archive or repeat an original restore.
It neither changes the accepted selector pins nor renews consumed secret/PKI or
provider permissions. Unchanged local native/.NET suites need not be repeated;
the retained production coverage remains applicable because C# is unchanged.
The new contracts and exact-revision static analysis still run. Quality gates,
exclusions, runners, timeouts, repository visibility and the Actions budget are
unchanged.

The [independent event-expectation producer](IndependentAuditExpectations.md)
now exercises exact production serialization from generated pinned PostgreSQL
snapshots through a closed in-memory handler. It has not consumed original data
or authenticated source lineage. Before original native execution, bind known
event IDs and value expectations independently from already permitted
application/audit data; do not use the same audit `Get` results as their own
expected digests. Establish the specific missing-evidence purpose and applicable existing
data consent. A measured owned isolated target may then consume frozen bytes
within that authority; the [bounded observer](BoundedAuditObservation.md) must
retain additional state as unreviewed. This adapter has no process, socket,
restore, credential or host-start API. Original key continuity, complete logical
keyspace review, original services, independent custody/WORM/approvals and full
RPO/RTO remain open. Phase 7 remains incomplete and PR #2 remains draft/unmerged.
