# Fresh native immudb data roundtrip

This closes a bounded audit-only rehearsal for Baseline section 17. It does not
start a restored Fleetory Server or read the retained original audit backup.
Run `tests/Fleetory.Tools.Tests/NativeImmuDataRoundtrip.Tests.ps1` with PowerShell
7.3+ and a Python interpreter. Linux CI runs the actual native exercise; Windows
and Linux run 19 portable refusal cases.

The fixture builds a UUID-labelled COPY-only image from pinned immudb 1.11.2,
immuadmin 1.11.2 and the existing .NET runtime. Two independent containers have
network none, no mounts or published ports, UID/GID 3322, read-only root,
cap-drop ALL, no-new-privileges and fixed memory/CPU/PID/core limits. Data and
private files use the existing audit tmpfs profile. Public probe code enters the
COPY-only image through a bounded context containing only Dockerfile/publish,
before any private fixture material is generated; no host code bind is needed.

All material is freshly generated: separate source/target administrator and reader
passwords, TLS server/client credentials and a P-256 state-signing key. The signing
key is shared only between these disposable fixtures to verify continuity; no
original key custody is exercised. Private values travel through bounded stdin
and mode-0600 tmpfs slots, never argv or logs. TLS verification uses the generated
CA, a fixed loopback hostname and a client certificate for the CLI. Container
identity and runtime constraints are rechecked before operations.
CLI login sends exactly the generated password bytes without a newline: the
[upstream pipe reader](https://github.com/codenotary/immudb/blob/v1.11.2/cmd/helper/terminal.go)
consumes all stdin bytes verbatim. Authentication failure does not trigger a reset
or fallback password.

The source gets four fixed synthetic ten-field audit values in `fleetoryaudit`
(four transactions). This differs from the retained original five-transaction
point; the original backup is not opened or reused here.
Native `immuadmin hot-backup` emits transaction bytes to a bounded private pipe.
The generated-only capture helper passes these through the actual two-input
immutable admission API, replaces its temporary files and proves that a subsequent
load fails while captured bytes remain unchanged. Its other input is explicitly
a non-native PostgreSQL placeholder. Its component report graph is a policy-shape
fixture, not a measured original inventory or external approval. Neither capture
helper is an original-data recovery controller.

The receiver checks bounds, IMMUBACKUP magic and SHA-256, then uses native
`hot-restore --verify-only` and `hot-restore` without force or append flags.
`--verify-only` accepts a changed transaction checksum: it checks framing, not
cryptographic integrity. The fixed digest must reject that changed packet, and
an actual restore into a third fresh disposable target must independently fail.
The third target is discarded; partial writes are allowed in that failed copy.
No atomic rollback of a failed immudb restore is claimed. Native framing also
rejects a truncated packet without restoring it.
A second restore into the good nonempty target must fail with the exact native
missing-append refusal and preserve the signed point and all four entries.

Exact readback requires all four keys, value bytes, revisions and per-key
transaction IDs. Before/after signed tips must be stable. Existing Fleetory
P-256 verification checks signatures against the generated public key; source,
restored and restarted transaction/hash/key identity and entry fingerprints must
match. A changed state signature is rejected. A separately created target reader
can read, but two actual write attempts (before/after restart) must return this
build's precise HTTP 500 / gRPC 13 `permission denied` response and leave the tip
unchanged. An incorrect target password must be rejected. User credentials are
recreated, not recovered by the per-database backup. The source is checked again
after all target operations, proving an observed stable fixture window only.

Each native process and the whole fixture have bounded deadlines. Cleanup verifies
held container/image ownership, removes only those resources and verifies absence.
A separate child deliberately fails after allocating both stores, exits nonzero
and emits a typed cleanup record. The parent independently checks both IDs, the
owned image and payload directory are gone. Cleanup uncertainty preserves the
resource ledger. No base image is deleted.
Session-token revocation is not established: all authentication state is confined
to the disposable servers and removed with their verified destruction.

Final output contains counts, hashes and scope flags after cleanup, not tokens,
raw values or backup bytes. This is a separate fresh audit-only proof; the
[PostgreSQL proof](NativePgDataRoundtrip.md) remains a separate capture point.
It proves no coordinated cross-service snapshot, native original-v2 inventory
equivalence, untrusted-archive sandbox, post-restore human login, independent WORM
or custody, original PKI/provider/Agent recovery, whole-VPS recovery or full RPO/RTO.
Phase 7 remains open. Next build the separate nonempty-data Server recovery
controller with actual artifact/inventory/build bindings and authority review.
