# Generated native audit history

`NativeAuditHistory.Tests.ps1` exercises a separate generated immudb history:
four events serialized by the production `ImmudbAuditExportSink`, plus one
explicit generated control key. The control write is transaction 1; the four
event writes are transactions 2–5. This does not identify the unknown additional
state in any retained original archive or approve its contents.

The read-only probe scans the entire current keyspace with a six-entry bound,
requires exactly five expected keys, and checks every value, transaction and
revision. Every key must have one revision. All ten event fields and the control
document must match. Each bounded History request must return that one revision;
each native TxById response must contain its expected single resolved KV entry
and transaction header, with no raw or sorted-set entries. Empty repeated fields
may be omitted by the protobuf JSON encoder. The request uses the upstream
[immudb 1.11.2 API schema](https://github.com/codenotary/immudb/blob/v1.11.2/pkg/api/schema/schema.proto).

Native signed states before and after capture must have the same database,
transaction, root hash and measured history. The source and target use **distinct
fresh P-256 signing keys**. Each signature is verified against that instance's
own public pin; restored data and history are compared separately from signer
identity. Crossed pins and changed signature/hash/transaction/database are refused with
their exact expected verification errors; missing or unreadable pin files cannot
count as successful cryptographic refusals.
No original private key is recovered, no signer continuity is claimed and no new
key is appended to an original receipt chain. Transaction readback and the signed
tip are checked; independent per-entry Merkle inclusion proofs are not computed.

`eng/pilot/audit_history_inputs.py` freezes a bounded native archive received over
stdin. Its pinned manifest binds fixture, measured probe DLL, image/container,
source point, stable capture observations and exact archive length/SHA-256. It
accepts no file path, endpoint, credential, approval graph or placeholder database
slot. Its comparison operation requires identical data/history with distinct key
fingerprints. These pure operations neither verify a native checksum/signature
nor authorize execution. The owning native fixture independently checks runtime
identity, performs native verification/restore and verifies both public pins.

Derived targets exercise an extra key, an identical-value rewrite at revision 2,
and reversed event transaction order. Only their specific data exceptions count
as refusals; authentication, configuration, TLS, JSON and process errors fail the
test. A corrupted native restore target and deliberately drifted targets are
discarded. Native truncated input and nonempty restore must fail; no rollback
guarantee is inferred. Three positive native restores, least-privilege reader
write denials, wrong password and restart must preserve the accepted point.

The common generated-only `NativeAuditDataFixture.ps1` builds an image from
public probe code alone and checks the actual in-container DLL hash.
Stores use the existing strict profile: network none, no mounts or published
ports, non-root UID/GID, read-only root, two private tmpfs mounts, cap-drop ALL,
NNP and bounded memory/CPU/PIDs/core dumps. Passwords, TLS and signing material
are newly generated; private values travel only through bounded stdin and tmpfs.
Canaries guard outputs. Resource UUID/label/image/creation checks precede use and
deletion. Normal cleanup and a deliberately failed two-store child are checked,
including independent absence checks. Unrelated Docker resources remain owned by
their existing operators. This is not an untrusted archive sandbox.

Run the portable Python and refusal-policy tests on Windows/Linux. The native
fixture runs locally and in Linux CI. The older four-transaction audit fixture
retains its own profile and is a regression check for the extracted resource
helper; it is not relabelled as this history. Production C# and its retained local
coverage are unchanged; the changed native probe is built, published and executed.
Coverage/scanner gates, exclusions, runners, timeouts, visibility and the $0
Actions budget remain unchanged.

The separate [generated v2 composition](NativeV2ServerComposition.md) combines
this history with application/signer readback. This audit-only component neither starts the Server application nor reads
original backups, credentials, PKI/provider state or the source VPS. Consumed
one-shot permissions remain consumed. Original services, coordinated capture,
human login, PKI/revocation/physical Agent, release authenticity, independent
custody/WORM/approvals, whole-VPS loss and full RPO/RTO remain open. Phase 7 is
incomplete; PR #2 remains draft and unmerged.

The separate [bounded observation profile](BoundedAuditObservation.md) reads four
known events while retaining unknown additional transaction state. It exercises
both four and five current KV keys at transaction five. The control key in this
history fixture remains a generated convention, not a retained-archive assumption.
