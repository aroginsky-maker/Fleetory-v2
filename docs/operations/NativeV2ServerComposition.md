# Generated v2 Server composition

`NativeServerPair.Tests.ps1 -Profile v2` composes the separately tested PostgreSQL
v2 observer and five-transaction audit history. The default `legacy` profile
retains its 23-row/four-transaction contract. Neither profile admits original
backups or carries external approval authority.

The new profile creates application state with 18 tables/24 rows, signer journal
state with four tables/five rows, and four application roles. Its generated
registration/authorization rows have no identity or certificate authority. The
application audit rows are replaced during bootstrap with a fixed generated
event vector. All ten fields are read through the runtime TLS connection and
checked before the production sink serializes those actual rows into immudb.
An explicit generated control key occupies transaction 1; event writes occupy
transactions 2–5. The complete keyset, values, revisions and native transaction
headers are checked, without guessing additional original archive contents.

Three real native archives are captured: application, signer journal and audit.
A bounded manifest binds their bytes/SHA-256, measured probe DLL/image/container
identities, both complete v2 inventories, supplemental role/settings fingerprints
and the signed audit point/history. Source observations surround capture and must
match exactly. Each SQL inventory is read in its own read-only repeatable-read
transaction; dumps and the three stores are separate observations. This is an
observed stable window, not a global atomic snapshot.

The pure stdin `eng/pilot/v2_server_composition.py` freezes all three byte buffers,
rejects missing or placeholder archives, stale/mixed windows, schema/type/pin
changes and authority fields. Its target comparison checks both full inventories,
supplemental security state and audit data/history. Distinct source/target state
keys are required; the owning native coordinator independently verifies each
signature against its own public pin. The pure module authenticates neither a
native measurement nor a signature and never authorizes execution. It gives
valid observation mismatches a specific exit/category; malformed packets and
unexpected errors have a different exit and sanitized stderr, so they cannot
count as successful data refusal tests.

Bootstrap and restore authority remain in the fixture. SQL restore authenticates
as fresh postgres, selects the appropriate NOLOGIN owner and uses one transaction.
Only regenerated runtime credentials and the dedicated audit writer reach Server's
File provider. The source and target use separate generated signing keys; no
original key recovery, signer continuity or change to an original receipt chain
is claimed. A drifted audit target is discarded and restored to a new owned
container. Native restore is not an untrusted archive sandbox.

The coordinator compares the complete three-store point **before invoking a
positive native Server lifecycle**. Signer data, application ACL and role-limit
changes must refuse this invocation and leave all three ports closed. Separate
negative native host probes build the application but reject audit-field and
extra-key drift before `StartAsync`. Their typed data exceptions exclude transport,
authentication and arbitrary process failures. The native host repeats runtime
audit-row/history checks immediately before startup. The full catalog/role/signer
inventory check belongs to the isolated coordinator; this is not a new production
startup policy or a concurrent-writer atomicity guarantee.

Two positive lifecycles exercise the actual Production builder, enabled gateways,
registered outbox worker, exact live/ready responses and private-path refusals.
The empty outbox and all three restored datasets must stay unchanged after stop
and after restarting both backend processes. No signer host, issuer, command,
enrollment, human login or production token is activated.

The existing strict owned-resource profiles are retained: two network-none
PostgreSQL namespaces and audit containers joined only to their respective
namespace, no host mounts or published ports, non-root users, read-only roots,
private tmpfs, cap-drop ALL, NNP and fixed resource/core limits. Public-only image
builds precede TLS/signing-key creation; private material uses bounded stdin/tmpfs.
Canaries and deadlines guard outputs and operations. Normal cleanup and a failed
four-store child are checked, including independent absence checks.

Portable contracts run on Windows/Linux CI; native profiles run locally and in
Linux CI. The shared v2 operations are extracted without changing their bodies;
the older native profile remains a regression check. Production/test C# and their
retained local coverage remain unchanged; modified probe code is built, published
and executed. Gates, exclusions, runners, timeouts, repository visibility and the
$0 Actions budget are unchanged.

This closes a generated composition rehearsal. Original-data authority and pins
still need a scoped review under existing consent; consumed leaf/config/provider,
share/root/token permissions are not renewed. Original configuration/services,
release authenticity, PKI/revocation/physical Agent, restored human identity,
independent custody/WORM/approvals, coordinated original capture, whole-VPS loss
and full RPO/RTO remain open. Phase 7 remains incomplete and PR #2 unmerged.
