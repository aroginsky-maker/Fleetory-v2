# Fresh coherent Server pair recovery

This generated-only controller exercises a nonempty PostgreSQL/immudb restore
before starting the native Server application. It reads no retained original
backup, credential, certificate, signing key or VPS state. Existing original
permissions are neither used nor renewed. Run
`tests/Fleetory.Tools.Tests/NativeServerPair.Tests.ps1` on PowerShell 7.3+ with
Docker and Python. CI runs the actual native fixture on Linux and the 15 packet
admission test methods on both Linux and Windows.

## Source and capture

`FreshPairModel` derives four event identities from a new fixture UUID, plus two
devices and two people. Events include apostrophes, a null target, a null context
and deliberately unsorted context keys. Fixed SQL literals use explicit escaping
and standard-conforming strings. The real current Platform/Core migrations are
generated offline; PostgreSQL receives 18 tables/23 rows including migration
history, four events and an empty outbox.

The source native probe reconstructs all four events from the actual PostgreSQL
rows using a verified runtime TLS login and a repeatable-read/read-only transaction.
It publishes them using the production `ImmudbAuditExportSink`, with a fresh,
database-scoped writer. A separate reader checks every key, all ten fields,
revision 1 and each key's transaction. The audit database has four transactions.
Before/after signed tips must remain stable, and the existing Fleetory P-256
verifier checks signatures against the generated public key.

Native `pg_dump` and `immuadmin hot-backup` produce both real artifacts. Source
PostgreSQL catalog/data/security inventory and cross-store signed readback are
repeated after capture and again after target operations. This is an observed
quiescent fixture window, not a globally atomic distributed snapshot.

`fleetory.fresh-native-server-pair.v1` is a distinct generated-only manifest.
It binds the fixture UUID, actual probe DLL hash, image/container identities,
measured PostgreSQL inventory hash, native cross-store point and exact artifact
lengths/digests. It contains no synthetic component approval graph or placeholder
artifact. `fresh_server_pair.py` accepts only a bounded private stdin packet, a
manifest SHA-256 and fixture UUID; it accepts no filesystem path or address.
Duplicate keys, nonfinite JSON, wrong scope/version, noncanonical identities,
mixed/mutated inputs, incorrect types, capture-point drift and unsafe sizes are
refused before either immutable captured packet is returned. Numeric zero and
boolean false remain distinct in capture records. The driver clears its original
byte arrays and restores only the captured packets. The payload-bearing response
must never be logged. A matching manifest pin is a byte binding, not authentication
of an external approver or an independently measured inventory.

## Targets and preflight

Two PostgreSQL containers each own a network-none namespace. Their respective
audit containers join only that namespace. All stores have UUID ownership guards,
no host mounts or published ports, read-only root, non-root identities, cap-drop
ALL, NNP, private tmpfs and fixed resource/core limits. A COPY-only image contains
the pinned immudb/immuadmin binaries and checked public probe payload, before
private material is generated. The actual in-container probe hash is checked.
Only the pair profile adds a fixed mode-0700, UID/GID-3322 16 MiB tmpfs at
`/run/fleetory-native` for the CA and Server secret directory. Its exact path,
size, ownership and noexec/nosuid/nodev options are runtime-validated; the older
audit profile still requires exactly its original two tmpfs mounts.

All database passwords, infrastructure TLS, separate Agent/Admin gateway CAs,
leaf keys and the state-signing key are freshly generated. Target users/passwords
are recreated. Bootstrap/restore authority stays in the fixture; Server receives
only its runtime login and the dedicated audit writer. The PostgreSQL restore
session authenticates as fresh postgres and selects the effective migrator role.
This is not a sandbox for arbitrary untrusted archive SQL. Native immudb restore
has no rollback assumption; a failed or deliberately drifted target is discarded.

The full PostgreSQL data/catalog/owner/ACL/default-ACL/role inventory must match
the captured source. Both stores must then match the same four-event point before
`StartAsync` can be called. `FreshPairPreflightException` is emitted only for
specific data mismatches; configuration, database authentication, TLS and arbitrary
process failures cannot count as successful negative tests.

The fixture changes each of the ten PostgreSQL audit fields individually. Each
change must cause a typed preflight refusal and leave all three Server ports
closed. PostgreSQL is cold-restored after each case. An extra target audit key
must also refuse startup; that audit target is destroyed and replaced from the
captured backup. These are derived test writes outside the accepted restore point.

## Native application lifecycle and limits

The actual Production Server builder uses its File provider, enabled gateways,
dedicated PostgreSQL/audit credentials and registered outbox worker. A new mode
supports the nonempty fixture; the older empty-table fixture is not used against
nonempty data. The host must start and stop normally, return exact live/ready
health responses, keep private paths absent on the public listener and close all
ports afterward. With an empty outbox it must leave PostgreSQL inventory, every
audit value/revision and the signed audit tip unchanged. Restarting both target
database processes and repeating the native application lifecycle must preserve
the same point. No enrollment, command, privileged mutation or human login occurs.

Per-process and fixture deadlines remain bounded. Cleanup checks held identities,
removes only owned containers/image aliases/public payload and independently
checks absence. A separate child deliberately fails after creating all four
stores, exits nonzero and reports typed cleanup identities; its parent verifies
absence again. A cleanup failure preserves the resource ledger. Base images and
unrelated Docker resources are not removed.

This controller verifies a generated nonempty pair and native application lifecycle.
It establishes neither original-v2 inventory compatibility nor original deployment
provenance, original credentials/PKI/provider/Agent restoration, a coordinated
original capture point, restored human/OIDC/MFA login, session-token revocation,
independent WORM/custody/approvals, whole-VPS loss or full RPO/RTO. Original data
requires a separate compatibility and scoped-authority review; this fresh manifest
cannot be relabelled as an original approval record. Phase 7 remains open.
