# Protected command signer deployment

Fleetory now includes the separate `Fleetory.CommandSigner.Host` executable.
It exposes only authenticated signing of empty `Inventory.Refresh` envelopes;
Agent command delivery/execution and high-risk/bulk approvals are not enabled.
The signer remains a separate trust domain from Fleetory Server and Agent.

## Run the mTLS host

Publish `src/Fleetory.CommandSigner.Host/Fleetory.CommandSigner.Host.csproj` for
the selected Windows/Linux host and run its DLL as the dedicated signer identity.
Use a protected management address, dedicated approval-service client CA/leaf
grants and a separate signer database login. No application Server or Agent
certificate should be granted signer-client authority.

```text
dotnet Fleetory.CommandSigner.Host.dll --Signer:SecretsDirectory=/run/fleetory-signer --Signer:TransitAddress=https://transit.example --Signer:TransitKey=agent-command --Signer:TransitKeyVersion=2
```

The default listener is `127.0.0.1:9443`. Set `Signer:BindAddress` to one specific
management IP and `Signer:Port` to the approved port. Wildcard addresses and
additional `Kestrel:Endpoints` are refused. Configuration can also be supplied
through `FLEETORY_SIGNER_` environment variables using `__` for nested keys.
Do not put tokens, connection strings or private keys in command arguments.

The required secret files are loaded through the shared bounded file provider:

| File | Value |
| --- | --- |
| `signer-server-ca` | Approved public server root CA PEM, one or two roots |
| `signer-server-cert` | Server leaf followed by intermediate CA PEMs |
| `signer-server-key` | Matching TLS private-key PEM |
| `signer-policy` | JSON below, containing public client trust and explicit grants |
| `signer-postgresql` | Separate runtime login connection string; local transport or verified TLS |
| `signer-transit-token` | Short-lived, sign-only Transit token |
| `signer-transit-public-key` | Base64 DER SubjectPublicKeyInfo for the pinned P-256 key version |

`signer-policy` uses camelCase properties `rootsPem`, `intermediatesPem` (optional)
and `callers`. Each caller contains `callerId`, `certificateSha256`, `deviceIds`
(array of UUID strings), `notBefore` and `expiresAt` (UTC strings). All fields are
validated; unknown/duplicate JSON properties, private-key policy material and
malformed/missing callers fail startup. Existing policy bounds still apply.
Mount directories/files with service-only access and protect their parent paths;
Unix files require private modes, and Windows deployments must provision private
service/System/Administrators ACLs. The shared loader rejects links and bounded
UTF-8 violations. Windows TLS deployments must also perform host PKI provisioning
as described in the Windows preflight runbook.

Provision journal schema v3 with `eng/provision-signing-journal.sql`. Grant the
runtime login only CONNECT, schema USAGE and SELECT/INSERT on all three signer
request/result/rejection tables, and only SELECT on `client_certificate_revocations`.
Keep the revocation writer on an independent operator identity. Startup and `/health/ready` check these
rights, deny UPDATE/DELETE/TRUNCATE/schema CREATE and reject privileged,
replication-capable or session-role-switched connections. Use direct grants;
runtime login membership in other roles is rejected. Database credentials must not be shared with
Fleetory Server. `/health/live` and `/health/ready` require registered mTLS too;
readiness verifies the journal, while Transit failures are reported by signing
requests and must be monitored separately.

Send `POST /signing/inventory-refresh` with exactly `requestId` and `deviceId`
as UUID JSON strings. The certificate must come from the TLS connection;
forwarded-certificate headers cannot supply authentication. TLS 1.2/1.3 and
client certificates are mandatory. The host permits at most four in-flight
requests, defaults to ten requests/minute globally (configurable 1–60), rejects
bodies above 1 KiB and applies a twenty-second application deadline, with up to
five additional seconds for denial-audit cleanup after cancellation. Limits
also apply to health probes. There is no HTTP listener, general command API,
cookie login, forwarded-header trust or public command execution route.

The response contains request/device/command IDs, format version, command type,
issued/expiry times, nonce, signing key ID and base64 signature, with `no-store`.
Reconstruct the signed envelope with an empty payload and verify it using the
existing Core contract. Duplicate requests return 409, invalid JSON returns 400,
scope denials return 403 and rate/concurrency denials return 429. HTTP rejections
are committed with the actual peer fingerprint and a fixed reason; valid parsed
request/device IDs are retained. `X-Fleetory-Audit-Id` identifies the denial record.
If rejection audit fails, the response is 503. Operational errors use fixed
responses and do not return backend exceptions or credentials.

For disposable local tests only, Development plus explicit
`Signer:AllowLoopbackHttpTransit=true` allows loopback HTTP Transit. Production
rejects it even when the flag is supplied. The signer listener always remains
HTTPS/mTLS. Grant/CA additions and other policy changes require a controlled restart;
certificate revocations take effect through the database without restart, as below.
Atomic policy reload, production custody, TLS-handshake audit retention, delivery
reconciliation and WORM/SIEM export remain deployment/integration controls.

## TLS failures before HTTP

The signer listener now emits a structured warning when a connection leaves TLS
admission without reaching the accepted HTTPS stage. This covers missing,
unregistered or foreign client certificates, malformed/plaintext traffic,
disconnects and the existing five-second handshake deadline. HTTP requests over
successfully established TLS continue to use the PostgreSQL rejection journal;
an HTTP 400/403 is not reclassified as a TLS failure.

Collect JSON console events with category
`Fleetory.CommandSigner.Host.SigningTlsHandshakeAudit` and EventId `701`
(`SignerTlsHandshakeNotEstablished`). Their `State` contains:

| Field | Meaning |
| --- | --- |
| `Schema` | `fleetory.signer-tls-failure.v1` |
| `AuditEventId` | New UUID for this connection observation |
| `ObservedAt` | Server UTC timestamp when the failed admission returns |
| `ConnectionId` | Bounded, sanitized server transport correlation ID |
| `RemoteAddress`, `RemotePort` | Actual IP socket peer, or `unknown`/0 for a non-IP transport |
| `ElapsedMilliseconds` | Monotonic elapsed time of the rejected admission |
| `Reason` | Fixed `TlsNotEstablished` classification |

This classification does not assert an authenticated caller or distinguish a
bad certificate from a timeout. A client retry may create multiple distinct
connection observations. The event contains no exception text, certificate
subject/PEM, raw handshake bytes, attempted HTTP headers, tokens or private keys.
Forwarded headers cannot supply its peer address or connection identity.
The audit category retains warning-level output even when generic console
logging is disabled. Byte-level Kestrel connection logging is not enabled.

Capture stdout under the dedicated service identity into the approved protected
collector, configure retention/rotation and capacity, monitor collector health,
and retain the required incident records outside the signer host. The events are
operational logs, not rows in the authenticated signing journal, and console
emission alone does not establish durable storage, WORM custody or delivery.
Connections rejected before entering the endpoint middleware still require
transport/Kestrel resource-limit monitoring. Production collector provisioning,
retention and independent custody remain open deployment controls.

## Implemented Transit client contract

`Fleetory.CommandSigning` currently signs only an argument-free, one-minute
`Inventory.Refresh` envelope for an explicit DeviceId. It pins the Transit key
version and P-256 public key and verifies each returned signature locally.

The client has a ten-second total deadline covering connection, response
headers, body buffering, JSON parsing and the final cancellation check before
releasing an envelope. Caller cancellation shares this lifetime; an already
cancelled call sends no request. Responses are limited to 4 KiB. Invalid JSON,
missing or incorrectly typed signature fields, unexpected key versions and
invalid signatures fail closed.

Production requires a credential-free HTTPS origin. Redirects, cookies and
inherited proxies are disabled; provide a direct route to the approved Transit
origin. The sign-only token must contain at most 8192 visible ASCII characters
with no whitespace or control characters. HTTP status failures retain the
status code but omit the remote reason phrase and body; JSON and signature
encoding errors also use fixed messages. Do not log request headers or tokens.

Unit tests cover rejected credentials and malformed responses. Real loopback
HTTP tests verify stalled headers, stalled bodies and caller cancellation;
their explicit test-only HTTP setting does not permit production HTTP. These
client checks are combined with the host's mTLS and journal controls described
above; production approval deployment remains a separate requirement.

## Implemented caller authorization component

`SigningClientAuthorizationPolicy` and `AuthorizedCommandSigner` provide the
input authorization layer for the standalone host. The host must first
prove possession of the client key through an actual mTLS handshake and pass
that connection's certificate. A certificate supplied in JSON, an HTTP header
or a forwarded-certificate header is not authentication and must not be used.

Each protected `SigningClientGrant` binds a configured caller ID to one exact
DER SHA-256 fingerprint, explicit DeviceIds and a UTC half-open validity window
`[NotBefore, ExpiresAt)`, at most 24 hours long. Policy creation rejects duplicate
fingerprints, duplicate/empty DeviceIds and malformed grants. It copies public
CA certificates and target sets, so later mutation or disposal of input objects
does not widen trust. Limits are two roots, three intermediates, 64 grants and
1024 explicit DeviceIds per grant; there is no wildcard target.

Authorization requires the pinned leaf, digital-signature usage, explicit
client-authentication EKU, a currently valid chain to an approved custom root,
a current grant and the exact target. System roots and downloaded intermediates
do not grant trust. Each approved root is checked separately so rollover also
works when the old and new CAs have the same subject name and different keys.
An unregistered Server or Agent certificate is denied even
when its chain is trusted. The wrapper checks authorization before Transit
access and again before releasing the signed envelope, and returns the configured
caller identity for the durable request record. Its only operation remains empty
`Inventory.Refresh`; high-risk and bulk signing are unavailable.

This component performs no CRL/OCSP lookup. Rotation may allow two explicit leaf
grants during overlap. The required `ISigningClientRevocations` additionally reads
the exact leaf denylist, without caching, before reservation, after reservation,
after Transit and after the result commit. The host also checks it on each HTTP
request, including health probes and requests on an already established TLS
connection. Read failure withholds the signature; HTTP returns 503 with a durable
denial record when that journal remains available. A revoked leaf returns 403.
TLS admission still uses the protected static CA/grant policy; revocation denial
happens at HTTP authorization and does not terminate every idle TLS connection.
Atomic host reload, authenticated approval integration and production deployment
still require independent evidence. The host supplies the actual mTLS connection
certificate and request limits; the library alone does not prove key possession.

## Revoke a signer client certificate

Use an independently approved incident/evidence bundle and exact DER SHA-256.
In the separate signer database, give the operator a dedicated login with CONNECT,
schema USAGE, table SELECT and column INSERT on `certificate_sha256`,
`incident_reference`, `operator_reference`, `approver_reference` and `evidence_sha256`
in `signer.client_certificate_revocations` only. Do not grant table-wide INSERT:
the operator must not supply database-generated event ID, session identity or time.
It needs no ownership, memberships, UPDATE, DELETE, TRUNCATE or signing-journal
write privileges. The signer runtime must have SELECT only on this table;
startup rejects both table and individual-column write grants. The three signing
journal tables also reject individual-column UPDATE/REFERENCES and table TRIGGER rights.
Upgrade existing deployments with the idempotent schema v3 provisioning script
and explicit SELECT grant before replacing the host binary; an old schema or
missing/excessive denylist permissions fail startup.

In one operator session, set the five `fleetory.signer_revoke.*` settings documented
in `eng/revoke-signing-client.sql`, then execute that script with `ON_ERROR_STOP`.
Inputs are `certificate_sha256`, `incident_reference`, `operator_reference`,
`approver_reference` and `evidence_sha256`. Fingerprint and evidence digest must
be uppercase 64-character SHA-256; references are bounded, nonempty, control-free
and operator/approver must differ after trimming and case normalization.

The single statement forces `synchronous_commit=on` and atomically appends the
certificate fingerprint, event UUID, evidence pointers, database `session_user`
and recording time. Read back that row and retain its event UUID with the approved
bundle. Duplicate revocation refuses to replace the first record. Reference
strings do not authenticate people or verify the evidence bundle; independent
approval, digest/custody validation and WORM/SIEM retention remain operator duties.

After commit, make an authenticated probe with the revoked leaf and verify 403
with its denial audit ID, then use a separately authorized replacement leaf to
verify continued scoped service. There is no unrevocation operation: replacement
requires a newly issued and explicitly granted certificate. Revocation during
Transit or result commit withholds the envelope on the following current read;
pending/completed journal rows remain for reconciliation. A completed row alone
does not prove delivery. Revocation cannot recall an envelope already returned
or a response that has passed the final check; stop downstream dispatch and
rotate affected Agent trust separately when the incident requires it.

## Implemented durable request journal

`AuthorizedCommandSigner` requires an `ISigningRequestJournal`, current
`ISigningClientRevocations` and a nonempty
RequestId. `PostgreSqlSigningRequestJournal` uses the independent `signer` schema;
provision it with `eng/provision-signing-journal.sql` under a deployment owner in
the separate signer database. Supply its data source from the protected signer
secret configuration. Fleetory Server must not receive these database credentials.
Do not point this component at Platform/Core tables or use the Server account.
Use local protected PostgreSQL transport or a verified TLS data source; production
host transport enforcement remains part of the host integration.

The runtime role needs only CONNECT to that database, USAGE on `signer`, and
SELECT/INSERT on `signer.signing_requests`, `signer.signing_results` and
`signer.signing_rejections`. Do not
grant table/schema ownership, UPDATE, DELETE, TRUNCATE or schema CREATE. The
provisioning script does not create a login or embed a password; record runtime
role provisioning separately. PostgreSQL must retain its durable fsync/WAL and
backup configuration. Each journal transaction explicitly sets
`synchronous_commit=on`, including when the connection's default is off.

Before Transit access, a unique RequestId reservation commits the configured
caller identity, client certificate SHA-256, target DeviceId, fixed command type
and database acceptance time. Concurrent or later attempts with that RequestId
are rejected, including attempts with changed caller/target metadata. A failure
after reservation leaves a pending row; it is never removed or retried by the
signer. An operator must reconcile the incident and request before authorizing
any new RequestId. A new RequestId must not be used blindly to bypass this state.

After local signature verification, the journal commits CommandId, signing key
ID, database recording time and SHA-256 over canonical signing bytes followed
by the 64-byte signature. It stores no bearer credential, private key, payload
or raw signature. Completion is bound to every reservation identity field;
repeated identical completion is idempotent and conflicting completion fails.
The signer rechecks authorization and cancellation after this commit and only
then returns the envelope. A completion row proves signing was journaled, not
that an Agent received or executed the command. Lost acknowledgements, database
errors and cancellation require reconciliation rather than another signature.

This implements durable records for authorized signing attempts. The host also
records HTTP denials in `signing_rejections`; TLS negotiation failures happen
before HTTP and require retained TLS operational diagnostics. The read-only
operator reconciliation described below is implemented; delivery acknowledgement
correlation remains open. The
separate WORM/SIEM export, immutable retention and independent administrator
custody remain deployment/integration requirements; database append permissions
alone do not establish those controls.

## Reconcile a signing request after a lost response

Use `eng/reconcile-signing-request.sql` in the independent signer database, under
an approved incident. Give the reconciliation operator a separate direct login
with CONNECT, schema USAGE and SELECT on `signer.signing_requests` and
`signer.signing_results` only. No signer/Transit credential, schema ownership,
role membership or journal write privileges are needed. Keep the PostgreSQL
service profile/password file protected outside Fleetory Server and the repository;
never put a database password in the command line.

Stop further upstream dispatch for the affected request and confirm the approved
database/restore lineage first. In a **fresh** PostgreSQL session, set the known
canonical nonzero UUID:

```sql
SET fleetory.signer_reconcile.request_id = '9ade91ca-6ec3-48e6-886f-2396fde9549a';
```

Then execute `eng/reconcile-signing-request.sql` with stop-on-error enabled.
For psql, use the approved service profile with `-X -q -A -t -v ON_ERROR_STOP=1`
and load the file using `\i`. Retain its single JSON result in a new protected
incident artifact. Record the exact artifact hash in the independently retained
incident/evidence bundle. The script sets a read-only transaction, UTC output,
a five-second statement timeout and two-second lock timeout. It rejects role
switching and any already assigned transaction, so it cannot accidentally commit
earlier writes. Do not run it inside an existing transaction.

The observation records schema `fleetory.signing-reconciliation.v1`, RequestId,
database name, actual operator login, observation time, the authorized request
metadata and any committed CommandId/key ID/envelope SHA-256. A single SELECT
joins the reservation/result under one database snapshot. It returns no raw
signature, private key, bearer token or signing credential and changes no rows.

| Status | Meaning and incident action |
| --- | --- |
| `NotFound` | No reservation is visible in this snapshot. Check pending work, the exact RequestId and database/restore freshness; absence does not authorize a retry. |
| `Pending` | Reservation exists without a committed result. Transit may already have signed; reconcile independently and preserve the row. |
| `SigningRecorded` | A signing result was committed. The host may still have withheld it or lost the response; correlate with independent delivery evidence. |

Every observation reports `automaticRetryAllowed`, `deliveryVerified` and
`executionVerified` as false. A permission failure, lock timeout or database
failure produces an error, not `NotFound`. A later observation may see a newly
committed result; observation time is not an immutable global cutoff.

If an envelope was actually retained, compare its DeviceId, CommandId and key ID
with this record and compare SHA-256 of its canonical `GetSigningBytes()` followed
by the 64-byte signature with `envelopeSha256`. Also verify its signature using
the approved device-bound public key. This comparison does not authorize delivery,
re-signing or bypassing Agent expiry/replay checks. The tool neither regenerates
a signature nor authorizes a new RequestId. Production operator approvals, latest
database custody, delivery acknowledgements and WORM retention remain separate
controls.

## Key and service isolation

1. Create a non-exportable P-256 signing key in the approved HSM or Transit
   engine. Disable plaintext backup and record the key ID and version in the
   change record. The private key must never be present in Fleetory Server,
   Agent trust directories, CI artifacts or operator workstations.
2. Deploy the signer on a separate service identity and network segment. Accept
   requests only over authenticated mTLS from the approved approval service;
   deny Server, Agent and public web networks by default.
3. Issue a short-lived sign-only credential with no secret-read, key-create,
   key-delete or policy-admin capability. Store it in the deployment secret
   manager and rotate it independently of the signing key.
4. Log every request with signer key version, command ID, DeviceId, approval
   correlation ID, requester and outcome. Never log private key material,
   bearer tokens or command payload secrets.

## Two-person approval

- The requester and approver must be distinct authenticated identities. Both
  must approve the exact command type, target DeviceId, canonical payload hash,
  expiry and incident/change reference.
- The signer must reject missing, expired, replayed, mismatched or single-person
  approvals. A changed payload or target requires a new approval record.
- High-risk and bulk command classes remain disabled until this gate and the
  future Agent execution host are deployed and independently tested.
- Keep approval, signing and delivery records for the approved retention
  period in the independent audit/WORM system. A lost acknowledgement is
  resolved by correlation ID; never retry a signature blindly.

## Agent trust distribution and rotation

1. Publish only the signer public key and version to the device-scoped Agent
   trust directory through the protected provisioning channel. The directory
   and files must be owned by the Agent identity, LocalSystem or Administrators
   and must reject broad ACLs, symbolic links and unauthorized writes.
2. During key rotation, distribute the new public key, verify overlap, sign a
   test command for an approved DeviceId, then retire the old key after the
   recorded overlap deadline. Archive the old fingerprint and approval record.
3. A trust-file mismatch, unknown key version, replay or revoked DeviceId must
   fail closed before a command reaches the future execution handler.

The local OpenBao Transit smoke test validates non-exportable key use, replay
rejection and Server-token denial. It is not production signer custody or an
approval deployment; those require the independent service, mTLS, HSM/Transit
records and retained approval evidence described here.
