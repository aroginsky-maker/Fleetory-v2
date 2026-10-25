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

Provision journal schema v2 with `eng/provision-signing-journal.sql`. Grant the
runtime login only CONNECT, schema USAGE and SELECT/INSERT on all three signer
tables, including `signing_rejections`. Startup and `/health/ready` check these
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
HTTPS/mTLS. Policy changes/revocation currently require a controlled restart;
atomic reload, production custody, TLS-handshake audit retention, delivery
reconciliation and WORM/SIEM export remain deployment/integration controls.

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
client checks do not establish the isolated signer service or approval workflow
required below.

## Implemented caller authorization component

`SigningClientAuthorizationPolicy` and `AuthorizedCommandSigner` provide the
input authorization layer for the future isolated host. The host must first
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
caller identity for the future audit record. Its only operation remains empty
`Inventory.Refresh`; high-risk and bulk signing are unavailable.

This component performs no CRL/OCSP lookup. Revocation currently means replacing
the protected policy snapshot without the old leaf grant; rotation may allow
two explicit leaf grants during overlap. Online revocation, atomic host reload,
authenticated approval integration and production deployment still require
independent evidence. The host now supplies the actual mTLS connection
certificate and request limits; the library alone does not prove key possession.

## Implemented durable request journal

`AuthorizedCommandSigner` now requires an `ISigningRequestJournal` and a nonempty
RequestId. `PostgreSqlSigningRequestJournal` uses the independent `signer` schema;
provision it with `eng/provision-signing-journal.sql` under a deployment owner in
the separate signer database. Supply its data source from the protected signer
secret configuration. Fleetory Server must not receive these database credentials.
Do not point this component at Platform/Core tables or use the Server account.
Use local protected PostgreSQL transport or a verified TLS data source; production
host transport enforcement remains part of the host integration.

The runtime role needs only CONNECT to that database, USAGE on `signer`, and
SELECT/INSERT on `signer.signing_requests` and `signer.signing_results`. Do not
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
before HTTP and require retained TLS operational diagnostics. Read-only
reconciliation and delivery acknowledgement correlation remain open. The
separate WORM/SIEM export, immutable retention and independent administrator
custody remain deployment/integration requirements; database append permissions
alone do not establish those controls.

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
