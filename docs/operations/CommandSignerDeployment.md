# Protected command signer deployment

Fleetory does not expose a command execution endpoint in this phase. This
runbook defines the production boundary for the future signer that produces
Agent command signatures. The signer must remain a separate trust domain from
Fleetory Server and the Agent host.

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
the mTLS listener, request limits, durable audit and authenticated approval
service integration still require host implementation and deployment tests.
The component alone does not prove client-key possession or constitute a
deployed signing service.

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
