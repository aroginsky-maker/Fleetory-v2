# Protected command signer deployment

Fleetory does not expose a command execution endpoint in this phase. This
runbook defines the production boundary for the future signer that produces
Agent command signatures. The signer must remain a separate trust domain from
Fleetory Server and the Agent host.

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
