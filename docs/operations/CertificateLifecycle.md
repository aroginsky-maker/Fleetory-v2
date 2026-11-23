# Production certificate lifecycle

This procedure is the deployment boundary for Fleetory Agent and Admin
certificates. Fleetory validates certificate identity, chain, binding, overlap
and revocation; the organization’s CA and operators own issuance, private-key
custody, physical-device verification and recovery evidence.

## Issuance and custody

1. Open an approved change or incident record containing the device/person
   identity, scope, requested validity window, operator and independent
   approver. The operator and approver must be distinct identities.
2. Issue the leaf certificate through the approved Agent or Admin CA. Include
   only the required SAN (`urn:fleetory:agent:{DeviceId}` or
   `urn:fleetory:admin:{PersonId}`), the correct issuer chain and the required
   client-authentication EKU. Never issue a wildcard or a shared identity.
3. Generate the private key on the target device or an approved HSM-backed
   workstation. Record the public-key or certificate SHA-256 fingerprint in the
   change record; never copy private key material into Git, Fleetory settings or
   an unprotected ticket.
4. Deliver the certificate and private key through the approved secret channel.
   Verify the recipient, transport, file permissions and owner before placing
   the material in the Agent/Admin service directory.

## Rotation acceptance

1. Run `eng/provision-fleetory-gateway-pki.ps1` on Windows gateway hosts with
   the approved root and intermediate fingerprints. The script must report the
   expected CA policy, validity and chain, and must leave private keys outside
   the certificate stores.
2. For an Agent replacement, create the rotation intent for the exact new leaf
   fingerprint. Redeem it only from the replacement certificate while the old
   certificate remains inside the approved overlap window. Confirm the old
   binding is revoked or expires at the recorded deadline.
3. For an Admin replacement, register the exact DER fingerprint and previous
   fingerprint through the controlled SQL procedure. Verify the one-hour
   overlap, OIDC subject match and revocation precedence using the real mTLS
   route.
4. Capture the old/new fingerprints, issuer, validity windows, overlap expiry,
   audit event IDs and CI run URL. Keep the old certificate available only for
   the approved rollback window.

## Lost-key recovery and rollback

- Lost Agent keys require two distinct Admin identities, an incident reference,
  a new fingerprint and an evidence-bundle SHA-256. Physical-device evidence
  must be reviewed before the replacement grant is delivered.
- Lost Admin keys require the controlled break-glass SQL procedure, separate
  operator and approver references and post-recovery revocation of stale
  registrations.
- A failed rotation restores the previously approved certificate pair only
  after confirming its fingerprint, issuer, validity and audit trail. Do not
  silently reset a grant or replace a certificate without an incident record.

The repository tests prove the validation and fail-closed behavior. Production
completion still requires the CA issuance, key-custody, device-verification,
delivery and recovery records for the selected deployment.
