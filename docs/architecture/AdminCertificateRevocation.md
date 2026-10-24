# Emergency Admin certificate revocation

Fleetory's Admin mTLS listener validates the approved CA chain and then checks the exact
client leaf certificate SHA-256 in PostgreSQL on **every** Admin request. A revoked
certificate receives HTTP 403, including on an existing TLS connection. A database
failure prevents the request from reaching an Admin handler. Denials with a valid
Admin SAN identity are audited. Revocation is independent of the Admin actor's RBAC
assignments, so a newly issued and registered certificate with the same SAN UUID
can continue to work after the old certificate is revoked.

This is an emergency denylist. Normal certificate registration and rotation are
documented in [AdminCertificateRegistration.md](AdminCertificateRegistration.md).
An approved CA, Admin OIDC/WebAuthn, credential custody and network restrictions
remain required. A database operator must not revoke the last working Admin
credential until a replacement has authenticated and its permissions have been
checked. Revoke the certificate at the issuing CA and disable compromised OIDC
credentials separately; Fleetory's denylist protects its own Admin listener.

## Operator procedure

1. Record independent approval, the incident reference, the operator identity,
   and the replacement Admin access check in the protected incident system.
2. From the **exact leaf certificate** to revoke, calculate the uppercase SHA-256
   of its DER bytes. For a PEM leaf, `openssl x509 -in admin-client.pem -outform DER |
   openssl dgst -sha256` yields the digest; uppercase its 64 hexadecimal characters.
   Check the certificate subject, Admin SAN UUID and issuing CA against the
   incident record. Do not hash the PEM text or private key.
3. In an approved `psql` session connected to the Fleetory database, with
   `ON_ERROR_STOP` enabled, run the following from the repository root. Supply
   database authentication through the operator's protected mechanism, not the
   command line or Git:

   ```sql
   BEGIN;
   SELECT set_config('fleetory.admin_revoke.certificate_sha256', '<UPPERCASE_SHA256>', true);
   SELECT set_config('fleetory.admin_revoke.incident_reference', '<INCIDENT_ID>', true);
   SELECT set_config('fleetory.admin_revoke.operator_reference', '<OPERATOR_ID>', true);
   \i eng/revoke-admin-certificate.sql
   COMMIT;
   ```

4. Confirm the row in `platform.admin_certificate_revocations` and its
   `admin.certificate.revoked` event in `platform.audit_events` and
   `platform.audit_export_queue`. An Admin request with the old certificate must
   return 403; the verified replacement must still work. Monitor the audit export
   backlog until the event reaches immudb.

The SQL statement inserts the revocation and audit/outbox entry atomically.
Malformed fingerprints, missing incident/operator references and duplicate
revocations fail without a second event. The list is append only: if the wrong
certificate was revoked, investigate and issue a new certificate rather than
deleting the row. Current Admin HTTP handlers do not maintain long-lived streams;
future streams must recheck revocation or close on revocation.
