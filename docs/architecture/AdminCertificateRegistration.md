# Admin certificate registration and rotation

The production Admin listener requires both a trusted Admin CA chain and an exact
registered SHA-256 digest of the client leaf certificate's DER bytes. The Admin SAN
must be `urn:fleetory:admin:<uuid>`, and the registration must contain the same
person UUID. The database check runs on every HTTP request, including on a reused
TLS connection. A missing, mismatched, revoked or expired registration returns 403
and is audited. A database failure closes access. OIDC/WebAuthn and RBAC remain
separate required gates.

Apply Platform migrations before starting a Server version with this gate. **On an
existing production deployment, pre-register every active Admin certificate before
upgrading the Server.** Otherwise all existing Admin credentials lose access until
an authorized database operator registers them. Development keeps this gate off by
default; `Fleetory:AdminGateway:RequireCertificateRegistration=true` enables it for
local integration testing. It cannot be disabled outside Development.

The CA issues the certificate and protects the private key outside Fleetory. The
operator calculates the uppercase SHA-256 of the exact DER leaf (for a PEM leaf,
`openssl x509 -in admin-client.pem -outform DER | openssl dgst -sha256`), checks its
Admin SAN and CA, and records an independently approved incident reference. Never
store the private key in PostgreSQL or Git.

## Initial registration

Run [register-admin-certificate.sql](../../eng/register-admin-certificate.sql) in
the **same transaction** as [bootstrap-first-admin.sql](../../eng/bootstrap-first-admin.sql),
as shown in [SecurityFoundation.md](SecurityFoundation.md). Set
`fleetory.admin_register.mode=bootstrap`; the script refuses to proceed if any
active Admin certificate is already registered. The RBAC grant, certificate
registration and both audit/export entries commit or roll back together.

## Rotation

Verify the new leaf and its SAN match the current Admin identity. In an approved
`psql` session from the repository root with `ON_ERROR_STOP` enabled:

```sql
BEGIN;
SET LOCAL fleetory.admin_register.mode = 'rotate';
SET LOCAL fleetory.admin_register.person_id = '<ADMIN_SAN_UUID>';
SET LOCAL fleetory.admin_register.certificate_sha256 = '<NEW_UPPERCASE_SHA256>';
SET LOCAL fleetory.admin_register.previous_certificate_sha256 = '<CURRENT_UPPERCASE_SHA256>';
SET LOCAL fleetory.admin_register.incident_reference = '<APPROVED_INCIDENT_ID>';
SET LOCAL fleetory.admin_register.operator_reference = '<OPERATOR_ID>';
\i eng/register-admin-certificate.sql
COMMIT;
```

The script requires exactly one active, unrevoked certificate for that identity,
matching the expected previous digest. A stale expected digest, duplicate new
digest, malformed input or revoked new digest fails atomically. The old and new
certificates can both authenticate for **at most one hour** after registration;
the old one then fails on its next request. Test the new credential, including
OIDC and RBAC, before retiring the old credential. If the old certificate is
compromised, use the [emergency revocation procedure](AdminCertificateRevocation.md)
immediately; its denylist overrides the overlap. Confirm the
`admin.certificate.rotate` audit event reaches the export sink. A further
rotation waits for expiry or revocation of the prior certificate so that the
script never creates more than two live certificates for one identity.

## Recovery of a different identity

Use the [emergency recovery procedure](SecurityFoundation.md) to grant a
replacement person Admin RBAC access. In that **same transaction**, set mode to
`recovery`, the replacement SAN UUID and fingerprint, the approved incident and
operator reference, then run the registration script before committing. This
mode refuses a pre-existing active certificate for the replacement identity and
does not change other administrators' credentials. After verifying the new Admin
can authenticate, revoke a compromised old certificate and remove inaccessible
RBAC assignments through the audited procedure.

Registration rows and audit entries are retained. A revoked digest cannot be
registered again. The exact digest check is a local credential binding; CA
revocation and OIDC account recovery must be handled in their own systems.
