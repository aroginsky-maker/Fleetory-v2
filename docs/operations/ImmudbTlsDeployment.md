# immudb TLS deployment and rotation

This runbook is the production boundary for the Fleetory immudb audit sink.
The immudb administrator owns the server certificate, private key, trust roots,
listener exposure and rotation record. Fleetory receives only the HTTPS origin
and the database-scoped writer credential through its protected secret path.

## Initial deployment

1. Issue an immudb server certificate for the deployment DNS name. The leaf must
   contain `serverAuth`, the DNS name used by Fleetory and a bounded validity
   period. Keep the private key on the immudb host or its protected secret mount;
   it must never enter the repository, Fleetory configuration or command line.
2. Install the approved root and intermediate CA material in the immudb trust
   path. Start immudb with the certificate and key configured through the
   deployment's protected service configuration, for example:

       immudb --certificate /run/secrets/immudb-server-chain.pem \
         --pkey /run/secrets/immudb-server.key

   The current Fleetory REST sink uses server-authenticated TLS and a
   database-scoped bearer token; it does not load a client TLS certificate.
   A topology requiring client mTLS needs a separately implemented and tested
   client-certificate transport before deployment. Do not expose the immudb
   administration API to the Fleetory application network.
3. Configure Fleetory with an `https://` origin whose host exactly matches the
   certificate name. The sink rejects HTTP outside Development, embedded URI
   credentials, redirects and the default administrator account. Use the
   dedicated database-scoped writer account provisioned by the immudb operator.
4. Restrict the listener to the audit network and the operator network. Deny
   public access, the PostgreSQL port and administrative endpoints from the
   Fleetory web and Agent networks.

## Root-only wire acceptance

Run this from an operator host that contains only the approved root certificate;
do not rely on the host's global trust store:

The following command uses a POSIX shell and OpenSSL:

```sh
openssl s_client -connect audit.example:8080 \
  -servername audit.example -verify_hostname audit.example -showcerts \
  -CAfile /etc/fleetory/trust/immudb-root.pem \
  -verify_return_error < /dev/null
```

Accept the deployment only when the output contains `Verify return code: 0
(ok)`, the certificate name matches `audit.example` and the chain contains the
leaf plus every required intermediate. Record the leaf and root SHA-256
fingerprints, the immudb version, listener address and operator reference.

Use the repository's credential-free HTTPS preflight in PowerShell to emit a
machine-readable record. It sends a HEAD request to the origin root and requires
HTTP 2xx; redirects and HTTP errors fail without producing a verified record:

    ./eng/verify-immudb-tls.ps1 `
      -Address https://audit.example:8080/ `
      -RootCertificatePath C:\ProgramData\Fleetory\trust\immudb-root.pem

The probe requires native `curl` (`curl.exe` on Windows), TLS 1.2 or later and an
absolute path to the approved PEM trust file. Addresses with credentials,
paths other than `/`, queries or fragments are rejected. It disables curl user
configuration and environment proxies, bounds connection setup to five seconds
and the whole request to fifteen seconds, and discards response headers without
downloading a body. Curl's certificate, hostname and revocation policy remains
enabled; a Schannel failure due to unavailable revocation information must be
resolved through the deployment PKI rather than disabling verification.

`rootCertificateSha256` is the SHA-256 of the exact supplied PEM file. Record the
CA and leaf DER fingerprints separately; a PEM file digest is not a certificate
fingerprint. Do not put the writer password or bearer token in this probe. The
Fleetory audit pipeline and signed-state/restore verifiers perform authenticated
checks separately. A successful preflight establishes TLS and root availability;
it does not establish database permissions, health or signed-state integrity.

The regression fixture pins a disposable self-signed localhost certificate and
checks a real TLS request, foreign trust, hostname mismatch, curl defaults,
redirect targets and non-2xx statuses on PowerShell 7 and Windows PowerShell 5.1.
The separate gateway wire-chain test covers a root/intermediate/leaf chain.

## Certificate rotation

1. Obtain approval and record the new leaf fingerprint, issuer, validity window,
   operator and rollback reference.
2. Install the replacement root/intermediate alongside the current chain when
   the CA changes. Validate the new chain with the root-only probe while the old
   chain remains active.
3. Replace the immudb server certificate and restart/reload the service through
   its service manager. Repeat the root-only probe and the credential-free HTTPS
   probe.
4. Run the Fleetory audit pipeline, signed-state receipt verifier and restore
   acceptance check. Confirm the database-scoped writer still selects the
   expected database and that no redirect or HTTP endpoint is accepted.
5. Retire the old trust material only after the acceptance output, fingerprints,
   timestamps and rollback record are stored in the approved change record.

The local security lab uses loopback HTTP intentionally and is not evidence for
this production control. Production completion requires the operator's TLS,
firewall, key-custody, rotation and rollback records together with the current
CI/Sonar results.
