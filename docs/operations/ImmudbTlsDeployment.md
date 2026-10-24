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
         --pkey /run/secrets/immudb-server.key \
         --clientcas /run/secrets/immudb-client-ca-chain.pem

   Enable mutual TLS only when the selected immudb topology requires it; in that
   case also provision the Fleetory client certificate through the secret
   provider. Do not expose the immudb administration API to the Fleetory
   application network.
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

    openssl s_client -connect audit.example:8080 \
      -servername audit.example -showcerts \
      -CAfile C:\ProgramData\Fleetory\trust\immudb-root.pem \
      -verify_return_error < $null

Accept the deployment only when the output contains `Verify return code: 0
(ok)`, the certificate name matches `audit.example` and the chain contains the
leaf plus every required intermediate. Record the leaf and root SHA-256
fingerprints, the immudb version, listener address and operator reference.

Use a credential-free HTTPS probe to confirm the application path and reject
redirects:

    curl.exe --fail --silent --show-error --proto "=https" --tlsv1.2 \
      --cacert C:\ProgramData\Fleetory\trust\immudb-root.pem \
      https://audit.example:8080/api/status

Do not put the writer password or bearer token in this probe. The Fleetory
audit pipeline and the signed-state/restore verifiers perform the authenticated
checks separately.

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
