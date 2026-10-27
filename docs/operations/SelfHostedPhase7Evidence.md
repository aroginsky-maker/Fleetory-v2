# Self-hosted PHASE 7 evidence

This record summarizes checks executed on the local Docker security lab. It is
review evidence for the implemented behavior and is not production custody.

## Evidence collected on 24 October 2026

- OpenBao Transit signer: the P-256 key was non-exportable, the Agent accepted
  one signature, replay was rejected, and the Server token received `403` for
  signing. Stale disposable trust was archived before the check.
- Audit pipeline: a PostgreSQL audit outbox entry was delivered by Fleetory to
  immudb through the dedicated `fleetory_audit_writer` account, selected
  `defaultdb`, and read back at revision 1.
- Backup/restore: an immudb hot backup covering transactions 1–33 was restored
  into an isolated replica database; the final database list reported 33
  transactions.
- Disposable immudb TLS: a uniquely named container served HTTPS with a
  generated localhost certificate; `curl --cacert` validated the certificate
  and returned `/` with HTTP 200 and `/api/status` with HTTP 404 without
  credentials. The container and temporary certificate directory were removed
  after the check.
- Readiness record: the verifier accepted distinct actors, UTC timestamps,
  control confirmations, CI/Sonar evidence, WORM reference and rollback plan;
  duplicate actors, invalid evidence hashes and failed gates were rejected.
- Latest CI/Sonar before this evidence record: [run 40129286182](https://github.com/aroginsky-maker/Fleetory-v2/actions/runs/40129286182), Quality Gate PASS, Sonar coverage 90.6%, new-code coverage 90.82901554404145%, duplication 0.0%.

## Evidence collected on 27 October 2026

- The published signer ran as UID 1654 in a separate Linux container with
  read-only root and secret volume, no effective capabilities, no-new-privileges
  and no Docker socket. An unrelated process had no signer secrets or Server
  binary, and an unrelated PostgreSQL principal could not read signing requests.
- An approved client completed real mTLS signing against that process with
  verified PostgreSQL TLS; the returned P-256 signature was verified. Restarting
  the same container retained RequestId rejection and did not repeat the Transit
  call. An unregistered client was rejected, and sanitized TLS diagnostics
  contained no token, database password or private-key marker.
- The HTTPS Transit endpoint in this process test was a disposable test backend
  with its signing key outside the signer container. Production HSM/Transit
  custody is not inferred from this check or from the separate local OpenBao lab.

Production completion still requires independent CA/key custody, signer
deployment, TLS/firewall records, WORM/SIEM object identifiers, retention/legal
hold records and final approval/recovery evidence.
