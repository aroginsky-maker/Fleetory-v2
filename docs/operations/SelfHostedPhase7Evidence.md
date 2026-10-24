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

Production completion still requires independent CA/key custody, signer
deployment, TLS/firewall records, WORM/SIEM object identifiers, retention/legal
hold records and final approval/recovery evidence.
