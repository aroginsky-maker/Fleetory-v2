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
- The separate signer journal evidence extract passed 18 PostgreSQL scenarios:
  complete/empty observations, stable snapshots during concurrent commits,
  explicit future-column exclusion, row/byte bounds, narrow reader permissions,
  prior-write rollback, role switching and lock deadline. Full local verification
  passed 399/399 .NET tests with 93.68% production coverage. This extracts metadata
  for reviewed archival; no external WORM/SIEM delivery or custody was claimed.
- Native psql checks reproduced multilingual journal export failures with
  inherited LATIN1 and WIN1251 client encodings. Explicit transaction-local UTF-8
  output fixed both cases; all 20 signer export tests passed. This exercises the
  real PostgreSQL Linux client and does not establish production authentication
  or independent archive custody.
  Full local verification after the fix passed 401/401 .NET tests, strict build
  with zero warnings/errors and 93.68% production coverage.
- Independent signer snapshot verification passed on local PowerShell 7:
  six acceptance and 30 rejection scenarios, native newline/8 MiB boundaries,
  duplicate/coerced fields, typed metadata and exact retained digest. Both real
  psql Unicode cases also passed through the read-only verifier. Shared immudb
  receipt export, independent verification and checkpoint checks passed on
  PowerShell 7 and Windows PowerShell 5.1. Full .NET verification remained
  401/401 with 93.68% local production coverage. External approval authenticity,
  database freshness and WORM custody were not inferred from file verification.
- Signer checkpoint continuity passed four acceptance and 18 rejection scenarios:
  identical/forward data, late pending completion, equivalent UUID/UTC spelling,
  missing/changed/duplicate row identities, different database/older observation,
  old history resubmitted with a fresh timestamp and matching digest, and invalid
  checkpoint inputs. The original verifier suite also passed, now with 33 common
  rejection scenarios including whitespace-contaminated UUID/digest/date values.
  Both real psql-to-verifier cases remained successful. Neither input artifact
  was changed, and no trust anchor or production recovery approval was created.

Production completion still requires independent CA/key custody, signer
deployment, TLS/firewall records, WORM/SIEM object identifiers, retention/legal
hold records and final approval/recovery evidence.
