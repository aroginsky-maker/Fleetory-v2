# Retained Server pair metadata compatibility

`eng/pilot/retained_pair_review.py` reconciles four pinned metadata packets:
the accepted application/signer restore report, accepted audit restore report,
database capture report and audit source observation. It has no file, Docker,
database, socket, restore or credential API. Path strings in reports are never
followed. The CLI accepts bounded base64 JSON on stdin and one externally retained
manifest SHA-256 via `--pin`; output contains counts and scope flags only.

All four packets are frozen before any is parsed. Exact byte lengths/digests,
strict UTF-8 JSON, duplicate-key/nonfinite rejection and fixed report names prevent
partial or mixed input delivery. Maximums are 64 KiB per report, 16 KiB manifest
and 384 KiB stdin envelope. Raw dumps, native audit backups, event bodies and keys
are not inputs. The observation supports only the four-field EventId/key/revision/
value-digest shape; adding a payload field is rejected.

The retained pilot profile is deliberately separate from
[the generated native pair](NativeServerPair.md):

| Feature | Retained application/signer v2 | Generated Server inventory v1 |
| --- | --- | --- |
| Application point | 18 tables, 24 rows, four events, empty outbox | 18 tables, 23 rows, four generated events, empty outbox |
| Other application rows | Registration and authorization state | Generated devices/person projections |
| Audit point | Four known revision-one events; five transactions | Four scanned revision-one keys; four transactions |
| Role set | Four application and signer roles | Migrator and Server roles |
| Role fields | Superuser, inherit, create role/database, replication, bypass RLS | Also LOGIN, connection limit and role configuration |
| Memberships | Incoming membership for the four roles; no grantor | Incoming/outgoing membership for two roles, including grantor |
| Default rights | All default-ACL rows | Application schemas and global defaults |
| Public schema | Tables/sequences allowed and inventoried; executable objects refused | Public relations refused; application functions fingerprinted |
| Sequences | Definition, owner/ACL and current state included | Refused by profile |
| Hash encoding | Length-prefixed PostgreSQL JSON text, binary sorted row hashes; separate security digest | Exact NDJSON packet bytes, including catalog and per-table row-hash aggregates |

These algorithms cannot be converted by renaming a field or normalizing their
hashes. Native v1 does not prove the original v2 fingerprint. V2's historical
schema/data/owner/ACL/default/membership evidence does not cover the missing role
fields. The separately accepted target-only SCRAM tests retain their own scope;
they did not recover source passwords or prove remote TLS.

The reviewer checks both database profiles, capture inventory equality, dump pins,
the same reported before/after/source signed-state point and public point, audit
backup length/digest, four unique UUID-derived audit keys, revision one and value
digests. Different signature bytes at the same point are accepted: signatures are
not transaction identities. Signature shape is checked, but cryptography is not
repeated. The accepted audit report remains evidence of the prior signature test.
The source observation does not contain per-event transaction IDs or an exhaustive
key scan; this reviewer therefore reports both properties as unverified. Existing
target observations contain embedded record bodies and must not be passed as this
metadata-only input. A future original readback controller needs an explicit
transaction/keyset contract rather than inferring four transactions from four events.

The retained reports authenticate neither a deployed source revision nor a new
operation. The release review establishes continuity of 67 payload files, while
release signatures, source-revision authentication and image configuration remain
unverified. Recorded application/configuration revisions are declarations; an OCI
label is not independent release authentication.

| Material/action | Existing scope | Next controller requirement |
| --- | --- | --- |
| Application/signer/audit backups | Existing data-copy/restore consent remains scoped | Use original typed v2 inventory/readback, pinned immutable bytes and exact native formats; no fresh-model substitution |
| Target runtime passwords | Generate temporary target-only credentials | Independently verify LOGIN/SCRAM, narrow permissions, verified TLS/origin and rotation/refusal; do not read source passwords |
| Original leaf/configuration material | Previous one-shot grants consumed | Concrete file/action/lifetime/cleanup plan and current specific permission before reuse |
| Original provider/share/root/token | Previous isolated operation consumed; source-root recovery excluded | No reuse of consumed grants or implied production-token/issuer permission |
| Source VPS or new secret/PKI category | Not authorized by this metadata review | Concrete scoped plan before any dependent operation |
| Human identity, physical Agent, WORM/custody and approvals | Open independent controls | Actual evidence, not synthetic acceptance flags |

Next implement a separately versioned original-profile native readback on generated
data that models these differences. Preserve the two independent algorithms and
the additional role checks; compare exact actual event values, per-event
transactions, revisions, full keyset and signed point before startup. Explicitly
separate bootstrap/restore/runtime identities. Current fresh restore uses postgres
with an effective migrator role and is not an untrusted archive sandbox. Keep
state-preserving checks, typed pre-start refusals, canary-safe diagnostics,
timeouts, isolation and independent cleanup before auditing original-data execution
authority. New PKI/provider actions need their own concrete approved plan.

Portable generated tests cover mixed/stale/schema/type/point/event/authority and
size refusals, freeze-before-parse behavior, no file/process/socket effects and
sanitized CLI errors on Windows and Linux CI. No old native restore, source-root
operation or unchanged successful native fixture is repeated for this review.
This is metadata reconciliation, with `executionAuthorized=false`, original-v2
recomputation and service recovery unverified. Global atomicity, whole-VPS recovery,
full RPO/RTO and Phase 7 completion remain open; PR #2 stays draft and unmerged.
