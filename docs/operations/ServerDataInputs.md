# Server recovery data admission

The next Baseline section17 service rehearsal needs application PostgreSQL and
immudb data. The older six-input reader also opens identity/provider backups;
it is too broad for that first Server slice. `eng/pilot/server_data_inputs.py`
provides a closed two-input admission stage for a future startup controller.
It does not restore data or start Server.

The operator pins `server-data-manifest.json` and chooses a protected working
directory. The CLI accepts only `--expected-sha256`. Its exact manifest fields are
`schema` (`fleetory.server-data-manifest.v1`), `componentManifestSha256`,
`candidateCommit`, `candidateBuildSha256`, and `artifacts`. Artifacts must be exactly
`application-postgres` and `audit-immudb`, each with `bytes` and lowercase `sha256`.
Their fixed filenames are `application.dump` and `audit.backup`; no input path,
root, provider material, credential, runtime option or execution flag is accepted.
The candidate revision/build digest are operator-pinned claims, separate from
historical source revisions. Admission does not authenticate a build or execute it.

The entire manifest is validated before opening the component metadata set.
The [eight-report composition](RecoveryComposition.md) then rechecks its pinned
bytes and semantic relationships. Application bytes must match the accepted
application dump digest; immudb bytes and length must match its accepted restore
report. Counts and inventory/security/audit-snapshot digests are retained for the
future post-restore readback. References inside those reports remain unopened.

Only after those checks are both fixed raw inputs opened with the shared bounded
held-handle reader. Each input is at most32MiB; their combined size is at most48MiB.
The manifest is at most64KiB. A caller receives nothing until both data hashes,
sizes and unchanged-source checks pass. The returned capsule contains immutable
captured `bytes`; a consumer must use `packet(kind)` rather than reopen a path.
Subsequent source replacement cannot change the captured data. The capsule hides
payloads from its representation, and `result()` returns a fresh metadata copy.
No temporary payload files are written. Transient hashing buffers can increase
peak memory; these limits are payload bounds, not a guarantee of exact RSS or
secure zeroization. The class is an in-process data carrier, not an authorization
token or protection against malicious code in the same Python process.

The CLI emits only metadata. Failed admission emits a fixed error with no input
contents. Native backup formats, restored event contents, schema compatibility,
candidate authenticity, original signing-key continuity, service startup and
human login remain unverified. Full-system recovery and Phase7 completion remain
false. A checksum pins bytes; it does not make an arbitrary dump safe to execute.

This stage is tested exclusively with fresh synthetic binary files and report
graphs. No retained raw backup, key, credential or provider input was opened for
this implementation. Existing application/audit consent stays scoped; consumed
leaf/configuration/provider permissions are not renewed by a manifest or capsule.

Before original-data execution, finish the closed startup/restore controller on
fresh data: native format/schema/owner/ACL compatibility, target-only credentials
and TLS, network-none/no published ports or source mounts, least privileges,
positive Server readback, failure/refusal/canary/resource/cleanup tests and current
CI/Sonar. Preserve the accepted original four-event/five-transaction baseline
separately from synthetic eight-event/nine-key regressions and derived writes.
Any genuinely new sensitive scope needs a concrete plan and applicable permission.
