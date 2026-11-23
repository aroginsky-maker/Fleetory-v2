# Evidence required to close Phase 7

Phase 7 closes when its Baseline controls have actual, retained acceptance
evidence. Passing software tests is necessary; a generated fixture or a
well-formed readiness record cannot substitute for deployment, human or custody
evidence. The [security foundation](../architecture/SecurityFoundation.md) and
[readiness record](Phase7Readiness.md) remain the governing implementation and
final gate documentation.

| Control | Implemented verification available | Evidence still required for closure |
| --- | --- | --- |
| `caPki` | Certificate/trust checks, mTLS refusal tests and lifecycle runbook | Actual issuance and protected custody, rotation/recovery/revocation records, physical Agent acceptance and relevant human admission |
| `signer` | Isolated mTLS signing host, journal, request/revocation controls and provider fixtures | Accepted deployed service/configuration/key lineage, actual provider authentication and independent approvals/custody |
| `immudbTls` | Authenticated TLS, dedicated-account, signed-state, receipt and restore verification | Accepted deployed trust/network/rotation settings, retained backup/restore and retention evidence |
| `wormAnchor` | Hash-linked receipts, export/checkpoint verification and pilot archival | Independently controlled immutable retention, object/version/hash and custody evidence; a mutable local copy or self-asserted flag is insufficient |
| `recovery` | Scoped component restores, generated native service tests, bounded input/process/resource contracts | One accepted complete recovery scope with code/configuration/secret/provider/PKI/identity continuity, human/Agent acceptance, failure/cleanup evidence and measured full RPO/RTO |

The current public cleanup work is preparation for the last row. Read-only OS
identity observations and a retained local consumed-attempt record do not prove
independent supervisor lifetime, actual create-receipt origin or cleanup after
controller/supervisor death. Those properties must be demonstrated before
original service recovery depends on them. Local process-restart replay refusal
also does not authenticate independent anti-rollback custody of the operator disk.

Before each new sensitive operation, prepare the actual executable plan and its
revision/hash, exact already-retained input inventory, proposed reads/transfers,
target isolation, token/privilege scope, maximum duration, negative checks and
owned cleanup. Obtain the applicable current permission before accessing new
secrets, private PKI or privileged provider material. Consumed one-shot grants
do not renew themselves. Preserve completed original recovery evidence and
repeat only an operation needed for a new explicitly reviewed acceptance scope.

Final acceptance must identify the actual independent requester, approver and
deployer, the deployed revision and current successful CI/Sonar, time-valid
evidence for all five controls and a validated rollback plan. Independently
verify the referenced objects, hashes, retention and identities before setting
the corresponding controls to true and running the readiness verifier. Neither
an operator alias nor the assistant can stand in for a missing independent actor.

If any control or its authority remains unverified, retain the exact open item
and its next concrete action. Keep Phase 7 open and PR #2 draft/unmerged; do not
fabricate approvals, production readiness or a completed full-system recovery.


The required CI graph separates Windows process/publication tests from the
independent Windows policy/evidence checks. The original Windows execution job
keeps its 20-minute limit; a separate standard Windows job has a 10-minute
limit and the same pinned SDK/build prerequisites. Signed artifact/journal,
dependency/quality/readiness, expectation/Sonar CLI and Windows PowerShell 5.1
checks retain their original commands and shells. No verification is omitted,
softened or made conditional. Linux retains its 35-minute limit, and native
data/provider jobs retain their 20-minute and 15-minute limits. The legacy and
v2 Server pair checks run with provider/identity. A separate required retained
Server job keeps a 15-minute limit and runs strict and explicit historical
Server recovery, active-SQL cancellation and actual data-only COPY interruption.
Each native job restores its own pinned prerequisites; none depends on Sonar
credentials or an upstream execution result. Admission, restore, lifecycle and
cleanup checks remain required.

The final aggregate requires all eight execution jobs, including both Windows
jobs. A missing, failed, cancelled, skipped or extra job result is rejected.
Layout tests also reject removed/duplicated/softened moved checks, altered
bootstrap and changed deadlines. The split addresses observed exhaustion of
the former single Windows job's 20-minute budget; it does not relax a control,
change the repository visibility or Actions budget, or accept any deployment.


A separate required `native-original-recovery` job runs the generated original-purpose normal, admission-peer-loss and original-expiry profiles on the standard `ubuntu-24.04` runner with its own 15-minute limit. All previous jobs and limits remain. The aggregate requires all eight execution jobs; omission, duplication, skipping, cancellation or failure remains a refusal. Independent prerequisites retain strict restore/audit/build checks. The repository is public; standard GitHub-hosted runner execution is free under [GitHub's public-repository rules](https://docs.github.com/en/actions/reference/runners/github-hosted-runners). No larger runner, artifact upload, budget or visibility change is introduced.

The three local generated native cases used identical working source hashes and passed 27 independent own-resource absence observations. Normal restored two PostgreSQL archives and immudb, then started/stopped Server twice with runtime login and backend refusal checks. Admission loss and original expiry blocked subsequent audit/Server execution; expiry measured 108789ms without renewal. These facts do not establish complete runtime/command/resource inventory, original release continuity or full-system recovery. Original backups and original private PKI were not opened by these cases.

The required `native-publication-faults` job runs the actual public publication
fault and retained owned-cleanup checks on a standard `ubuntu-24.04` runner
with a 15-minute limit. It prepares its own pinned Python image and SDK/build
prerequisites and does not rely on another job's cache. The aggregate requires
this eighth execution job; the existing verification commands and deadlines
remain required. Generated publication fault evidence does not establish
original-service recovery, independent custody or Phase 7 completion.
