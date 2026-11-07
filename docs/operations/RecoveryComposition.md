# Partial recovery component composition

Baseline section17 needs a coherent service recovery argument. Successful
component reports have different scopes and dates; combining their PASS labels
cannot establish original credential continuity or a whole-service restore.
The read-only `eng/pilot/recovery_composition.py` checks their byte pins and
selected semantic relationships before preparing the next fenced service step.

Run from the protected operator directory:

```powershell
python -B 'E:\Fleetory Core\Fleetory\eng\pilot\recovery_composition.py' --expected-sha256 <manifest SHA-256>
```

The directory must contain `recovery-component-manifest.json`, schema
`fleetory.recovery-component-manifest.v1`. It records the reported source app,
configuration and operator40-character revisions and exactly eight report entries
with `bytes` and lowercase `sha256`. CLI paths and a root override are not accepted.
Report filenames are fixed by this version of the pilot policy. The separately
retained manifest digest is the trust anchor; the tool does not authenticate a
manifest supplied by an untrusted operator.

The existing [recovery file reader](RecoveryFiles.md) supplies bounded held-handle
reads, root containment, ordinary single-link files and unchanged-byte checks.
The manifest and each report are capped at64KiB; aggregate report input at512KiB.
All eight manifest entries are validated before any report is opened. Strict UTF8,
duplicate JSON fields, schema/type errors, changed bytes, missing inputs, unknown
path/permission fields and inconsistent cross-component claims fail without
printing report contents. Report paths such as backup/proof/journal references
are data only: they are never opened. No raw backup, credential or PKI input is read.

| Component | Accepted report scope | Relationship or limit retained |
| --- | --- | --- |
| Application/signer DB pair | Preserved state, owners, ACLs, role membership and restart | Per-DB snapshots/stable observed window; no global atomic capture or recovered source passwords |
| immudb | Original audit events, revisions and signed checkpoint | Same reported source app/config, audit count and transaction boundary as the DB pair; independent custody remains open |
| Runtime LOGIN | Fresh target passwords, SCRAM, rotation/restart and permission refusals on the retained pair | Exact DB report digest, dump digests and before/after inventories; neither source-password recovery nor remote TLS is inferred |
| Original configuration |13 files, three leaf keys and two native Build/Dispose calls | No service startup, DB opening, backend authentication or renewed permission |
| Provider | One completed isolated target operation | Canonical operation ID, matching controller/plan and cleanup; consumed permission, no standing grant or actual signer authentication |
| Identity | Historical logical database preservation | Human login after restore remains unverified |
| Release |67 matching payload files in the current pilot record | Payload continuity does not authenticate source revision, signature or image configuration |
| Rebuilt images | Three code-only image records | Same source payload archive, matching Server/signer file total and native image metadata; historical source image reproduction/startup remain unverified |

The result is `PASS_PARTIAL_COMPONENT_COMPOSITION`, with an eight-row scope
matrix and report-byte count. It always keeps `newOperationsAuthorized`,
`standingAuthorizationRemaining`, `sourcePasswordsRecovered`,
`postRestoreHumanLoginVerified`, `sourceRevisionAuthenticated`,
`coordinatedCaptureWindowVerified`, `originalServiceStartupVerified`,
`independentCustodyVerified`, `fullSystemRecoveryVerified` and `phase7Complete`
false. Hash pins establish integrity against the chosen manifest, not independent
truth of historical statements. Original event contents and state signatures
are not recomputed by this metadata check. No new backup, restore, provider/root/token
operation, issuer, source mutation, Docker process or external approval is performed.

The reconciled pilot point has four original audit events/five immudb transactions,
18 application tables/24 rows and four signer tables/five rows. The later LOGIN
exercise proves target-only authentication on that exact retained pair; the old
full-system plan's blanket LOGIN gap is stale when read without this qualification.
Original service authentication, a common original capture window, current PKI,
real human admission, independent WORM/custody and full RPO/RTO remain open.
The eight SQL events/nine keys from the [native synthetic fixture](NativeLiveRevocation.md)
are a different data set and cannot replace this original four-event point.

Next prepare one concrete service target plan from this matrix, its exact release
and runtime inputs, least privileges, isolation and cleanup. Existing app/signer/
audit consent remains scoped; consumed configuration/leaf/provider permissions
do not authorize new use. Any new sensitive category needs a concrete reviewed
plan and a new applicable permission before access. Phase7 stays open; PR#2 is
draft and unmerged.
