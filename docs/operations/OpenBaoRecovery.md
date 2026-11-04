# OpenBao Raft recovery acceptance

Baseline section 17 includes secret-provider recovery material in the backup
scope. The pilot uses pinned OpenBao 2.7.1 with Integrated Storage (Raft) at
`/openbao/data`. Its existing dev-mode Transit lab is not a persistent-storage
recovery test. Keep actual pilot acceptance separate from synthetic fixtures.

## Snapshot and custody boundaries

A native Raft snapshot contains barrier-encrypted provider state, including
Transit keys and point-in-time authentication/authorization state. It does not
replace the server configuration, TLS/PKI material, original seal recovery
material or separately retained audit logs.

The pilot's declarative file audit writes `/openbao/data/audit.log`. That file is
outside the storage barrier encryption and is not an encrypted Raft snapshot.
Do not package the whole directory as though every file were encrypted.

Keep plaintext recovery shares, credentials and TLS private keys separate from
the snapshot. Losing the original Shamir material can make the encrypted copy
unusable. The pilot's approved temporary 1-of-1 local custody does not establish
independent production custody, recovery quorum, retention or immutable audit.
An encrypted snapshot is still sensitive; its destination and custody need
explicit approval. Never export the Transit private key or enable its
`exportable`/`allow_plaintext_backup` settings to simplify recovery.

Original provider material must be recovered inside the approved provider/DR
service boundary. Do not unseal a real provider copy on an operator workstation.
Synthetic test keys are confined to disposable test environments.

## Point-in-time authorization matters

Revoke temporary administrative credentials **before** capture, then take the
snapshot using a separate short-lived read-only orphan snapshot credential.
Create it through the supported orphan-token endpoint or independent issuer;
a normal child can be revoked along with its parent root.
A later revocation on the original does not edit an existing snapshot.

A restore must preserve the original token creation/expiry times and revoked
state. It must not silently renew tokens or extend signer/certificate/grant
deadlines. Before exposing a real recovered provider, reconcile credentials
revoked after the backup with the current independently retained change record.
A restored old snapshot is not authority to resurrect those credentials.

## Fresh-cluster restore

A fresh initialized cluster has its own seal keys. A normal snapshot restore
checks compatibility with those keys and should reject a snapshot from another
Shamir initialization. The pinned OpenBao 2.7.1 CLI documents `-force` as the
override for that compatibility check.

For a disaster-recovery test this override is limited to a verifier-created,
fresh, isolated target after checking the independently retained source
snapshot hash and expected source identity. It is not an option to apply an
unknown snapshot to an existing deployment.

The acceptance sequence must show all of the following:

1. The normal restore rejects the different bootstrap seal and leaves that
   bootstrap state usable.
2. The target is the fresh instance created by the test, with the pinned image,
   a unique ownership/session label and no path to the source service.
3. The retained snapshot bytes match the trusted capture reference before the
   override is used.
4. After recovery the bootstrap share cannot unseal the restored state; the
   original fixture share can. Never run a second `init` or create a replacement
   Transit key after restoring.
5. The expected source cluster identity, public SPKI, key version and
   nonexportable/plaintext-backup-disabled settings are preserved.
6. A new synthetic signature verifies under the previously retained public key.
   The known source credential revoked before capture and the target bootstrap
   root remain denied; this does not test erased historical root credentials.
   Signer management remains denied and original token lifetime is preserved.

This establishes the tested recovery properties only. It does not authenticate
independent human approval or establish production recovery acceptance.

## Synthetic regression fixture

Run the disposable test with PowerShell 7.3 or later and Docker:

```powershell
./tests/Fleetory.Tools.Tests/OpenBaoRaftRecovery.Tests.ps1
```

The fixture creates its own non-dev source and fresh restore node from the
pinned image, with distinct node IDs and no published ports, host mounts or
network access. Synthetic TLS material is generated in memory and transferred
only into the owned tmpfs; the CLI validates that CA without skipping TLS
checks. No real provider, recovery share or operator credentials are inputs.

Both configurations include the file-audit device. Its runtime log and server
configuration have separate recovery/retention scope from the native snapshot.

Acceptance compares the original public key and version/settings, cluster
identity, known root/management denials, a fresh signature and the retained
token lifetime metadata. The summary may retain only public fingerprints,
hashes, status and stated limitations. A passing fixture is not an actual pilot
snapshot or recovery-quorum, independent-custody, audit-retention or full-system
acceptance record. It does not establish post-expiry behavior across arbitrary
production downtime.

### Expired credentials and target-only replacement

The synthetic fixture also captures a live, nonrenewable 20-second signer
credential and tests its read/renewal denials after expiry on the restored node.
It then rehearses a fresh restricted credential without renewing that captured
identity. Both node IDs, the retained signing public key/version/settings and
the original one-hour token expiry references remain checked.

The Docker-free `OpenBaoTargetCredential.Tests.ps1` contract runs on Windows and
Linux: two valid leases and nine refusals, including a lifetime one tick above
300 seconds, excess/default policy, renewable/non-orphan credentials and a
source/unrestored target. Duration uses the precise `issue_time`/`expire_time`
pair: provider processing can shorten the effective lifetime, while any amount
above 300 seconds is rejected. Integer-second `creation_time` is not an exact
duration reference.

Legacy root generation is disabled on both nodes initially. The fixture rejects
the source role/ID as a recovery-window target. Only its already-restored owned
target can temporarily enable `disable_unauthed_generate_root_endpoints=false`
on its loopback TLS listener. The generated fixture share completes one root
attempt; OTP, share and token values stay in bounded process I/O/memory rather
than arguments or result JSON. The decoder follows the
[version-pinned OpenBao encoding](https://github.com/openbao/openbao/blob/v2.7.1/sdk/helper/roottoken/decode.go).

The target root creates a five-minute, nonrenewable orphan with no default
policy: the fixed Transit key read/sign paths, self lookup and self revocation.
Root revocation must return an explicit 403 before restricted use. A restart
closes the recovery window, restores the default 405 and preserves the new
token's identity, creation/absolute expiry and decreasing TTL. Key/policy/token
management and renewal remain denied. The token verifies the unchanged key and
one non-command signature, is denied on the synthetic source, then is revoked
and must return 403. The recovered root is also denied on that source. Public
results are checked against generated credential canaries; owned targets are
removed even on failure.

OpenBao 2.7.1 exposes separate
[legacy and authenticated root-generation APIs](https://github.com/openbao/openbao/blob/v2.7.1/website/content/docs/api/system/generate-root.mdx);
the [listener guard](https://openbao.org/docs/configuration/listener/tcp/)
defaults to closed. This test is not a production recovery controller or
permission to change a real listener. An actual provider plan still needs exact
artifact/share scope, approved provider/DR placement, revocation reconciliation,
bounded target administration/token issuance and explicit current consent.
Never unseal real provider state on the operator workstation or repeat the
completed source-root recovery under this fixture's synthetic scope.

## Transport preparation for a future provider target

`eng/pilot/ProviderRecoveryTransport.ps1` renders public arguments; it does not
connect to a host or execute a recovery. The SSH model checks a bounded,
single-entry Ed25519 host ledger against both an independently retained file
hash and host fingerprint. It accepts a canonical IPv4 destination and explicit
identity path. It disables ambient SSH configuration, proxies, agent forwarding,
password authentication, connection sharing and automatic host-key updates.
An offline `ssh -G` test checks how the installed OpenSSH parses these options,
including a ledger path containing spaces. No identity file is needed for that
test. See the primary [OpenSSH client reference](https://man.openbsd.org/ssh)
and [configuration reference](https://man.openbsd.org/ssh_config).

The remote command quotes every public argument as a literal POSIX shell word
and selects `/usr/bin/docker --host unix:///var/run/docker.sock` explicitly.
Only public arguments belong in this renderer: it cannot determine whether a
caller has mistakenly put a secret in an argument. Tokens, shares, TLS keys and
snapshot bytes must travel through bounded binary stdin. The shared native
process helper rejects input above 64 MiB, limits stdout to 64 MiB and stderr to
1 MiB, enforces a 1–120 second per-process deadline, kills the local process tree
on failure and clears Docker endpoint/context/TLS environment overrides in the
child. It emits no raw response on a transport failure.

The generated-only Raft fixture exercises the same argument model through a
real POSIX shell on Linux, and an explicit Docker Desktop Linux context on
Windows. Its source and restore containers now use `--rm` with a PID 1 lifetime
of 3,300 seconds. Their independent 55-minute expiry does not rely on the
operator remaining connected. Runtime inspection verifies this command,
automatic removal and the existing network-none, no-port, no-host-mount,
non-root, read-only and resource restrictions. Normal ownership-checked cleanup
still runs immediately. Portable tests cover literal shell metacharacters on
Linux, offline SSH options, malformed or changed host pins, binary stdin,
timeouts and both output limits. All data is newly generated for the fixture.

This completes transport and disposable-lifetime preparation only. A concrete
remote recovery controller still needs a closed operation allowlist, fresh
target/source-ID guards, capacity checks before original input reads, a durable
one-attempt marker, a whole-operation deadline, protected pin continuity during
execution and verified remote cleanup after interruption. Rendering an SSH
request is not authority to execute it. The real snapshot/share operation
remains unapproved, and original state must remain inside the approved
provider/DR boundary. These checks do not prove real service authentication,
current revocation reconciliation or full-system recovery.

## Actual pilot operations

Prepare and review the executable fixture and recovery evidence before
requesting an actual provider operation. The completed Keycloak and
application/signer database restore checks do not authorize copying OpenBao
state or using its real recovery share.

An actual operation needs concrete consent covering the recovery-quorum use,
any temporary administrative credential/listener and required restart window,
snapshot scope and destination, original share use in the isolated provider
restore target, and the restricted signature-probe credential.
The pilot's original root was revoked; an earlier one-time root-recovery
approval for initial Transit setup is not standing authorization for a new
administrative recovery session.

Use the supported native Raft snapshot API/CLI. An online atomic Raft snapshot
does not itself require stopping the provider. Avoid concurrent upgrades,
seal/key migrations or structural system operations during capture.
Do not improvise a hot copy of Raft files or migrate the live storage backend.

Use an existing still-valid restricted probe credential or an explicitly
approved short-lived probe credential created before capture. Expiry does not
authorize renewal or a new clone root. The signature challenge must be
synthetic data that cannot be accepted as a Fleetory command envelope.

Create only the temporary capabilities required for capture. Record and revoke
the temporary root before capture; revoke the snapshot credential on the source
after transfer. Retain its absolute expiry because that final revocation does
not retroactively modify the snapshot. Restore testing must retain strict
network isolation and cannot expose a copied production issuer or signing
service.

Record the source version/image, backend, capture time, cluster identity,
snapshot hash, public-key/version reference, actual custody and actor evidence,
restore result, cleanup and remaining limitations. No token, share or private
key belongs in Git, chat or CI artifacts.

A full deployment exercise must also prove recovery of configuration, PKI and
revocations, audit/checkpoints, application/signer histories and physical Agent
trust. RPO/RTO and retention belong to the deployment profile. Keep Phase 7 and
its PR open until the remaining Baseline controls have actual evidence.

## Verified actual pilot acceptance - 1 November 2026 UTC

This is a historical record of an explicitly approved operation, not a current
provider-health assertion or standing authority for another root session.
The retained protected capture and restore records were independently rechecked
before adding this summary. Neither the encrypted backup nor private operator
files are published here.

The native barrier-encrypted snapshot contained 27,161 bytes, SHA-256
e94f5c8457e0d56671a40ef2a3f8a25c73698fa0dfd332f54f2c64cdba268094.
The one-time source root was revoked before capture, permanent configuration
and health were restored, and the source maintenance window was 24.812 seconds.
Temporary source credentials were revoked. The offline copy remains in the
approved protected local destination outside Git.

The same snapshot was restored in a fresh, same-VPS provider target with
network none, no published ports or host mounts, a read-only root and tmpfs.
The normal foreign-seal restore and fresh bootstrap share were rejected with
HTTP 400; the original approved share unsealed the restored state. Cluster/key
continuity and Transit P-256 version 1 were retained, with nonexportable key and
plaintext backup disabled. Public SPKI SHA-256 was
84f39cbc722afb27d0943ef09ecd25daf4c39b5fa70a2da617c86f3518171206.
A new domain-separated non-command signature verified under that public key.
Fresh bootstrap root and signer management returned 403, clone root generation
returned 405, and audit mode/owner was 600:100:1000. The target was removed
and source health checked after cleanup.

The restore continuation used no second source-root recovery, token issuance
or renewal. Existing signer self-lookup was denied on source and clone, so the
clone credential's identity/expiry was **not independently introspected**.
The retained original deadline is administrative metadata, not a verified new
lease or proof of post-expiry behavior.

This establishes same-VPS logical provider-key recovery. Independent production
custody/quorum, separate-host/VPS-loss recovery, full configuration/PKI and
revocation reconciliation, critical audit retention and physical-Agent trust
remain open. Phase 7 and PR #2 remain incomplete.

References: [OpenBao storage/backups](https://openbao.org/docs/concepts/storage/),
[Integrated Storage](https://openbao.org/docs/internals/integrated-storage/),
[Raft snapshot commands](https://openbao.org/docs/commands/operator/raft/) and
[documented restore API semantics](https://openbao.org/docs/2.6.x/api/system/storage/raft/).
The API reference is the published 2.6.x page; confirm the relevant flags and
behavior against the pinned 2.7.1 executable before accepting a test.
