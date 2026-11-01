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

References: [OpenBao storage/backups](https://openbao.org/docs/concepts/storage/),
[Integrated Storage](https://openbao.org/docs/internals/integrated-storage/),
[Raft snapshot commands](https://openbao.org/docs/commands/operator/raft/) and
[documented restore API semantics](https://openbao.org/docs/2.6.x/api/system/storage/raft/).
The API reference is the published 2.6.x page; confirm the relevant flags and
behavior against the pinned 2.7.1 executable before accepting a test.
