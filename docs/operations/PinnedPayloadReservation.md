# Pinned payload reservation

`audit_launch_bundle.py`, `audit_payload_launch.py` and the fixed
`audit_payload_owner.py` add a metadata-only reservation protocol to the
[owned process fence](OwnedProcessFence.md). This owner creates one disposable
directory; it has no archive, database, Docker, private-key, provider or issuer
operation. The legacy PowerShell audit restore owner remains a separate path.

An externally pinned manifest binds a canonical operation nonce and revision,
one Python executable hash and the exact eleven local source files used by
this profile, including both OS implementations and every local import. Missing,
additional, aliased, linked or changed files are refused. Each source is bounded
to 512 KiB and its read descriptor and parent-directory identity remain held.
The runtime is bounded to 64 MiB. The repository root is also held and rechecked.
The fixed owner runs with `-I -B`; it adds only its own measured source directory
for local imports. There is no generic command, root, endpoint or user-data CLI.

These are measured, retained component pins on a trusted host. They do not
authenticate the source of the approved manifest, Python standard library,
interpreter/native dependencies, external gates or consent. Runtime dependency,
full transitive software origin and full-system authority flags remain false.
This fixed inventory does not claim to pin the legacy restore toolchain or a
published ServerBackendProbe/dependency set.

After the launch attempt is flushed and the actual OS image/birth is checked,
the parent sends a bounded metadata frame. It includes the control reservation
hash, held control-directory identity hash, component-manifest hash and nonce.
The child exclusively creates `artifacts/native-audit-controller-<nonce>` under
the trusted repository, then writes and flushes one `controller-owner.json`.
It holds that directory and the single-link marker while awaiting release.
There is no precreation or adoption by the parent.

The ready frame reports the marker hash and the child's actual directory
identity hash. The parent opens the known directory, retains its identity and
marker descriptor, checks the marker against the live owned process handle or
unreaped process group, and rechecks component and control identities. Identical
marker bytes in a replacement directory cannot satisfy the directory identity.
It then exclusively writes/flushed `payload-binding.json` inside the held
control namespace. A duplicate, corrupt, partial or unavailable record is a
refusal, never an empty resource set or permission to remove anything.

Only after those checks does the parent flush `payload-release.json`, close its
marker pin and send a fixed finish frame. The child rechecks its own directory,
marker and exact one-file layout, then removes only that marker and empty
directory. Cleanup is nonrecursive. The parent requires the original retained
directory to be deleted (POSIX link count zero or Windows delete-pending),
releases its handle and independently verifies path absence. A claimed closed
frame alone is insufficient. The consumed control/binding/release records stay.

Early exit, forced owner death, unexpected files, failed writes or identity
changes preserve an unverified outcome. The parent has no cleanup API. OS
process termination is not permission to delete a remaining payload, and this
protocol has no backend namespace or backend cleanup capability. Directory
identity and source pins assume the existing trusted account/host; independent
rollback resistance and complete power-loss recovery are not certified.

```powershell
python -B tests/Fleetory.Tools.Tests/audit_payload_launch_tests.py
```

CI requires the actual protocol on Windows and Linux. Contracts cover component
inventory/closure, manifest replay/mutation/bounds, source and root identities,
actual process PID, preexisting namespaces/records, copied-marker substitution,
binding flush failure, early exit, forced owner death, nonrecursive refusal,
forged cleanup receipts and input field boundaries. Existing process and control
regressions remain mandatory. All inputs and resources are generated temporary
test material; no original archive, PKI, VPS or provider session is accessed.

Before original or legacy native restore dispatch, integration still needs the
complete approved restore runtime/source/probe set, private native readiness
and immutable backend resource intents, independent ownership-checked backend
absence after owner death, current authenticated gates/public trust and the
existing durable audit-only purpose transaction before original capture.
This step grants no new secret/PKI/root/issuer or production-token authority.
Phase 7 remains open and PR #2 remains draft and unmerged.
