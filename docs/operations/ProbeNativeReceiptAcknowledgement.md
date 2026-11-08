# Native acknowledgement of public probe receipts

`audit_native_probe_runtime.py` adds a separate fixed native receipt profile for
an already-bound exact `ProbeImageBinding` and `ProbeRuntimeBinding` in the same
held controller. The receipt pins both immutable IDs, both binding and intent
hashes, bundle manifest, source code, full runtime JSON profile and shared expiry.
The source digest must match the native preparation header. Receipt, offer, ACK,
action, refusal and bound/result schemas are distinct from the Python profile.

The native owner is launched through its fixed `ProbeRuntimeAcknowledgementOnly`
mode. The selected 45 public source/build-input files, including the exact pinned
JSON profile, stay held through the OS fence, independently bound empty metadata
namespace, live pipe acknowledgement, closing and report. Existing 40/34/32 native
inventories and the original Python/linked receipt schema remain closed. Native
code takes no caller-selected module, command, endpoint, archive, key or token.

The common protocol preserves one-use intent/ACK files, ready/header/owner and
namespace hashes, live PID/birth identity checks and deadlines. A repeated ACK is
refused immediately. Expiry during intent or ACK flush cannot grant acceptance;
an already-published unknown record is preserved. Final acceptance requires the
valid close and absence of owned process members and the original empty namespace.

Portable contracts check full receipt projection, foreign/old/fake types, source
and profile drift, strict fields/types/expiry, header source matching, frame bounds,
parent/schema refusals, factory closure, one-use ACK and expiry during publication.
Actual copied-public PowerShell cases cover success, bad offer, bad ACK, owner
exit, expiry after ACK and bad close. Foreign sentinels/source records survive;
unknown interrupted reservations remain within the disposable public fixture.

The actual-public Docker fixture publishes the current probe, holds the complete
bundle, builds one untagged image and reads every file back from a stopped copy.
It runs one isolated sleep worker, verifies the accepted kernel/runtime profile,
then starts the actual fenced native owner against the real selected public sources.
The native owner acknowledges those exact live controller receipts and removes its
own empty metadata namespace. Native launch replay is refused; fixture-owned sleep,
stopped copy and final image are disposed through their original receipts. Local
and CI publication revisions/hashes/byte counts are retained independently.

Build and container-create receipts are produced by the trusted test fixture before
the native owner starts. Acknowledgement covers their typed, pinned metadata; native
production of build/create receipts is still open. The 60-second image admission
and 30-second native protocol limits stay unchanged. The 660-second sleep argument
grants no operational lease or runtime continuity. Backend services started: zero.

Reports keep backend control/cleanup, actual native build/create, operational lease,
owner-death backend cleanup, deployed release provenance and full recovery false.
Original archives, service credentials, private PKI, VPS, provider/root/issuer and
production tokens are unused. Next: native-owned public build/create production,
a separate bounded operation lease and generated kill-after-build/create/restore
cleanup. Coordinated full-service recovery and Baseline Phase 7 remain open.

Actual public receipt-fixture failures are covered by
[PublicProbeOwnerFaults.md](PublicProbeOwnerFaults.md).

The separate [native public container creation](NativeProbeCreation.md) profile now
produces its own sleep-container receipt; this earlier acknowledgement profile
continues to cover fixture-precreated resources only.
