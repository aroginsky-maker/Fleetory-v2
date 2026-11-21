# Native public container creation faults

`native_public_create_faults.py` adds two real public-data failure cases to the
46-file native creator. The earlier public owner-fault gate continues to cover
fixture-precreated resources under its original schema. Both reuse the bounded
single-commit public Git copy, dependency restore, stopped sentinel, base-image
preservation and whole-fixture disposal code. No production gate or source profile
is relaxed.

The malformed-create case alters the actual pipe offer after the empty metadata
reservation is bound. The native helper must return its typed `create` refusal.
The runtime remains unbound, its observation-attempt slot is absent, no native
create receipt exists and the exact intended Docker name remains absent. A startup
failure or timeout cannot count as this injection.

The owner-exit case waits until the controller has persisted and fsynced its native
create receipt and backend binding. The test re-observes the live owner PID, birth
and image identity, then kills that owner before any resource-receipt ACK offer.
The OS fence must end without live members and final native acceptance remains
false. The native-created Docker worker is observed still running with the fixed
profile; it is outside that process fence. The surviving trusted fixture parent
then removes only its complete native create receipt after matching the full ID,
name, labels and immutable image.

Ownership transfer checks the held controller records, nonce, native executable,
owner identity, exact intent hash, header, backend-binding hash and public-only
flags. A label, partial ID, unbound intent or foreign record grants no adoption or
cleanup. Unknown native marker directories are preserved until the separate public
copy is disposed. Replay is refused before spawn. The unrelated stopped sentinel
and three cached base images remain intact; original checkout and SDK input are
unchanged. Public build manifests, image IDs, owner birth records and create receipt
hashes are retained separately for local and CI builds, without binary-identity
claims.

Portable fault/ownership contracts run on Windows and Linux; the real Docker fault
gate runs on Linux CI and locally. Native creation still uses the existing
30-second protocol and 60-second image admission limits. The fixed 660-second sleep
is not an operational lease.

This verifies generated native-create fault cleanup by a surviving fixture parent
only. Death before a durable create receipt, controller/supervisor death, native
publication/image build, non-empty publication namespace, compiler input continuity,
intermediate cache cleanup and operational service recovery remain open. No original
data, credentials, private PKI, VPS, provider/root/issuer or production tokens are
used. Phase 7 and full coordinated recovery remain open.

The next separate public publication namespace is described in
[PublicationNamespace.md](PublicationNamespace.md). Its Python fixture proves
namespace handoff only; native publication/build remain open.
