# Held native publication continuation

The `native-publication-retain` profile keeps the fixed public PowerShell publisher,
its four frames, 30-second native fence and 20-second compiler limit. It has a
separate 40-file controller inventory. The old publication profile still selects
36 files; the old preparation/import inventories remain closed.

After independent validation of the complete native publication and owner ACK,
the controller moves the existing namespace, marker, directory and file leases
into a provisional capability. It does not reopen the publication to establish
continuity. Native release closes an empty lease stack. The capability stays
unusable until the normal native close frame, zero exit and absence of running
owned process members have all been verified. A consumed attempt and a binding
record connect the controller identity, actual native owner, receipt, release,
manifest and native process evidence.

The capability lasts at most 60 seconds from capture, checked against both wall
and monotonic clocks. A clock rollback, expiry, controller PID change, closed
control session, changed source pin, replaced directory, unexpected file or
changed public byte refuses use. The repository and all 40 controller source
pins remain held through the enclosing context. Closing the context releases
the transferred descriptors and preserves the publication namespace.

Exactly one image intent can be requested. Invalid base metadata consumes that
attempt. The existing fixed three-base recipe, deterministic context and image
ID binding are reused. The image binding checks the capability on every access;
it cannot outlive close or expiry. A single readback attempt must bind that same
image and controller to a never-started, read-only, network-none copy container,
with no mounts and the fixed `/bin/true` entrypoint. The complete TAR is checked
against the still-held bundle before the receipt is written. Corruption, foreign
resources, boolean aliases and extra observation fields refuse acceptance.
A refusal remains consumed, including when a later flush crosses the deadline.

`publication_continuation_tests.py` uses generated files and explicitly synthetic
native evidence to test the state machine and failures. It is not actual native
execution evidence. CI runs it on Windows and Linux. The existing actual public
fault fixture also performs one positive retained publication, reusing only its
public source copy, restore and reference build. All three existing fault cases
remain required. `--continuation` verifies actual native close and held context
on Windows; `--continuation-image` additionally builds one untagged image and
creates one stopped copy for full readback on Linux. The latter mode can also
run locally against the already authorized Linux Docker engine. It starts no
service, opens no port and loads no original backup, secret or PKI.

The fixture removes only its own stopped container and untagged image from
validated receipts, then disposes its own public copy. Base images remain.
This is public fixture cleanup, not operational cleanup authority. A Docker
build request already submitted is not proven cancelled at capability expiry;
late results cannot be accepted. Intermediate cache cleanup, daemon identity,
compiler/package provenance, controller-death recovery, a live runtime/service
lease, deployed image/configuration lineage and full recovery remain open.
No production cleanup, original secret/PKI, provider, root, issuer or token grant
is added. Phase 7 and PR #2 remain open.
