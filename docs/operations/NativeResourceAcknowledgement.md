# Native acknowledgement of generated recovery receipts

The native owner has a fixed metadata-only mode, `-ResourceAcknowledgementOnly`.
It extends the accepted empty namespace protocol while preserving its existing
three-frame mode. The parent holds 40 selected public source/build files and
three entrypoint pins, authenticates the actual PowerShell process through the
OS lifetime fence, accepts its ready frame and independently binds the empty
payload directory and marker before offering any resource metadata.

Only an already-bound `ImageBinding` and `LinkedContainerBinding` from the same
held control are accepted. The typed receipt contains the immutable image ID,
container ID, both intent hashes, both exact binding record hashes and their
shared expiry. The controller rechecks these objects before and after every
publication. The resource intent record also binds the header, ready frame,
payload-binding record hash and observed process identity. An offer carries
only the typed receipt and the relevant control/namespace hashes.

The PowerShell owner delegates receipt validation to its fixed, pinned Python
helper. The helper requires the actual direct parent PID, reopens only the
owner's exact marker-only reservation and validates strict keys, types, IDs,
nonce, control hashes and expiry. It neither operates Docker nor restores or
removes backend resources. The resulting acknowledgement binds the parsed IDs,
receipt hash, intent hash, header, ready frame, payload marker/directory and
native PID. The parent re-observes the pipe peer's OS identity before publishing
an exclusive acknowledgement record. The waiter is released only after that
record is flushed and current pins and deadlines pass again.

Final acceptance also requires the normal empty namespace removal, exact final
frame, successful owner exit, no process-fence members and live source receipts.
A copied PID, stale pair, foreign controller, substituted receipt, duplicate
publication, expired flush or interrupted owner never grants final acceptance.
Unknown reservations are preserved. Metadata records do not confer backend
cleanup or private-input release authority.

Portable contracts and six actual PowerShell cases run on Windows and Linux:
normal acknowledgement/removal, invalid offer, forged acknowledgement, owner
exit after acknowledgement, source expiry after acknowledgement and invalid
close. Consumed launch replay is refused. Fixtures copy only the selected
public files and a generated source stub into a synthetic Git revision; they
do not claim to build or observe the Fleetory application revision.

A separate Docker fixture uses genuine quiet-build/create receipts for three
untagged label-only images and constrained containers. The native owner accepts
one pair; an invalid offer and owner exit fail. A separate sentinel survives.
Fixture cleanup checks only its own receipt IDs, labels and immutable image
relationships, removes containers before images without image force/pruning,
and verifies absence while preserving the cached base. This cleanup belongs
to the test fixture and does not prove operational cleanup after owner death.
The mandatory Linux CI gate and local Windows Docker run compare their proof
apart from Docker version; the metadata-only native cases run on both CI OSes.

The original empty namespace profile keeps its 34-file inventory, the close-only
profile keeps 32, and the earlier Python payload inventory keeps 11. No generic
wire path, executable, endpoint, command, key or archive option was added. The
new mode branches before the legacy build, key generation and backend path.

`nativeOwnerResourceAcknowledged` can now be true only for the completed
metadata handshake. `legacyNativeOwnerIntegrated`, `legacyApplicationImageVerified`,
Docker observation authenticity, backend control/cleanup authorization,
original-input release and full-system recovery remain false. Binding the
actual application/probe image, accepted build/runtime provenance and operational
owner-death cleanup are still required before original-data dispatch. Phase 7
remains open. This step needs no additional secret/PKI permission or VPS access.

[Fixed public probe image build](ProbeImageBuild.md) separately freezes the
actual published probe bundle and legacy recipe. Its image type is intentionally
not admitted by the original Python/native receipt profile; the operational
native image/runtime handoff remains open.
