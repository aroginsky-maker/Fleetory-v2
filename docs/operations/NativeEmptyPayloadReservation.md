# Empty payload reservation by the native owner

The historical PowerShell entrypoint has a separate `-PayloadReservationOnly`
mode. It uses the existing held process/control fence and creates only a fresh
directory containing one public metadata marker. It does not accept archive
bytes, credentials, keys, backend addresses or a request to restore data.
The original close-only preparation mode remains separate.

The controller holds three executable entrypoints and 34 fixed component/root
files. The first bounded header binds the native plan, revision/code snapshot,
Git digest, held control-directory identity and selected-source inventory.
Only after the actual PowerShell image/PID/birth and ready frame match does the
controller exclusively write and flush `native-payload-intent.json`. A fresh
deadline check precedes authorization to reserve the empty directory.

A fixed Python helper creates the directory under the copied repository's
`artifacts` directory. Its nonce determines the single permitted basename.
The helper requires its actual direct-parent PID to match the native owner;
the marker records that logical owner, control identity, source digest and
directory identity. The controller independently holds that directory and
marker and binds them to the observed PowerShell process through the existing
`BoundPayload` checks. A preexisting namespace is never adopted by creation.

The controller publishes the held payload binding and release records, then a
separate close request. It rechecks its deadline after publication before
sending the only permitted continuation: remove empty metadata. The helper
reopens only the exact recorded reservation under the same native parent,
checks the marker and directory identities, and refuses any additional files.
Trailing input is rejected before removal. Success additionally requires a
matching acknowledgement, independent process-member absence, deletion of the
original held directory and absence of its pathname.

A refusal, partial response, missing record or owner exit does not authorize
generic cleanup. Unknown reservations are preserved. Refusal metadata
distinguishes a reservation not attempted from an unknown or observed state;
it does not claim that a failed helper created nothing. Backend cleanup,
private-input release and full-system recovery remain false.

Portable contracts exercise strict metadata, parent delegation, foreign and
hardlinked markers, nonempty directories, callback isolation and expiry during
intent/close publication. Native fixtures run the real PowerShell code on a
separate minimal repository copied from the 34 public components/root inputs.
The fixture has its own generated Git revision and a generated application
source stub; it does not represent the deployed application or a full
application recovery point. SDK metadata is copied as public input, without
running an SDK or building an application in this fixture.

Six native cases cover successful reservation/removal, consumed replay,
private authorization refusal, foreign namespace preservation, invalid close,
trailing input and owner exit after binding. The latter failures preserve an
unknown marker-only reservation; their public temporary fixture is disposed
by the test owner after process closure. This is not owner-death cleanup of
an operational backend. Both native and portable gates are mandatory on
Windows and Linux without changing jobs, budgets, timeouts or quality limits.

Full legacy payload/image/container handoff, complete release/runtime
provenance and cleanup after owner death with real backends remain open.
This mode grants no original-data, PKI, provider/root/issuer or production-token
authority. Full-system recovery and Phase 7 remain incomplete.

The separate [linked generated image/container gate](LinkedRecoveryResources.md) provides the same-session immutable-image dependency needed before native resource acknowledgement and legacy application handoff.
