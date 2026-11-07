# Historical owner readiness without private input

The actual `Invoke-HistoricalAuditObservation.ps1` entrypoint now has a separate
`-PreparationOnly` mode. It loads the small preparation dependency set and exits
before creating the legacy payload/context, changing builder state, generating
keys, publishing probes, building images, contacting Docker or restoring data.
The ordinary historical-controller path retains its existing behavior and tests.

The fixed Python launcher sends only a bounded metadata header containing the
native plan, control nonce and reservation digest. The existing strict V2 plan
decoder checks its references, historical-only scope and limits; no archive,
event values, state, key or endpoint is admitted. The owner checks the actual
repository revision and application/build-input snapshot before emitting ready.
Probe/input byte checks are not performed or claimed by this mode.

Before sending the header, the process fence checks the actual PowerShell image
and OS birth identity. The launcher holds the repository directory, Python and
PowerShell executables and 32 fixed source/root inputs. Ready must match the
live owned PID and header/plan/control/code identities. Its raw-frame digest,
selected-source inventory digest and observed process identity are exclusively
written and flushed into `native-ready.json` under the held control session.
The original eleven-file Python payload profile remains separate and unchanged.

Only a close-without-input frame can follow ready. The controller flushes a
separate `native-close.json`, rechecks its deadline after publication and then
sends close. A flush that crosses the deadline sends no close frame. The owner
strictly rejects duplicate/extra fields, foreign pins, continuation commands,
private payload fields and trailing input. A matching closed acknowledgement
and independent process-fence termination are required for acceptance. Missing,
partial, unreadable or mismatched records remain an unverified outcome.

The 32-input preparation inventory includes eight root build inputs. A narrowly
scoped descriptor handles the fixed public `.editorconfig` leaf; the generic
recovery-file path grammar still rejects hidden paths. Source and runtime pins
are checked again through closure. The selected Git path is trusted-host
configuration; its binary and the complete PowerShell/Python/native dependency
sets are not authenticated by this profile. The aggregate code check remains a
snapshot rather than an atomic or complete lifetime-held legacy build.

Portable contracts cover framing, plan/scope/nonce pins, callback isolation,
foreign records, forged PID/backend claims, bounds, input refusal and deadline
expiry during close publication. Actual owner tests cover successful ready and
close, consumed launch replay, wrong code and a private-continuation injection.
They independently check owned process-member absence and unchanged legacy
payload namespaces. A temporarily supplied local SDK metadata file is removed
only when this fixture created it and its exact bytes remain unchanged; no SDK
is installed or executed by the preparation fixture.

This accepts close-only readiness of the actual owner, not private-input
release, legacy payload/image/container namespace handoff or backend cleanup.
The transport callback is a fixed trusted-host implementation selected by the
closed preparation profile; wire data cannot choose callbacks or commands.
Legacy resource intent integration, approved toolchain continuity and owner
death after container creation/restore remain open before original dispatch.
No new original-data, private PKI, provider/root/issuer or production-token
authority is granted. Full-system recovery and Phase 7 completion remain open.
