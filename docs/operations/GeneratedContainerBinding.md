# Generated container metadata bound to held control

`audit_backend_binding.py` adds one consumed resource-intent attempt and one
consumed observation attempt to an existing identity-held control session.
Both attempt records are created exclusively and flushed before admitting
their inputs. A failed validation or publication cannot reuse the attempt.
The immutable intent includes the control nonce, revision and reservation
digest, one derived container name, three exact control labels, the existing
pinned synthetic Python image reference and its expected local image ID.
This is a separate generated metadata profile; it does not change the fixed
Python payload owner's protocol or grant creation authority.

An observation must match the full container ID separately returned by the
trusted caller's Docker create/run operation. The name, image ID, reference,
labels and fresh UTC creation time must also match. The profile requires the
fixed empty Python sleeper, UID/GID 65534, network none, read-only root,
capability drop, no-new-privileges, 64 MiB/0.25 CPU/32 PID limits, no mounts,
ports, devices, added capabilities, shared host namespaces or restart policy.
The native fixture requests selected inspect fields only, excluding environment
variables, logs and volume contents. Extra top-level metadata is refused.

Binding has a sixty-second wall-clock window and a separate monotonic deadline.
It records the input digest and observed identity in another immutable,
flushed file held by the control session. Both deadlines and the retained
control/record identities are checked again after publication. Expiry during
the final flush returns no accepted binding, even if that record exists.
Missing, partial, modified or unreadable records are unknown outcomes; they
are never interpreted as an empty resource set. Foreign files and consumed
records remain in place. The module has no Docker or deletion API.

Portable tests cover identity, labels, timing, isolation, strict input shape,
replay, write/flush failure, record modification and control-directory
replacement. A separate local Docker fixture creates two fresh empty
containers under three generated control sessions, binds one actual ID,
refuses the other container's observation under a foreign control session,
checks that the sentinel is unchanged, and independently verifies removal of
its two known IDs. An additional injected inspect failure checks removal of
one further fresh container using the smaller identity-only inspection path.
Fixture cleanup uses its own successful Docker receipts and
checked identity fields; a binding report does not authorize cleanup.

The supplied Docker observation is validated metadata, not cryptographic
authentication of the client, daemon, image origin or continuous runtime state.
The report keeps those claims and legacy native owner integration false.
The shared cached upstream image is inspected; no built image/tag is created
or claimed. Image-build intents remain separate work. No archive, private key,
credential, endpoint or arbitrary command is admitted by this profile.

This closes the generated container-ID binding prerequisite only. The legacy
PowerShell/immudb owner still chooses its own payload/image namespaces. Its
readiness protocol, complete toolchain/execution continuity, actual resource
handoff and abrupt-owner-death backend cleanup must be integrated and checked
before original-data dispatch. The [application input snapshots](LegacyAuditInputPins.md)
and [held control identity](AuditControlIdentity.md) remain distinct evidence.
Full-system recovery, independent custody/WORM/signoff and Phase 7 completion
are not established by these tests.
