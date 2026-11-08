# Public sleep cleanup protocol preparation

`audit_cleanup_protocol.py` is a bounded metadata-only model. It has no Docker,
process, filesystem-target, deletion or executor API. A valid model result cannot
authorize an operation. Controller/supervisor observations and the create receipt
are explicitly asserted data. Actual OS identity, receipt origin, durable state,
independent expiry enforcement and cleanup remain unverified and reported false.

Ticket bytes are frozen before parsing. All four assertion frames are frozen
once before any of them is validated or hashed; caller bytearray mutation cannot
change which bytes a candidate binds.

The pinned protocol covers exactly one generated sleep worker:

- Separate controller and supervisor nonces, distinct PIDs, matching OS birth-token
  kinds, canonical nonzero birth tokens and executable hashes.
- Full immutable container/image IDs, the fixed runtime name and profile, nonce,
  reservation, image/runtime intent and binding pins, publication/readback pins,
  held-descriptor digest and runtime code digest.
- Complete bounded create-receipt bytes with a matching hash, resource identities,
  labels, creation time, nonce, reservation and runtime intent. The current resource
  assertion must match those identities and the complete label hash. Matching a
  mutable name cannot adopt another ID. Missing resources/states are refusals.
- Arming before admission expiry; admission at most 60 seconds from opening; a
  fixed 10-second model reaction window. Wall and monotonic clocks both enforce
  the hard bound and reject rollback. The fixed command lifetime stays 660 seconds.

A matching live-controller model waits without consumption. Asserted controller
exit or model admission expiry consumes one proposal before returning
`trusted-enforcer-required`. Unknown/dead supervisor, unknown controller state,
changed birth identity, wrong receipt/resource, invalid pin or clock failure
refuses terminally. Replays of that object fail. No branch returns cleanup
permission; even a fully matching candidate has `cleanupAuthorized=false`.

The in-memory model is not a durable anti-replay store: constructing a fresh
model from the same ticket can succeed while its admission remains valid. It
also does not authenticate asserted exit using a PID, signature or actual held
process object. These gaps are explicit and cannot be closed by metadata flags.

Before an actual independent supervisor is connected, the trusted host must hold
and verify real process handles/pidfds and birth/image identities, obtain the
receipt at its own successful Docker create boundary, retain source/namespace
identity, consume a durable attempt before action, and reobserve the full immutable
ID plus its owned labels/image. Only that one own create receipt may be considered;
name-based discovery, broad cleanup, image/cache/network/volume deletion and
original data/secret/PKI paths are outside this protocol. Supervisor death and
unknown or late outcomes must never be reported as successful cleanup.

`cleanup_protocol_tests.py` uses generated assertions and controlled clocks.
Its 31 contracts cover schema/type/size limits, receipt consistency, OS-token
kinds, PID reuse, foreign IDs, label changes, both triggers, hard deadlines,
rollback, mutation and replay. CI requires them on Windows and Linux. The suite starts no containers and has no restore or runtime actions. Existing
mandatory CI gates remain required; completed local restores and unchanged native
experiments are not rerun for this contract change.
Actual independent expiry/controller-death cleanup, operational/service leases,
full recovery and the remaining Baseline requirements stay open. Phase 7 and
PR #2 remain open; no production or privileged cleanup grant is added.
