# Consumed public cleanup attempt

`audit_cleanup_attempt.py` closes the local restart/replay preparation gap left
by the in-memory cleanup model. It reserves one fixed
`public-sleep-cleanup-<nonce>.json` name under a trusted caller's retained
operator directory. The API has no command line, callback, process, Docker,
reset, deletion or operational-lease capability.

All ticket, asserted create-receipt and resource buffers are copied before any
of them is parsed, validated or hashed. The existing protocol checks their full
schema and relationships, the exact ticket pin and the bounded time window.
The record binds the controller/supervisor identities, separate nonces, complete
container/image IDs, reservation/runtime intent and the three exact byte hashes.
Those process and receipt values remain assertions in this library.

The existing exclusive-create primitive refuses every existing name, including
empty, partial, malformed or different-ticket records. Windows uses CREATE_NEW,
write-through and no sharing; POSIX uses O_EXCL/O_NOFOLLOW with mode 0600 under a
held directory descriptor. Descriptors are non-inheritable. The module requires
an owned mode-0700 POSIX operator directory and retains the directory's OS
identity. Windows directory ACL provisioning and custody remain the trusted
caller's responsibility and are explicitly not authenticated by this library.
During the operation an additional Windows handle denies write/delete sharing
on the existing ordinary operator directory before ledger creation. This does
not change its ACL or authenticate protection of its parent path.

The single bounded write must complete in full; short writes fail without
retrying or removing the created name. The file is flushed before a session is
returned; POSIX also flushes its containing directory. The result's
`localConsumedRecordFlushed` flag is added only after these operations succeed;
it is not written speculatively into the persistent record. A flush error or a
lost caller response leaves the name consumed. No exception contents are stored.

Every report and successful context exit rechecks the held file, exact bytes,
single-link state, path/directory identity, private POSIX mode and current caller
process. Reports are fresh decoded copies; caller mutation cannot rearm the
attempt. Closing the observer does not remove or reset the record. A fresh
process with the same nonce is refused while the record remains in place,
including when it supplies a different otherwise valid ticket.

Seventeen generated filesystem contracts cover one winner among eight concurrent
claimants, separate-process replays after normal and abrupt process exit, wrong
packets, mutable input races, lost responses, short writes, flush failure,
changed bytes/directories, hardlinks, malformed
existing records, closure/fork guards, returned-record mutation and OS-specific
mode/exclusive-sharing checks. Windows and Linux CI require the suite without
soft failure or skipped methods.

This is a local consumed record under a protected, retained directory, not an
independent anti-rollback store. Deleting/restoring the directory, privileged
tampering, filesystem/controller power-loss behavior and external custody are
not proved by a process-restart test. The record neither authenticates a Docker
create receipt nor makes the read-only supervisor independent. Actual receipt
origin, connected lifetime enforcement, immutable-ID resource reobservation,
expiry/controller/supervisor-death cleanup and a full service recovery remain
open. No original input, secret, private PKI, provider or VPS is used. Phase 7
and draft PR #2 remain open.
