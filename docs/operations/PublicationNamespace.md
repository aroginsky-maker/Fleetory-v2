# Held public publication namespace

`audit_publication_namespace.py` adds a separate `native-probe-publication-<nonce>`
namespace containing one owner marker and a fixed `publish` child. It does not
modify the existing empty-only `native-audit-controller` namespace, its marker or
its removal rules. Old 46/45/40/34/32/11 source profiles keep their inventories.

The owner claims a fresh directory with exclusive creation. Its marker binds the
controller nonce/reservation/directory, exact intent, selected source pin, manifest
pin, actual owner PID and both directory identities. The controller independently
reopens the marker and directories while re-observing the live OS-fenced process
image and birth. A consumed controller attempt prevents re-binding.

Sealing is a separate one-use operation. It uses the existing bounded public probe
manifest: at most 256 entries/128 files, 15 MiB content, DLL/JSON/PDB extensions and
required probe/runtime files. Both owner and controller retain no-follow file and
directory descriptors and recheck exact tree, hashes, lengths and identities.
Unknown files, links, aliases, replacement roots/markers, changed files and wrong
manifests fail closed. The controller records an owner ACK only after matching the
independent sealed receipt. Release is exclusive and grants no deletion authority.
Close preserves the namespace, including failed or unknown outcomes.

The actual fixture uses a fixed Python worker with a real Windows Job or Linux
process-group/pidfd fence. It pins 17 library source files plus its fixed entrypoint,
releases input after observing the owner and consumes launch before spawn. Three
synthetic cases run on both operating systems: positive handoff, explicit typed
manifest-pin refusal and live owner exit before ACK. Startup failures/timeouts do
not count as a typed refusal. Replay is refused before spawn. Parent fixture cleanup
is disposal of its separate whole temporary repository after all handles and owned
process members are closed; the library has no cleanup or publisher CLI. On POSIX,
exit is observed without reaping; group birth/ID checks and cleanup precede wait.

The real-public variant first publishes the current public ServerBackendProbe with
the pinned SDK through the existing trusted parent fixture. It holds that full
manifest, copies the bounded public bytes into the owner-created namespace, and
proves independent owner/controller sealing of every output descriptor. The
publication occurs before the 30-second handoff fence starts. No application,
backend, Docker service, private input, PKI, VPS or issuer is started by this gate.
Local/CI actual source revisions, manifests, SDK/entrypoint hashes and owner birth
records remain separate; binary identity is not inferred.

This namespace fixture verifies handoff only; its owner is Python. The separate
historical PowerShell publisher below verifies native publication without changing
that fixture's claims. Native image build, full SDK/package/compiler input
continuity, operation lease, pre-receipt/controller-death cleanup and full recovery
remain open. Existing 30-second native and 60-second image admission limits stay
unchanged. Original data, secrets and PKI need their own current scope; no new
sensitive permission is implied. Phase 7 stays open.

The fixed historical PowerShell publisher integration is documented in
[Native public publication](NativePublicPublication.md). The namespace library
itself continues to make no native compiler or full recovery claim.
