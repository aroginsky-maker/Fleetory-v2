# Generated native Signer backend acceptance

Run `tests/Fleetory.Tools.Tests/NativeSignerBackend.Tests.ps1` with PowerShell
7.3+, .NET 10 and a local Linux Docker engine. Windows uses the existing
`desktop-linux` context; Linux uses the reviewed noninteractive Docker-only
sudo wrapper. No SSH, operator input path or original-material mode exists.
The fixture requires its solution project to have been restored first.

The probe calls the public `OpenBaoCommandSigner` implementation against a
fresh OpenBao 2.7.1 instance, rather than an HTTP mock or the provider CLI. It
constructs an Inventory.Refresh envelope for a new dummy DeviceId, verifies
its signature and shape, and never emits, persists, dispatches or executes
the envelope. Only the generated `fleetory-recovery-fixture` key and a fixed
HTTPS loopback origin are used. The executable accepts neither an endpoint,
key name, input file path nor DeviceId supplied by a caller.

The native cases require one accepted signature and eight specific refusals:
wrong public-key pin, unavailable version 2, a token without signing rights,
an invalid token, a revoked token, an expired one-second token, untrusted TLS
CA and the signing token after self-revocation. The pinned provider returns
HTTP **500** for unavailable version 2; this fixture requires the native
client to reject that exact response. It does not count a 500 as a 403
authorization denial or accept an arbitrary failure as a successful test.
The fixture root is revoked and denied with 403 before the native cases.

Three protocol cases reject missing fields, duplicate fields and an endpoint
override. Input is bounded at 16 KiB with a depth limit and closed field set;
credentials enter only through stdin. Probe output contains categorical
results, no envelope, token, private key, raw peer body or exception message.
All native output is independently checked against generated credential
canaries by the orchestrator.

## Runtime boundary

The fresh provider uses the existing digest-pinned OpenBao image, network
none, no ports or host mounts, UID/GID 100:1000, read-only root, dropped
capabilities, no-new-privileges, private tmpfs and fixed CPU/memory/PID limits.
Its configuration is always generated and its key is newly created; no
snapshot or retained share is loaded.

The worker uses digest-pinned ASP.NET 10 runtime
`sha256:de0ee358cdd672f7017a003bed21e9ac9ed48a27c922a59b18175b6e82fa7fee`.
It shares only the network namespace of that positively owned network-none
provider. The actual worker interfaces are checked to contain only loopback.
No host listener, published port, bridge, route to a source service or live
configuration mount is created. The sole host mount is a newly published,
validated, read-only code payload; only managed assemblies, PDBs and dependency
metadata are admitted. Windows apphost generation is disabled.

Worker ownership binds UUID/name/labels, image ID and creation time. Runtime
inspection checks UID/GID 1654:1654, private PID/IPC, read-only root, cap-drop
ALL, no-new-privileges, 256 MiB/0.5 CPU/64 PIDs, core dumps disabled and one
0700 tmpfs. Public generated CA files use private tmpfs permissions; the
process-scoped trust bundle and empty certificate directory do not alter host
trust. Tokens are never Docker arguments, environment variables or mounted
files. Both containers expire independently after 3,300 seconds with
auto-removal. Cleanup also handles a lost worker-run response by inspecting
only its fresh UUID name and verifying ownership before removal. It attempts
both cleanups even after an error; success is emitted only after verified
absence and removal of the owned public payload directory.

The portable boundary contract rejects 21 unsafe metadata mutations, including
wrong source namespace/identity, privileged execution, ports, writable/live
mounts, weakened resources/tmpfs, added credential environment and expiry
removal. Windows CI runs this contract; Linux CI also runs the native fixture.

## Acceptance limits

This establishes generated-only native component authentication, TLS trust,
key verification and credential refusal against a real backend. It does not
start the complete Signer host, authenticate Server PostgreSQL/immudb paths,
restore an original key, prove deployed-release continuity, test an original
credential or verify hostname mismatch against this real backend. Existing
HTTP fault/unit tests remain separate evidence.

The previous [actual target-credential operation](OpenBaoRecovery.md#verified-actual-target-credential-recovery---4-november-2026-utc)
remains a consumed, separately approved CLI operation. This fixture neither
repeats it nor gains permission to read original provider/PKI material. Original
provider recovery belongs inside an approved provider/DR boundary, never on
the operator workstation. Full startup, current revocations, human login,
common-point/VPS-loss recovery, independent WORM/custody/approvals, physical
Agent trust and full RPO/RTO remain open. Phase 7 is incomplete and PR #2 stays
draft.
