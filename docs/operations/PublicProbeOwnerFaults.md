# Public probe native owner faults

The Linux CI and local Docker rehearsal adds two actual-public fault cases to the
accepted native receipt handshake: a malformed offer and native owner death after
receipt ACK. An unrelated stopped container remains present throughout both cases.
No backend service, original archive, credential, private PKI or VPS is used.

The rehearsal creates an empty local Git repository and fetches exactly the current
public commit with depth1 and no tags. Only local file transport is allowed; global
Git configuration, system configuration, attributes and hooks are excluded. Before
checkout, the public tree is bounded to2048 regular blobs/64MiB total, at most4MiB
per file and262144 bytes of metadata. Links/submodules, Git metadata paths, traversal,
Windows reserved names and case/directory aliases are refused. Every checked-out
blob byte sequence matches the Git object format; this format check uses SHA1 as a
non-security Git identifier, not as software-origin authentication. The full tree
and source revision are retained. Build dependencies are restored normally in the
copy; no advisory/security gate is disabled. The operator checkout/ref and active
SDK input are checked unchanged.

The actual current public probe is published in that copy, frozen, built into one
untagged image and read back from a stopped container for each case. One isolated
sleep worker per case uses the accepted UID3322 runtime and kernel checks. The
actual fenced PowerShell owner runs against the selected45 public source files.
The bad offer changes only the test protocol frame; the second case observes the
owner still alive immediately before killing it after a verified receipt ACK.

A startup failure, wrong refusal stage, timeout before injection, unverified owner,
unconsumed launch, surviving process members or private/operational acceptance is
never counted as the intended fault. The failed operation cannot grant final native
ACK acceptance. Source image/container records are unchanged; consumed native launch
replay is refused without spawning. Unknown empty reservations retain their exact
owner marker inside the disposable copy before the entire public fixture is removed.

The independent cleanup actor is the trusted test-fixture parent. It uses its own
successful create/build receipt IDs plus exact name, image and labels. Own sleep,
stopped-readback and final image receipts must be absent after unwinding the fault;
all three cached bases and the unrelated stopped sentinel are preserved. Image
removal does not force or prune parents. The sentinel is disposed later by its own
fixture receipt. No global Docker prune or label-only deletion is used.

This closes generated public receipt-fixture fault cleanup only. The resources are
still created by the trusted fixture before the native owner starts. Native-owned
publication/build/create production, the pre-receipt crash gap, a separate bounded
operational lease, intermediate builder cache cleanup and operational backend
owner-death cleanup remain open. The60-second admission and30-second native limits
are unchanged. Full coordinated recovery, independent gates and Phase7 remain open.
