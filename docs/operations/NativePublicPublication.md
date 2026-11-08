# Fixed native public publication

The historical PowerShell entrypoint has a separate PublicProbePublicationOnly
mode. It runs the fixed dotnet publish for
eng/ServerBackendProbe/ServerBackendProbe.csproj in Release, with no restore,
no apphost and build servers disabled. It does not start the probe, Server,
a backend, an image build or an issuer.

The trusted host pins the dotnet executable and 36 selected source/build
inputs. The native owner checks Git, the full selected code snapshot and
SDK 10.0.402, then checks the source snapshot and dotnet bytes again around
publication. These are selected input measurements; they do not authenticate
the complete compiler, package, task or SDK dependency closure.

Before launch, the host freezes a bounded expected manifest from a public
reference publication at the same project path and SDK. The new header admits
at most 12 KiB of manifest bytes and must also satisfy the existing 24 KiB
header limit. Its primary assembly and aggregate bundle hashes must match the
native plan. Unknown fields, paths, commands, archive continuations and other
SDK versions fail admission. An expected manifest mismatch is a refusal;
there is no claim that outputs from different checkouts or platforms match.

The owner reserves a fresh typed publication namespace. Its Python helper may
delegate the marker only to its actual direct PowerShell parent. The controller
independently observes that parent's OS image and birth identity, checks the
marker and both directory identities, and verifies that output is empty before
authorizing the fixed publisher. The native owner then validates every output
against the frozen manifest. While the owner remains alive, the controller
independently reopens the full output tree, retains all file descriptors,
checks the receipt and records its binding before release and close.

The existing outer native fence remains 30 seconds; the compiler subprocess
has a 20-second limit. No sleep duration or output receipt extends that lease.
Library namespace receipts continue to report native publication as false.
Only the fixed native protocol records native production; its final result
additionally requires the full close handshake, exit and absence of owned
process members. Closing preserves the namespace. A trusted test fixture
disposes only its own identity-checked namespace after process cleanup.

Run native_publication_tests.py for generated contracts and
native_publication.py for the actual public publisher. The latter checks a
positive full manifest handoff, wrong code, wrong dotnet header pin, a private
continuation refusal, a wrong output manifest and consumed launch replay.
On a cold package cache, the fixture restores from the explicit public nuget.org\npackage source while retaining the repository audit settings and strict failures.\nOn Linux, a fixture-owned public SDK replica holds the selected muxer and SDK402\nwith private directory permissions; shared host permissions are unchanged. The\nreplica does not authenticate the complete dependency closure.\nCI requires both scripts on Windows and Linux without soft failures. No
original backups, credentials, private PKI, provider material or VPS access
are required.

Native image build/create composition, pre-receipt and controller-death
cleanup, compiler provenance, an operational lease and full-system recovery
remain separate open work. This evidence does not close Phase 7.


The separate existing runtime fixture samples PID 1 with a two-second startup
deadline. Only the secure initial sh process may transition to sleep; every
sample must already have the required UID/GID, zero capabilities, NNP and seccomp.
The final accepted process must still be sleep, with all previous mount, network
and scratch checks unchanged. Unknown names fail with a bounded public diagnostic.
This consumes time inside the existing image admission lease and never renews it.
A prior CI failure recorded a non-sleep name without preserving its actual value;
these transition tests do not prove the exact cause of that historical failure.

See [Native publication faults](NativePublicationFaults.md) for the separate
live-owner, observed compiler-child and pre-ACK receipt tests.

The separate [held continuation](NativePublicationContinuation.md) keeps the same
publication descriptors through native close and a bounded public image/readback
attempt. The original publication profile continues to release its descriptors.
