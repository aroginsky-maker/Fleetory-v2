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
CI requires both scripts on Windows and Linux without soft failures. No
original backups, credentials, private PKI, provider material or VPS access
are required.

Native image build/create composition, pre-receipt and controller-death
cleanup, compiler provenance, an operational lease and full-system recovery
remain separate open work. This evidence does not close Phase 7.
