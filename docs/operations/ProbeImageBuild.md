# Fixed public probe image build

This separate generated-image profile freezes the actual `ServerBackendProbe`
publication and the three-base recipe used by the legacy generated audit
fixture. It closes the publication/context/image receipt preparation step.
It does not integrate the native owner's actual build/create operations or
recover the deployed Fleetory Server release.

The existing historical probe-bundle descriptor is admitted by exact bytes and
SHA-256. Its ordinal entry list, ledger hash, file/byte counts, required files,
parent directories, allowed DLL/JSON/PDB extensions and case aliases are checked.
The profile allows at most 128 files, 256 total entries and 15 MiB of content.
All paths must fit the fixed USTAR context grammar. Unknown fields, hidden or
absolute paths, traversal, links, duplicate names and false origin claims are
refused.

The public publication root, nested directories and every file remain held.
The tree is checked before content opens. Each file uses a relative open anchored
to the held root descriptor and the existing single-link/ordinary-file checks;
a changed path cannot be followed into an unrelated file before hashing. File
identity, state and digest, root/directory identity and the exact path/kind set
are rechecked through context preparation, binding and reporting. A late extra
file invalidates the context and is preserved.

The deterministic context contains exactly `Dockerfile` plus the admitted
published files. It uses regular USTAR entries, mode 0644, UID/GID zero, mtime
zero and no extension headers. The full context is bounded to 16 MiB and pins
both its byte count and hash. The fixed Dockerfile uses the existing digest-pinned
immudb 1.11.2, immuadmin 1.11.2 and ASP.NET 10 images, exactly three COPY
instructions, controller/bundle labels and USER 3322:3322. There are no RUN,
ADD, arbitrary instruction, host-path, command or tag inputs.

A distinct intent/schema binds the held control's revision, source snapshot and
probe digest, the full bundle manifest hash, its ledger hash and counts, the
three selected base image IDs/layers/labels, definition hash and context hash.
It uses the existing consumed image-attempt/observation slots and original
60-second wall/monotonic publication bounds. A quiet untagged build receipt is
bound only to matching observed metadata: immutable ID, empty tags/digests,
exact labels, user, Linux/amd64, runtime-base layer prefix and three copy layers.
Expiry during publication never returns an accepted binding.

The original Python image, linked container and native metadata profiles retain
their exact types, recipes and schemas. They reject this new image type. The
library has no Docker, execution, backend cleanup or original-data CLI/API.

Portable negative contracts are mandatory on Windows and Linux. The separate
native Linux CI gate and local Windows Docker rehearsal perform the real public
publication without restore, check its source snapshot before/after publication,
build one untagged image and read back every published file through Docker cp
from a stopped network-none/read-only container. The container is never started.
A foreign controller receipt, replay and corrupt readback are refused. Tar
readback checks exact files, hashes, sizes, kinds and permissions without
extracting to the host. The fixture removes only its matching stopped container
and final image receipt ID, without force or parent pruning; selected metadata
for all three cached bases is preserved. Intermediate builder cache removal
and operational cleanup after owner death are not claimed.

Builds use the unchanged SDK pin in `eng/global.ci.json`. The local system has
10.0.401, so the operator prepared an isolated 10.0.402 SDK for this rehearsal:
the official archive SHA-512, safe ZIP paths, Microsoft executable signature and
reported version were checked against [Microsoft release metadata](https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json).
System SDK/CI configuration was not changed. Full unchanged local .NET tests
are not repeated; the required CI quality jobs still run their configured suites.

Publication hashes and byte counts are observed independently on each platform;
compiler output, paths and per-controller image/context IDs may differ. These
records are not an assertion of identical cross-platform binaries or authenticated
publisher/toolchain origin. Actual native build/create receipt handoff, the
separate service runtime profile, backend kill-after-create/restore cleanup,
accepted release provenance and original-data purpose/gate admission remain open.
No archive, PKI, provider, issuer or VPS input is used. Full-system recovery and
Phase 7 remain incomplete.
