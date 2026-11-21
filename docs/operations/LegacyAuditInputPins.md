# Historical owner application input snapshots

The legacy PowerShell historical observation owner accepts only
`fleetory.historical-audit-restore-plan.v2`. V1 plans and missing, malformed or
stale `probeBundleSha256` fields are refused. The packet and historical
comparison profile remain unchanged; this revision adds no execution consent.

Before creating its public payload, it checks the plan's Git revision and a
versioned SHA-256 snapshot of tracked `eng`, `src` and tool-test files, plus these
eight active root inputs: `.config/dotnet-tools.json`, `.editorconfig`,
`Directory.Build.props`, `Directory.Packages.props`, `Directory.Solution.targets`,
`Fleetory.sln`, `NuGet.Config` and `global.json`. The actual `global.json` bytes
are measured even when CI has installed its untracked SDK overlay. A clean
working tree is not asserted. Paths, file counts, individual and total byte
sizes are bounded, links rejected and the revision rechecked after hashing.

After publishing, the owner checks the existing probe DLL pin and a second
versioned digest covering every published file and directory, including
dependency DLLs, dependency/runtime JSON and PDBs. Only ordinary DLL/JSON/PDB
files are admitted. Relative names are canonical, bounded and case-unique.
The three primary probe files must be files. Links, unexpected extensions and
missing required files fail closed. Before writing generated credential slots
or starting the native target server, the owner compares the container's exact
`/tool` entry set and every application file hash to that snapshot. Extra files,
missing files, changed entry types and altered contents are refused.

The portable generated fixture changes each root input and tracked source
group at an unchanged revision, changes revision with unchanged bytes, and
tests bundle dependencies, required files, links, unsafe names and container
substitutions. Both Windows and Linux CI require this fixture. The actual
generated native controller now uses ten distinct child nonces: one success,
two handled failure/cleanup cases and seven typed refusals, including wrong
revision and wrong bundle pin. The positive native case checks the files in
the real generated container. No original archives, credentials, PKI, VPS or
provider sessions are needed by these tests.

These are bounded application/build-input snapshots, not lifetime-held
execution continuity or software-origin authentication. They do not cover
untracked source additions, external MSBuild imports, restored package caches,
SDK/runtime installations, shared framework files, PowerShell/Python standard
libraries or native tool dependencies. Git, Docker, tar, sudo, find and sha256sum
remain trusted tool invocations; executable identity is not authenticated here.
Git revision and OCI digests alone do not prove accepted build provenance.
Per-file metadata checks do not create an atomic repository snapshot. The
owner's internally chosen payload/image namespaces are still separate from
the identity-held outer control namespace. Resource-intent admission, actual
ready/cleanup protocol integration and abrupt-owner-death backend cleanup remain
open before original dispatch. Full recovery and Phase 7 completion are not
claimed.
