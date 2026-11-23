# Code-only recovery image preparation

Baseline section 17 requires usable image inputs after losing the pilot host.
The [release continuity gate](ReleaseInputs.md) verifies retained code bytes;
this step prepares and verifies new local images without restored service data.

`eng/pilot/recovery_build.py` builds deterministic in-memory tar contexts for
Server, signer and optimized Keycloak. It reuses the bounded release reader's
same verified descriptor/packet rather than validating a pathname and reopening
it. The CLI only reports context sizes, SHA-256 digests and public base pins:

```text
python -B <repo>/eng/pilot/recovery_build.py --archive release-<revision>.tar.gz --expected-sha256 <retained-sha256>
python -B tests/Fleetory.Tools.Tests/recovery_build_tests.py
```

Invoke the first command from the protected operator directory. It has no
destination, root, recipe-path, Docker-host or build option, writes no files and
never calls Docker. Context bytes are available only to the separate reviewed
operator workflow. No host archive extraction occurs.

The four packaged recipes and the checkout's Keycloak recipe must match
reviewed SHA-256 pins after CRLF/LF normalization. Changing the archive pin does
not authorize a changed recipe, base, command or build context. Contexts contain
only the verified role's publish files and required recipes; no operator
directory, environment file, data backup, secret or PKI path is included. Tar
entries have deterministic ordering, zero timestamps/UID/GID, read-only file
modes and an executable signer entrypoint. Copied runtime bytes, including that
entrypoint, remain unchanged; recipe normalization does not silently rewrite it.

The metadata contract checks Linux/amd64 identities, exact base RootFS prefix,
additional build layers, non-root users, working directory, entrypoint/command,
the inherited environment plus only reviewed overrides, exposed-port metadata
and absence of image volumes. A Dockerfile that sets a new `ENTRYPOINT` clears
an inherited base `CMD`; Server/signer must not inherit the runtime base's shell
command. Port metadata is not a host port publication. Docker's optional Config
fields are read using safe map lookups, including absent `Cmd`.

## Verified local result on 2 November 2026

Both pinned upstream references were accessible in their registries. Raw
manifest SHA-256 values matched the pins, and Linux/amd64 cached base metadata
matched those references. This records availability at observation time, not a
future retention guarantee. No pull or other operation was performed on the VPS.

Three fresh images were built on the explicitly selected local `desktop-linux`
Docker endpoint/builder using code-only tar stdin, Linux/amd64, `--pull=false`,
no build cache for recipe commands and `--network none`. BuildKit can resolve
public pinned metadata; build commands have no network. No secrets, build args,
source binds or restored data were supplied. Keycloak ran `kc.sh build`, without
starting an issuer or connecting to a database. Build logs, context hashes,
image identities and selected metadata were retained privately.

Two never-started, network-none, read-only containers provided filesystem
readback of Server/signer. All **67 payload files** matched the retained release
by complete name set, size and SHA-256. These temporary containers had no mounts
and were removed after ownership checks. No application or issuer was started.

The three owned images were saved to a protected offline archive of
**372,420,096 bytes**. Only their exact UUID-owned tags were removed, then the
archive was loaded and all three exact image identities/ownership labels were
recovered. Archive SHA-256 remained unchanged across reload. Other project
images, cached bases and containers were preserved; no global prune occurred.
The three code images and their archive remain available for the next reviewed
target-topology check.

Sixteen synthetic tests pass on Windows and unprivileged Linux without skips,
including deterministic contexts, exact payload preservation, recipe pinning,
strict CLI/read-only output, inherited command behavior and unsafe image metadata.
The 20 release-input tests per OS also pass after the shared-reader refactor.
Both existing CI jobs run the new contract without receiving real release
archives or operator evidence.

## Remaining acceptance

The contexts are deterministic; whole image byte reproducibility is not claimed.
These are freshly rebuilt recovery images, not reproduction or authentication
of the three historical deployed image IDs. Release signatures, authenticated
DLL source provenance and independent custody remain unverified. The archive
reload used the same Docker daemon with shared cached layers; it is not an
empty-host or bare-metal recovery acceptance.

Next validate a real-image target Compose/runtime boundary without sensitive
material or service startup. Use the reviewed [isolated topology](RecoveryIsolation.md)
and fresh owned target-only paths, never live bind directories, host networking,
published ports or source endpoints. Loading actual configuration, secrets/PKI,
data or issuer state requires the separately scoped plan and applicable consent.
Database LOGIN credentials, human identity login, provider/PKI/revocation and
physical-Agent recovery, independent WORM/custody/approvals and full RPO/RTO
remain open. This step does not complete Phase 7 or full-system recovery.

The subsequent [creation-only target check](RecoveryTarget.md) verified eight
never-started containers and three owned internal isolated networks, including
the PostgreSQL image-volume override, and removed its resources without loading
service material. Runtime and recovery acceptance retain their separate scope.
