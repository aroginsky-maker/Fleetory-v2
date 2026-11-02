# Recovery release input continuity

Baseline section 17 needs recoverable code as well as recoverable data. The
read-only `eng/pilot/release_inputs.py` inventories a retained pilot release
archive using a separately retained SHA-256 pin. Invoke it from the protected
operator directory; the CLI accepts a release basename, with no root override:

```text
python -B <repo>/eng/pilot/release_inputs.py --archive release-<revision>.tar.gz --expected-sha256 <retained-sha256>
python -B tests/Fleetory.Tools.Tests/release_inputs_tests.py
```

The archive name is limited to `release-<7..40 lowercase hex>[-verified].tar.gz`.
Opening reuses the [recovery file boundary](RecoveryFiles.md): protected ancestor
directories, regular single-link inputs, no reparse/link traversal, canonical
containment and descriptor checks. The same open descriptor is hashed, rewound,
decompressed and checked again for size/state changes. Compressed input is
limited to 16 MiB, expanded input to 32 MiB, individual files to 8 MiB and tar
entries to 128. Decompression reads bounded chunks into bounded memory.

The parser accepts ordinary file and directory tar records in the reviewed
Server/signer layout only. It rejects extension headers before interpreting
them, including PAX, GNU long names and sparse records. It checks tar checksums,
complete termination, duplicate/case-colliding names, required build/runtime
inputs and the filename allowlist. Links, devices, traversal, streams, unexpected
code/configuration files and private-key filenames are refused. It never
extracts files, restores archive permissions, writes files or executes a recipe.
Output contains only names, sizes, digests and explicit scope flags; failures
do not print input contents.

The library's `compare_runtime` requires exact complete per-role code inventories,
not just the main assembly. The caller must separately establish that the
observation came from the intended running image, with a read-only `/app`, no
mount overlay there or on an ancestor, and ordinary single-link files. Matching
payloads do not authenticate the caller or Docker administrator.

## Verified pilot result on 2 November 2026

The retained `e4833f2` package contains 70 regular files and four directories.
Its compressed size is **3,691,187 bytes**, with **10,806,138 file-content bytes**.
All **67 runtime payload files** matched the live pilot by name, size and SHA-256:
56 Server files, ten signer publish files and the signer entrypoint. Enumeration
had to match the expected complete set before hashing; image identity and mount
metadata were stable before and after observation. Only hashes and selected
Docker metadata were returned, without reading secret mounts, Env, logs or
service command lines. No VPS writes or restarts occurred.

The four packaged build inputs also match Git revision `e4833f2`, allowing only
CRLF/LF normalization: Server Dockerfile and signer Dockerfile, entrypoint and
dockerignore. Three retained older package candidates failed the current
payload comparison. The earlier staged upload directory is also stale and must
not silently substitute for this package. AdminLogin's separate `e761b61` build
record identifies the login client, not the deployed Server.

Twenty synthetic tests pass on Windows and unprivileged Linux, without skips.
They cover pin substitution, gzip corruption/expansion limits, tar integrity,
unsafe paths/types/extensions, hard links, file-state changes, missing/duplicate
inputs, complete runtime comparison and content-free read-only CLI behavior.
Both existing CI jobs run them.

## Image and configuration limits

The three custom image IDs (Server, signer and optimized Keycloak) have selected
RootFS metadata recorded privately. Their pinned base references were not
present in the source Docker cache, so base-prefix continuity was **unavailable**;
this is not evidence of a base mismatch. No image was pulled on the VPS.
Keycloak's reviewed Git recipe names its pinned upstream base and `kc.sh build`,
but this review does not authenticate execution of that recipe. Local aliases,
RepoDigests and labels do not establish availability after VPS loss.

The newly retained archive pin establishes continuity from this observation.
It is not a historical signed release, independent custody, proof that DLLs were
built from the named commit, an authenticated container configuration or a
reproducible build. The verifier reports these limits explicitly. Next, stage
reviewed code inputs and verify pinned bases/builds on the isolated local host,
without loading restored data or real configuration/secret/PKI material.

The protected real-service plan separates existing authorized data artifacts,
Git templates, target-only ephemeral database credentials and still-unapproved
secret/PKI transfer or issuer activation. Any target must use the reviewed
[isolated topology](RecoveryIsolation.md), fresh target-only paths, no live
binds, no host-network edge, no published ports and no source endpoints. Actual
configuration reconciliation, credential/PKI/revocation recovery, identity
login, physical-Agent acceptance, independent WORM/custody/approvals and full
RPO/RTO remain open. No full-system restore or Phase 7 completion is claimed.
