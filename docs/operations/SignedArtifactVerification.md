# Signed artifact verification

Fleetory release artifacts are verified before installation or update. The verifier
runs outside the normal request path and accepts only the approved public verification key.

Create four release-side files:

- the artifact;
- a compact UTF-8 JSON manifest with artifactId, positive integer version,
  uppercase or lowercase sha256, and signingKeyId;
- a Base64 P-256 IEEE P1363 signature over the exact manifest bytes;
- the approved P-256 public key in PUBLIC KEY PEM format (SubjectPublicKeyInfo).

The manifest is one JSON object with exactly four case-sensitive members:
`artifactId`, `version`, `sha256` and `signingKeyId`. The identifiers and digest
must be JSON strings satisfying the identifier/hash checks; `version` must be a positive
JSON integer from 1 through 9223372036854775807. Numeric strings, decimal or
exponent spellings, nulls, arrays and objects cannot substitute for those types.

Missing, unknown or duplicate members, including duplicates hidden by JSON
escapes, are refused even when the manifest has a valid signature. A singleton
array cannot stand in for the object. Unique escaped names/values, property
ordering and whitespace remain supported; sign the exact bytes of that spelling.
The same record parser enforces the shared metadata rules in the anchor.

Release metadata is read through bounded file handles: the manifest is at most
**65536 bytes**, and the signature and public-key files are each at most
**4096 bytes**. These limits include any UTF-8 BOM and whitespace. Invalid UTF-8
fails closed. The signature authenticates the exact manifest bytes, including
any BOM or padding.

The key input accepts exactly one `PUBLIC KEY` PEM block containing a complete
P-256 SubjectPublicKeyInfo value, with optional surrounding whitespace. Private
PKCS#8/SEC1 keys, other algorithms/curves, multiple blocks, extra text and trailing
DER bytes are refused. Keep private signing keys in the separate release system.

Manifest and signature validation precede payload hashing. The artifact SHA-256
is computed from a file stream with bounded buffering; package size does not
require an equally sized managed byte array. No anchor lock or state update
occurs until all validation succeeds.

Use PowerShell 7, and keep `evidence-file-helpers.ps1` beside the verifier when
packaging the tool. Run it with absolute paths and a protected anchor directory:

    ./eng/verify-signed-artifact.ps1 -ArtifactPath C:\ProgramData\Fleetory\releases\Fleetory.Server.zip -ManifestPath C:\ProgramData\Fleetory\releases\Fleetory.Server.manifest.json -SignaturePath C:\ProgramData\Fleetory\releases\Fleetory.Server.manifest.sig -PublicKeyPath C:\ProgramData\Fleetory\trust\Fleetory.release.public.pem -AnchorPath C:\ProgramData\Fleetory\state\Fleetory.Server.anchor.json -ExpectedArtifactId fleetory.server

The verifier checks the signed manifest, P-256 public key, artifact hash and
symbolic-link/reparse-point safety. The anchor is written atomically after a valid
release. Repeating the same version and hash is idempotent; a lower version or a
same-version hash/key conflict fails closed. Keep the public key and anchor under
the deployment's protected ownership and retain approval and rollback records
outside the Fleetory host. Key rotation requires an approved new signingKeyId
and a release version above the current anchor.

The existing anchor is a UTF-8 JSON object of at most **4096 bytes**, containing
exactly these case-sensitive members:

- `artifactId`, `sha256` and `signingKeyId`: strings satisfying the manifest's
  identifier/hash rules;
- `version`: a positive JSON integer within signed 64-bit range; booleans,
  nulls, numeric strings and fractional numbers are rejected;
- `acceptedAt`: an ISO-8601 UTC string ending in `Z` or `+00:00`, with zero
  through seven fractional-second digits.

Missing, additional or duplicate fields (including escaped-name aliases), invalid
UTF-8 and unsupported roots such as `null` or `[]` fail closed. The shared
evidence reader enforces the byte cap while reading one open file handle.
An optional UTF-8 BOM and trailing whitespace are supported within that cap;
idempotent verification leaves the original bytes unchanged.

Only an absent anchor permits controlled first acceptance. An invalid existing
file is preserved and must be recovered from the independently retained approved
record through the deployment change process; do not delete it to bypass the
failure. Protect the anchor directory and serialize deployment writers per anchor.
The UTC field is structural metadata, not an authenticated approval or trusted
clock attestation.

## Concurrent verification

After artifact/signature validation, each verifier acquires an exclusive handle
on the adjacent `<AnchorPath>.lock` file before loading the current anchor.
The handle covers the read, version/hash/key comparison, optional atomic
replacement and result emission. A waiting process therefore checks the latest
anchor after acquisition. File-share contention is polled against a monotonic
five-second deadline; timeout refuses the update without changing anchor bytes.

The marker is a persistent regular file in the protected anchor directory.
The lease is the open OS handle using
[`FileShare.None`](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileshare),
rather than the marker's presence or contents. Process exit releases that handle;
a later verifier can reuse the marker without stale-PID cleanup. Preserve the
marker while any deployment process may be active: deleting it could create
separate lock identities. Directories and symbolic-link/reparse-point lock paths
are refused. Authorized deployment writers need access to this coordination file.

This coordinates cooperating verifiers using the same canonical anchor path on
a local filesystem. Installer orchestration must still serialize verification
and installation as one deployment operation; the CLI releases its handle when
verification ends. Distributed/network-filesystem coordination, protected
ownership and independently retained recovery records remain deployment controls.

The checked-in tests cover first acceptance, idempotence, forward versioning,
rollback, content tampering, unambiguous typed manifests, strict public-key import,
bounded metadata, streaming-hash allocation and actual-process anchor coordination.
These tests prove verifier behavior; production key custody, release approval and
installer integration remain
deployment controls.
