# Signed artifact verification

Fleetory release artifacts are verified before installation or update. The verifier
does not run in the normal request path and never receives a private signing key.

Create four release-side files:

- the artifact;
- a compact UTF-8 JSON manifest with artifactId, positive integer version,
  uppercase or lowercase sha256, and signingKeyId;
- a Base64 P-256 IEEE P1363 signature over the exact manifest bytes;
- the approved P-256 public key in PEM format.

Use PowerShell 7, and keep `evidence-file-helpers.ps1` beside the verifier when
packaging the tool. Run it with absolute paths and a protected anchor directory:

    ./eng/verify-signed-artifact.ps1 -ArtifactPath C:\ProgramData\Fleetory\releases\Fleetory.Server.zip -ManifestPath C:\ProgramData\Fleetory\releases\Fleetory.Server.manifest.json -SignaturePath C:\ProgramData\Fleetory\releases\Fleetory.Server.manifest.sig -PublicKeyPath C:\ProgramData\Fleetory\trust\Fleetory.release.public.pem -AnchorPath C:\ProgramData\Fleetory\state\Fleetory.Server.anchor.json -ExpectedArtifactId fleetory.server

The verifier checks the artifact hash, signature, P-256 key, manifest fields and
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

The checked-in test covers first acceptance, idempotence, forward versioning,
rollback, content tampering and invalid signatures. It proves verifier behavior;
production key custody, release approval and installer integration remain
deployment controls.
