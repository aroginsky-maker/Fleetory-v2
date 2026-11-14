# Creation-only real-image recovery target

The [code-image preparation](RecoveryBuild.md) retains three rebuilt recovery
images and their offline archive. Baseline section 17 next needs a target
boundary that accepts these real images without loading service state or
starting applications. `eng/pilot/recovery_target.py` renders and validates that
creation-only Compose model. It never calls Docker.

Run from the protected operator directory using a separately retained image-set
manifest digest:

```text
python -B <repo>/eng/pilot/recovery_target.py --images recovery-target-images.json --expected-images-sha256 <retained-pin>
python -B <repo>/eng/pilot/recovery_target.py --images recovery-target-images.json --expected-images-sha256 <retained-pin> --validate < target-model.json
python -B tests/Fleetory.Tools.Tests/recovery_target_tests.py
```

The bounded manifest has exactly `schema: fleetory.recovery-target-images.v1`
and `images`, containing all eight role references. Five upstream references
are fixed to reviewed public digest pins. Server, signer and Keycloak use
distinct immutable local image IDs selected from protected accepted-build
evidence. A syntactically valid image ID alone is not approval: preserve the
independently retained manifest pin and review image ownership/build evidence.
Manifest reads reuse the regular-file, no-link, canonical/descriptor boundary;
there is no CLI root or destination override.

## Boundary

The model uses a fresh `fleetory-recovery-target-<32 lowercase hex>` namespace
and separate target ownership labels. It reuses the reviewed eight-role/three-
segment membership from [synthetic isolation](RecoveryIsolation.md), with
internal bridges, IPv4 gateway mode `isolated` and IPv6 disabled. It does not
reuse the live host-network edge, static addresses or source endpoints.

Every role has a fixed non-root UID, read-only root, dropped capabilities,
no-new-privileges, disabled healthchecks/restart, fixed memory/CPU/PID limits and
`pull_policy: never`. Model fields are closed: no host publications, binds,
volumes, configuration/secret/environment inputs, resolver overrides, build,
hooks, namespace delegation or entrypoint/command overrides. Image defaults
remain inherited for inspection; this model is not an approved startup profile.
The only reviewed writable declarations are empty tmpfs mounts. PostgreSQL's
image-declared `/var/lib/postgresql` volume is explicitly covered by a bounded
tmpfs to prevent an implicit anonymous persistent volume. Other roles have only
their bounded `/tmp`; required service-specific writable paths/configuration
are intentionally absent from this preparation.

The private operator workflow uses only `docker compose create --no-build
--pull never`, never `up`, `start`, `run` or `exec`. It disables default `.env`
loading, strips Compose overrides/profiles and explicitly selects the reviewed
local Docker endpoint. It checks image-declared volumes before creation.
Cleanup verifies exact project/session/role/name ownership and never-started
state before removing only its containers and networks. No global pruning or
image/archive deletion occurs.

## Verified result on 3 November 2026

All **eight real-image containers** were created and inspected on the local
Docker Engine 29.8.0. All had state `created`, zero restart counts and zero
start/finish timestamps. Container image IDs/references, inherited commands,
users, disabled healthchecks, read-only roots, capabilities, namespace modes,
resource limits, tmpfs declarations and configured memberships matched the
reviewed model. There were **three internal isolated networks**, **zero host
port publications**, **zero bind or persistent-volume mounts** and **zero named
or anonymous volumes**. All eight owned containers and three networks were
removed. Accepted images and their archive were preserved.

Seventeen synthetic regression tests pass on Windows and unprivileged Linux,
without skips. They reject image-set substitution, malformed/bounded inputs,
unsafe model fields, numeric/boolean substitutions, namespace/ownership changes,
unexpected image volumes, evidence of startup/restart and leaked privileges,
mounts or ports. Both existing CI jobs run this portable suite; they do not
receive the private accepted-image manifest. The 20 portable synthetic-network
tests also pass after parameterizing the shared network-label helper.

## Limits and next step

This verifies creation-time configuration, not real-service runtime readiness,
connectivity, packet isolation, database recovery or authentication. No service
process, issuer, data backup, real configuration, credential, PKI material or
source VPS operation was used. The earlier synthetic 28-allowed/28-denied proof
retains its separate scope; it is not a packet test of these stopped containers.

Next derive the exact configuration/credential/PKI recovery material matrix from
public code/templates and retained metadata, separating work already authorized
from new sensitive access needing concrete approval. Do not load new materials,
issue production tokens, start restored issuers or repeat OpenBao source-root
recovery under this creation-only scope. Runtime LOGIN/password recovery,
post-restore human login, provider/PKI/revocation/physical-Agent acceptance,
independent WORM/custody/approvals and full-system RPO/RTO remain open. Phase 7
and full-system recovery are not complete.
