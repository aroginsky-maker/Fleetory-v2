# Synthetic recovery network rehearsal

Baseline section 17 needs a reviewed target boundary before loading recovered
service state. The live pilot profile uses host-network Caddy, loopback port
publications and live bind directories. Keep it separate from recovery testing.

`eng/pilot/recovery_isolation.py` renders a Compose JSON model containing only
eight pinned Python TCP probes. Their names describe the planned service roles;
they do not run Fleetory, PostgreSQL, Keycloak, OpenBao or immudb. The renderer
does not access Docker, operator files, backups, credentials or production endpoints.

```text
python -B eng/pilot/recovery_isolation.py | python -B eng/pilot/recovery_isolation.py --validate
python -B tests/Fleetory.Tools.Tests/recovery_isolation_tests.py --docker
```

The first command renders and validates bounded JSON without creating resources.
The second runs the owned local Docker rehearsal and removes its containers and
networks. It requires a reviewed local Linux Docker Engine 28 or newer, Compose
and the pinned Python image already cached. Unreviewed Compose environment overrides are removed and default .env loading is disabled. Remote Docker host/context overrides
are refused. No VPS operation or real recovery operation is performed.

## Target boundary

| Segment | Synthetic roles |
| --- | --- |
| `app_net` | Caddy, Server, Keycloak, PostgreSQL, audit gateway |
| `signer_net` | PostgreSQL, signer, OpenBao |
| `audit_net` | Audit gateway, audit store |

Caddy joins only the private application segment. Every segment is an internal
bridge with IPv6 disabled and IPv4 gateway mode `isolated`. Docker documents
that [internal networks](https://docs.docker.com/compose/how-tos/networking/#internal-networks)
have no default gateway; a node also attached to a non-internal network could
regain external connectivity. The contract therefore checks every membership.
The additional [isolated gateway mode](https://docs.docker.com/engine/network/port-publishing/#gateway-modes)
keeps an address off the host bridge. Docker/host administrators remain outside
this boundary.

There are no published ports, volumes, secret/config mounts, build contexts or
inherited entrypoints. Probes run as UID/GID 65534, with read-only roots,
capabilities dropped, no-new-privileges and fixed memory/CPU/PID limits. Their
only protocol sends the fixed synthetic role name; it performs no forwarding,
authentication or command execution.

The model has a unique `fleetory-recovery-proof-<32 lowercase hex>` namespace and
matching ownership labels. Only the exact reviewed service and network fields
are accepted. Host networking, even loopback publications, extra segments,
external/named networks, real images, source binds, credential/environment
injection, privilege additions, namespace overrides, hooks and unreviewed keys
fail validation before target creation. JSON input is bounded at 64 KiB and
duplicate fields/nonfinite numbers are refused. Validation always reports
`realRecoveryStarted=false`, `fullSystemRecoveryVerified=false` and
`phase7Complete=false`.

## Verified result on 2 November 2026

Twenty portable regression tests passed on Windows and unprivileged Linux;
94 unsafe model mutations were rejected. The real local Docker rehearsal used
eight probes on three internal isolated bridges. Inspection verified the
runtime image, role membership, users, read-only roots, dropped capabilities,
resource limits, no mounts and no port publications. Listener readiness was
checked before testing every directed role pair.

All **28 permitted connections** returned the expected role. All **28 forbidden
connections** were denied. All eight nodes had no default IPv4 route. The
rehearsal removed all eight owned containers and three owned networks, including
stopped containers; ownership/project/name checks guard cleanup. No real backup,
secret, PKI material, source VPS configuration or OpenBao recovery share entered
the rehearsal. Both existing CI jobs run the portable contract; Linux also runs
the actual Docker rehearsal.

## Remaining recovery work

The recorded source topology covers eight image identities. Three roles use
locally built aliases: Server, signer and Keycloak. Observed repository digests
and OCI labels alone do not verify registry availability, reproducible build
inputs, release provenance or application revision. Preserve and review accepted
release/image evidence separately before selecting real target images.

This closes the synthetic target-network preparation step. Loading the six
retained files, recovered runtime credentials, real service startup, issuer/RP
continuity and human login, configuration/PKI/revocation/physical-Agent recovery,
independent custody/approvals and full-system RPO/RTO require their own evidence
and appropriate scope. Real recovery materials are not authorized by this probe
profile. See [file preflight](RecoveryFiles.md), [application/signer recovery](ApplicationDatabaseRecovery.md)
and [pilot boundaries](../../infra/pilot/README.md).
