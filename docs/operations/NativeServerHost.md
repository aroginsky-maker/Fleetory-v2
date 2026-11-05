# Generated native Server HTTP host lifecycle

`tests/Fleetory.Tools.Tests/NativeServerBackend.Tests.ps1` now follows the
[registered-worker stage](NativeOutboxWorker.md) with two actual
`FleetoryApplication` / `WebApplication` starts and stops. The production builder,
modules, Kestrel, File provider, database services, immudb sink, health checks and
hosted exporter are unchanged. These cases call the application's `StartAsync`
and `StopAsync`; they never start the worker manually or invoke its pump.

The existing ownership-checked PostgreSQL/immudb/worker sandbox has only loopback,
`network=none`, no published ports, non-root processes, read-only roots, bounded
resources and independent expiry/cleanup. All data, credentials and Agent/Admin
TLS roots/leaves are freshly generated. No original material or VPS is read.
Mandatory OIDC, gateway TLS and audit export remain enabled; no issuer or login
is activated by the probe.

## Startup and HTTP behavior

The real audit writer first commits `Fixture.Host.Read`. The fixture ages only
that new disposable queue entry by six minutes. It does not override the clock
or retry date. All three fixed listener ports must refuse TCP connections before
startup: public `19580`, Agent `19581` and Admin `19582`.

With queue UPDATE revoked, start the complete application. Require its
`ApplicationStarted` token, the real worker's active execution task and an
observed categorical worker PostgreSQL failure. The queue remains unclaimed.
Verify:

- `GET /health/live`: HTTP 200 and exactly `Healthy`.
- `GET /health/ready`: HTTP 200 and exactly `Degraded`, matching the actual
  registered backlog health result.
- Public-port GET to the fixed valid-GUID Admin role-version route and
  `/agent/identity`: HTTP 404 with empty bodies. Before these requests, the actual
  endpoint table must contain exactly one GET registration for each route, so a
  missing endpoint cannot satisfy this boundary test.
- All three configured ports accept loopback TCP connections.

The current default health HTTP mapping returns 200 for both `Healthy` and
`Degraded`. Status 200 alone therefore cannot establish healthy readiness.
Responses are read with a 64-byte bound; the fixed loopback client refuses
redirects. No privileged HTTP mutation or OIDC metadata/login request is made.

The [lab readiness reader](ReadinessResponse.md) now enforces the same exact
`200/Healthy` acceptance contract and explicitly refuses redirects. Its isolated
CLI regressions do not execute the existing token-backed lab.

After bounded stop and independent store readback, restore queue UPDATE and start
a new native application process. Its own hosted worker must automatically drain
the pending event. Liveness remains `Healthy`; readiness must now be exactly
`Healthy` over HTTP and through the real backlog check. The private-path and
listener checks repeat in this healthy host instance.

## Shutdown and independent readback

Every application stop has an independent five-second deadline. Require both
`ApplicationStopped` and a completed, non-faulted worker execution task; normal
cancellation is allowed. Each of the three ports must then produce native
`ConnectionRefused`. Other socket errors, timeouts and ambiguous closure fail.
Two distinct native process IDs bind the restart proof.

The healthy host also runs the [generated native client TLS matrix](NativeClientTls.md)
against both actual gateway listeners before stopping. Matching clients receive
the path-boundary404; missing/cross-root/wrong-purpose clients and incorrect
server trust/hostname must fail native authentication. This is scoped TLS
admission and does not establish identity or OIDC authorization.

Independent PostgreSQL counts and immudb exact-key/revision/content reads verify
that the first host retained the event and the second delivered it. All four
PostgreSQL events stay immutable. The direct-sink, prior pump, two worker and new
host event give five total immudb keys, each at revision one with all ten expected
fields. The final queue is empty. Existing generated-secret canaries, runtime
constraints and verified resource absence remain mandatory.

This verifies a generated Server host inside its local sandbox. It does not prove
external firewall/proxy routing, client identity authorization, OIDC/human login,
original credential/PKI admission, process-crash/multi-node recovery, a common
original capture point or whole-VPS loss. Physical Agent/current revocations,
independent WORM/key custody/approvals and full RPO/RTO remain open. Phase 7 is
incomplete and PR #2 remains draft and unmerged.
