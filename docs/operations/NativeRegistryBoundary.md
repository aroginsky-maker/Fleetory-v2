# Native refusal of unregistered identity certificates

The generated Server host fixture now follows [missing-SAN refusal](NativeIdentityBoundary.md)
with two client-auth leaves that have valid Fleetory URI identities. A valid SAN
and trusted mutual TLS must still fail without durable binding/registration.
Production gateway, identity parsers, stores, audit writer and worker are used.

The disposable TLS factory optionally accepts one exact `urn:fleetory:device:` or
`urn:fleetory:admin:` URI followed by a nonempty lowercase D-format GUID. It
creates a separate identity client leaf while the fresh CA handle remains in
memory. Default three-property and existing five-property results are unchanged;
the URI option adds only two identity leaf PEM fields. CA private keys are never
exported or persisted. Four new allowlisted identity leaf slots are sent over
stdin to owned0600 tmpfs files and covered by output canaries.

Before the HTTP requests, the actual SAN parsers must accept both leaves.
Registered runtime services must return `UnknownCertificate` for Agent binding
and `Unregistered` for Admin registry using the actual database principal.
Parameterized inventories independently require no matching Core binding, Admin
registration or Admin revocation row. A database failure cannot pass as a403.

Both actual private GET routes must then return empty403 over verified TLS1.2:
Agent `/agent/identity` and the existing fixed valid-GUID Admin role-version route.
Native connection ID, normalized endpoints, successful handshake, GET method and
exact path must match. A fixed per-route correlation header must be echoed once.
Existing safe404, no-SAN403 and ten native TLS refusals remain required, giving
six successful TLS/HTTP connections in total.

The Agent unknown-binding request leaves the audit count unchanged. The Admin
unregistered request must create exactly one
`admin.certificate.unregistered_denied` event with the expected actor kind,
subject, certificate fingerprint/target and fixed correlation. The actual
registered worker must drain its outbox entry before host shutdown; no manual
pump or worker start is used in this stage.

Independent SQL/immudb readback requires five immutable PostgreSQL events and six
audit keys at revision one, with all ten event fields equal. The prior five keys
remain unchanged. Exact-set scanning is bounded to seven entries, one above the
accepted six, so an extra entry cannot hide behind a six-entry scan limit.
Existing host/worker stop, closed listeners, health, runtime limits, complete
nested JSON and verified owned cleanup remain mandatory.

The portable generator test retains its five existing key-pair/chain checks and
six refusals, then checks two exact URI leaves, six extended key pairs/chains,
four purpose/root refusals and six invalid input refusals, without files or
network. Default contracts, key separation and exact single-URI DER are checked.

All data, credentials and PKI are fresh fixture material in the existing owned
loopback-only network-none sandbox. There is no original material/VPS access,
provider recovery, issuer service, token, login, enrollment or privileged HTTP
mutation. This proves refusal of unregistered identity-shaped credentials and
delivery of the Admin denial audit. Positive binding/registry/OIDC admission,
original revocation/custody, physical Agent, human login, independent WORM and
approvals, TLS1.3 and full-system RPO/RTO remain open. Phase7 is incomplete and
PR#2 remains draft and unmerged.

The subsequent [registered stage](NativeRegisteredBoundary.md) seeds only
synthetic fixture rows and adds a third host: Agent204, registered Admin401
without a token and one delivered OIDC-denial event. Its final state is six
PostgreSQL events/seven immudb keys; the six-key result above remains the
independent prerequisite snapshot.
