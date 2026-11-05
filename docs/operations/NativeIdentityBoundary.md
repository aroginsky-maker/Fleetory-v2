# Native identity refusal after mutual TLS

The generated [native gateway fixture](NativeClientTls.md) checks that a valid
TLS client certificate alone cannot act as a Fleetory device or administrator.
This uses the actual Production application, Kestrel listeners and gateway
middleware in the existing owned loopback-only, network-none sandbox.

Before any request, require both actual GET registrations to exist exactly once.
For each independent Agent/Admin root, the fresh client leaf must pass client-auth
chain validation and contain no SAN extension. It has only the disposable CN;
no device or actor URI identity is supplied.

After verified mutual TLS, request only:

- Agent `GET /agent/identity` on port19581.
- Admin `GET /admin/authorization/roles/00000000-0000-4000-8000-000000000001/versions`
  on port19582.

Both must return exactly HTTP403 with an empty body. Missing routes/HTTP404,
other statuses, peer closure, TLS refusal or an uncorrelated response fail this
case. The two existing safe-path HTTP404 controls and all ten TLS refusals remain
required. There are four successful native TLS/HTTP connections in total: two
safe404 responses and two identity403 responses.

The read-only Kestrel observer binds each result to the exact normalized server
and client endpoints, native connection ID, successful TLS1.2 handshake and one
GET request with the exact expected path. Duplicate requests, unexpected methods,
paths longer than180 characters or a mismatched path fail. It does not inspect
headers, request bodies or configuration and replaces no certificate validator,
identity parser, application middleware or service implementation.

Each connection retains its two-second deadline and1024-byte response bound.
Both host lifecycles, completed worker/stopped listeners, output canaries and
verified cleanup remain mandatory. Independent readback must still find the
same four immutable PostgreSQL events, empty outbox and five revision-one immudb
keys with all ten event fields unchanged. Thus an extra audit/outbox write by
these refusal requests cannot pass unnoticed.

The final bounded proof retains the nested identity result as a JSON object;
serialization truncation warnings fail the fixture instead of silently replacing
that result with a type name.

The production middleware rejects these leaves before binding/registry/OIDC
admission. Mandatory Production OIDC and the existing identity, registry and RBAC
guards remain configured. No token, issuer, enrollment, rotation, mutation,
command, original material or VPS is used. This proves refusal of absent SAN
identity after valid TLS; it does not prove positive identity/binding/registry or
OIDC admission, human login, malformed/duplicate SAN variants, TLS1.3, original
revocation/custody, physical Agent, independent WORM/approvals or full-system
RPO/RTO. Phase7 remains open; PR#2 remains draft and unmerged.
