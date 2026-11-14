# Generated native gateway client TLS

The [native HTTP host fixture](NativeServerHost.md) now completes actual mutual
TLS connections to both production Kestrel gateway listeners inside its owned
loopback-only, network-none sandbox. The healthy host runs this matrix before its
bounded stop; its PostgreSQL worker and audit readback remain required.

`New-PilotDisposableTlsMaterial -IncludeClient` issues a fresh P-256 client-auth
leaf while its fresh root handle is alive. Only the public root and server/client
leaf key pairs leave the factory; the CA private key is never exported or
persisted. Without that switch the original three-property result is preserved.
Agent and Admin roots are independent. Four additional allowlisted client slots
are written over stdin to the existing private worker tmpfs, checked as mode
0600, UID1654, one link, and included in output-canary guards.
An optional exact fixture identity URI adds a separate identity leaf pair and
four further slots across both gateways; the default contracts remain unchanged.
See [native registry refusal](NativeRegistryBoundary.md).

For each gateway (`19581` Agent, `19582` Admin), the native probe:

- Validates fixture chains and purposes against their exact public roots.
- Requires a matching client to complete mutual TLS and return HTTP404 with an
  empty body for `GET /fixture/client-tls`. This path stops at the existing
  gateway path boundary, before device/actor/registry/OIDC lookup.
- Requires the same trusted CN-only client, with no SAN identity, to receive
  exact empty-body403 from the actual registered Agent/Admin private GET path.
  See [native identity refusal](NativeIdentityBoundary.md).
- Requires native authentication refusal for no client, the other gateway's
  valid client, and a same-root server-auth-only leaf. Explicit local certificate
  selection exercises the supplied client in the latter two cases.
- Requires refusal with the wrong server root and with a hostname absent from
  the server SAN, retaining the matching client as the control.

The matrix has six real HTTP responses and ten native authentication refusals:
two safe-path404 controls, two no-SAN403 and two unregistered-identity403 responses;
six correlated server-side client refusals and four client-side server trust
refusals. It deliberately uses TLS1.2 and does not claim a TLS1.3 matrix.
`SslStream` performs server chain and hostname validation
using custom-root trust, server-auth purpose, no certificate downloads and no
accept-all callback. Revocation is not checked for these disposable roots.

Client-side authentication completion can precede the server's certificate
validation result. For each client refusal, a bounded read observes peer closure
or an authentication/I/O exception. That observation alone never passes: native
Kestrel `ConnectionStart` endpoints bind it to the exact connection ID, which must
then have `TlsHandshakeFailed`, an unsuccessful `TlsHandshakeStop` and no
`RequestStart`. Positive requests require the matching successful TLS1.2 stop and
HTTP GET request with its exact expected path. IPv4-mapped endpoints are
normalized; the private observer retains at most32 connection records and reads
only connection/GET-path metadata, ignoring configuration, headers and bodies.
Neither application options nor certificate-validation callbacks are replaced.
The event contract is defined by [Kestrel's EventSource](https://github.com/dotnet/aspnetcore/blob/v10.0.0/src/Servers/Kestrel/Core/src/Internal/Infrastructure/KestrelEventSource.cs).

Wrong server trust/hostname must produce client `AuthenticationException`.
TCP connection failures and timeouts cannot pass, nor can an arbitrary I/O failure
without the correlated native server failure. Any peer data in a client-refusal
case fails. Each connection has a two-second deadline inside the existing bounded
process. The positive HTTP response has a1024-byte limit and uses a raw fixed-path
request, with no redirects.

The portable in-memory generator test checks the unchanged default shape,
five leaf key pairs, five valid exact-root chains and six purpose/root refusals.
Its URI extension checks six further key pairs/chains, four chain refusals and
six invalid inputs, including preservation of the original result shapes.
The native matrix uses the actual production TLS validator and gateway builder.
It retains lifecycle, stopped worker, closed listeners, immutable events, six
revision-one audit keys and verified removal of all owned resources.
The subsequent [registered boundary](NativeRegisteredBoundary.md) adds a third
host with Agent204, registered Admin401 and a seventh revision-one audit key.
The [revocation boundary](NativeRevokedBoundary.md) adds a fourth host using the
same still-valid leaves after durable fixture revocation: both private GETs403,
exact Revoked store preflights and an eighth revision-one audit key before OIDC.

No original keys, existing lab tokens, VPS, provider recovery, issuer, login or
privileged request is used. Successful TLS plus a path-boundary404 proves neither
Agent identity nor administrator/OIDC/RBAC admission. Original PKI/revocations,
physical Agent, post-restore human login, independent custody/WORM/approvals,
external routing, common restore point and full-system RPO/RTO remain open.
Phase7 remains incomplete; PR#2 remains draft and unmerged.
