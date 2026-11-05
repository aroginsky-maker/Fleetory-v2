# Native revocation on already authenticated TLS connections

The [cold-restart case](NativeRevokedBoundary.md) is retained. The third actual
Server host now keeps its two original TLS connections open across the fixture
owner's durable revocation, proving request admission is checked again without
restarting the host or authenticating a replacement connection.

The same fresh URI leaves and owned network-none sandbox are used. Each gateway
has one TcpClient/SslStream, one verified native TLS1.2 handshake and exactly two
sequential GETs. First: registered Agent204 and registered Admin401 without a
bearer. The real readers/inventories must accept both credentials and the hosted
worker must export the OIDC denial before the native probe publishes readiness.

The controller then verifies the six-event/empty-queue state and independent
seven-key audit content. Only its existing fixture-owner connection revokes the
two known fingerprints at the same real database instant. Owner credentials and
mutation privileges are never given to Server. The original binding/registration
and `fixture-not-approval` references remain. No new key or issuer is created.

The second GET on each still-open TLS connection must return empty403. Both real
store preflights must now say Revoked, with three exact inventories and the same
runtime registration/revocation write refusals42501 as the cold case. Exact native
Kestrel connection IDs, endpoint pair, ordered GET paths and distinct echoed
correlations bind both requests to the same socket. There is no reconnect path.
The two gateways must have distinct connection IDs. A shared identity guard also
rejects replacement, empty and oversized native connection IDs.

Persistent HTTP has a separate bounded reader. The first validated zero-body
frame ends at its header delimiter, leaving the connection open. The second
requires exact empty framing and EOF; data between responses or after the final
frame cannot pass. A first `Connection: close` is refused. The existing shared
204/401/403/404 validator,1024-byte/two-second request bounds and original
one-request/EOF reader remain intact. Two valid response pairs and fourteen
unsafe pairs exercise the actual persistent reader; the identity guard has one
valid and three refusal controls.

Coordination uses only fixed, non-secret slots in a new private worker tmpfs
directory. The probe atomically publishes `admitted` after its first requests.
The controller atomically publishes `revoked` only after the owner transaction;
this signal cannot replace the real database/status checks. A detached native
process retains the existing18-second application deadline and five-second stop
deadline. Controller waits check a25-second deadline; each control Docker command
has a three-second bound, with the existing separate runtime identity checks.
Result/error/exit capture is bounded and checked for generated-secret canaries.
Seven fixed operations, two absent/two valid markers and twenty refusals are
checked portably without Docker; IDs, slots, exit status, UTF8, sizes and stderr
cannot select another command or silently satisfy success.

Live Admin refusal writes one `admin.certificate.revoked_denied` before OIDC,
correlation `native-live-revoked-admin`. The fourth host then starts a fresh process
and repeats the cold refusal, correlation `native-revoked-admin`. Finite audit
queries distinguish those two records by action and correlation. Final independent
readback requires eight immutable SQL events/nine immudb keys, all revision one
and all ten fields equal. Prior events and the original OIDC denial stay unchanged.
Exact-set scanning is bounded to ten keys, retaining one extra-key sentinel;
4096-byte packets are unchanged. All four host/worker stops, initial/final closed
listeners, health/public-route checks and owned cleanup remain mandatory.

This is synthetic live and cold revocation evidence. Original current PKI,
CRL/OCSP, custody/approval, physical Agent, positive Admin/OIDC/MFA/human admission,
TLS1.3, independent WORM, common original restore point, whole-VPS loss and full
RPO/RTO remain open. No original material, VPS/provider/share/root/token, issuer,
production token, enrollment, command or privileged HTTP mutation is used. No new
expenses are added. Phase7 remains open; PR#2 stays draft and unmerged.
