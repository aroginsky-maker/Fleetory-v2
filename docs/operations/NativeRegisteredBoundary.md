# Native registered binding and mandatory OIDC boundary

The [unregistered credential stage](NativeRegistryBoundary.md) still proves its
original refusals and six-key audit state. A third actual Production host then
checks admission after synthetic durable binding/registration, without issuing
any token or starting an issuer.

Only the positively owned disposable PostgreSQL database is seeded. One fresh
device and matching Agent fingerprint/validity are inserted together with the
exact Admin fingerprint/subject registration, in one fixture-owner transaction.
Both Admin references are literally `fixture-not-approval`; they represent no
external approval or real person. The current freshly generated URI leaves are
reused. No original key or credential is loaded and no runtime grant is added.

Before requests, real runtime readers must return `Accepted` for both credentials.
Three parameterized inventories verify exact device/binding/registration content,
validity timestamps, absent revocation and expected audit counts. Two native
runtime INSERT attempts using `SELECT ... WHERE FALSE` must fail specifically
with PostgreSQL42501. Permission unexpectedly granted, another SQL error or a
failed preflight cannot satisfy the admission case.

The third host starts with an empty queue and Healthy readiness. Require:

- Actual Agent `GET /agent/identity`: empty204 from the registered Core endpoint.
- Actual Admin role-version GET without any bearer token: empty401 from mandatory
  OIDC after accepted certificate registration. It must create exactly one
  `admin.oidc.denied` event with expected subject/kind/correlation and null target.

Both use verified native TLS1.2 and exact endpoint/connection/GET-path correlation.
Fixed correlation headers must be echoed once. The registered worker must drain
the new denial automatically before stop. Independent readback requires six
immutable PostgreSQL events and seven immudb keys at revision one, with all ten
fields equal and prior six keys unchanged. The shared exact-set verifier is
bounded to ten entries for the later nine-key live/cold revocation stages. All three host lifecycles require
completed workers, bounded stop and initial/final native refusal on three ports.

The shared response reader treats204 separately: no Content-Length or
Transfer-Encoding and no body. Existing401/403/404 cases require one zero
Content-Length and no transfer encoding. The first header/body separator must be
the final four bytes; an appended CRLF-only body cannot satisfy an empty response.
Four valid forms and twelve unsafe forms exercise the actual reader, including
wrong statuses, body data, duplicate/framing/correlation headers, oversized input
and forbidden204 Content-Length. Native204/401 requests also use this same reader.
Two-second request and1024-byte response bounds remain unchanged.

The original safe404/no-SAN403/unregistered403 and ten TLS refusals remain intact.
Public-port private routes still return404 after fixture registration. The final
nested proof, resource/expiry/canary guards and verified owned cleanup remain
mandatory. No enrollment, command or privileged HTTP mutation is called.

This proves synthetic Agent binding admission and missing-token OIDC refusal,
not positive Admin/OIDC/MFA/human admission, real device enrollment, original PKI
or current revocation/custody, independent WORM/approvals, TLS1.3, external routing
or full-system RPO/RTO. Phase7 stays open; PR#2 remains draft and unmerged.

The subsequent [revocation stage](NativeRevokedBoundary.md) keeps this admission
evidence, revokes the same fresh credentials in the owned database, and starts a
fourth real host to verify403 before OIDC and automatic revocation-denial export.
The [live stage](NativeLiveRevocation.md) retains the third host's original
authenticated connections across the fixture-owner revocation and checks403
on their second requests before the cold restart.
