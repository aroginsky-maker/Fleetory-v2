# Native durable credential revocation after restart

The [registered boundary](NativeRegisteredBoundary.md) first proves Agent204 and
registered Admin401 without a bearer. A fourth actual Production Server host
then proves that the same fresh, still-valid URI leaves are refused after a
durable fixture revocation. All earlier controls remain mandatory.

Only the owned disposable database is changed. One fixture-owner transaction
sets the matching Agent binding's `revoked_at` using real `clock_timestamp()`
and inserts the Admin fingerprint revocation using that same instant. The
original device, binding and Admin registration are retained. Both revocation
references are literally `fixture-not-approval`. No clock override, new key,
issuer, runtime grant, external approval or production decision is involved.

The finite credential-state selector distinguishes unregistered, registered,
live-revoked and cold-revoked. Real runtime store preflights must return `Revoked` for both leaves.
Three parameterized inventories check unchanged identities/validity/registration,
the exact shared revocation timestamp, fixture references, current leaf validity
and audit counts. The revocation instant must lie within both leaf validity
windows and not in the future. Two runtime registration INSERTs remain denied;
an Agent unrevocation UPDATE and Admin revocation INSERT must also fail with
exact PostgreSQL42501, even with `WHERE FALSE`. Other SQL errors cannot pass.

The fourth host starts with an empty outbox and Healthy readiness. Actual private
Agent and Admin GETs must both return empty403 after native verified TLS1.2.
Exact endpoint/connection/method/path and distinct echoed correlation headers
bind the outcomes to the intended requests. The Admin case must create exactly
one `admin.certificate.revoked_denied` event, with expected Person subject and
certificate target, before OIDC. The prior `admin.oidc.denied` record must remain
unchanged; another OIDC refusal cannot satisfy this case. The existing bounded
empty-response reader is reused, including its four valid/twelve unsafe forms.

The actual hosted worker must drain automatically. Independent PostgreSQL and
immudb readback now includes the preceding [live refusal](NativeLiveRevocation.md):
eight immutable SQL events and nine immudb keys, all revision one and all ten
fields equal. Prior values are preserved. Exact-set scanning permits at most ten entries, keeping
one extra-key sentinel above the final accepted set; packets remain bounded
to4096 bytes. No manual pump or worker start occurs in the host cases.

All four hosts must run in distinct native processes, complete their workers,
stop within five seconds, and show exact TCP ConnectionRefused on all three
listeners before and after each lifecycle (twelve initial/twelve final refusals).
Health, public-route404 controls, resource/expiry/canary guards, complete JSON
evidence and verified owned cleanup remain required.

This proves fresh synthetic durable revocation after restart. It does not prove
original current PKI/CRL/OCSP/custody, real revocation approval, physical Agent,
positive Admin/OIDC/MFA/human access, TLS1.3, independent WORM, original common
restore point, whole-VPS loss or full-system RPO/RTO. No original material,
VPS/provider/share/root/token, issuer, production token, enrollment, command or
privileged HTTP mutation is used. Phase7 remains open; PR#2 stays draft/unmerged.
