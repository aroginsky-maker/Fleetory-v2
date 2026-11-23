# Exact readiness response acceptance

The default ASP.NET health writer returns HTTP 200 for both `Healthy` and
`Degraded`. The [generated native HTTP host](NativeServerHost.md) independently
observed both responses. `eng/verify-security-lab.ps1` now requires HTTP 200 plus
the exact, case-sensitive text `Healthy` before reporting readiness. A degraded
response keeps polling rather than producing a false success marker.

The shared `eng/readiness-response.ps1` predicate accepts only integer/HTTP-status
200 and a decoded string of at most 64 characters equal to `Healthy`. It rejects
unknown types, byte arrays, JSON, whitespace/BOM/NUL variants, empty or oversized
bodies, other casing and every other status. This bounds recognized decoded
input; the existing `Invoke-WebRequest` receive buffering is unchanged. Requests
now explicitly disable redirects. The success message includes `200/Healthy`.

## Verification without the existing lab

Run `tests/Fleetory.Tools.Tests/ReadinessResponse.Tests.ps1` under PowerShell7.3+.
Three canonical cases and 25 refusals check the response contract. Six isolated
CLI cases execute copies of the actual entry point/helper under a fresh owned
fixture repository:

- Immediate healthy response succeeds after one poll.
- Degraded then healthy succeeds only after the second poll.
- Persistent degraded200, redirect302 and transport failure exhaust the existing
  30-poll budget without a success marker.
- An already-exited Server reports not-ready without an HTTP request.

The driver replaces path probes, process launch/stop, HTTP and sleeps with
asserting fixture functions. It requires the existing two-second request timeout,
zero redirects, exact copied paths/arguments, poll count, owned-process cleanup
and zero token/env file reads. Neither the real Server nor a network request is
started. The outer test does launch bounded child PowerShell drivers.

Linux runs six CLI cases in PowerShell7; Windows runs twelve, including the same
entry point/helper under Windows PowerShell5.1. Windows execution policy is set
only for those copied-fixture child processes; no machine policy is changed.
The temporary root is checked for containment/reparse points before removal.
Both CI jobs run these regression tests.

No existing security lab, OpenBao token, retained material, PKI, VPS or original
recovery operation is used by this test. This reader correction does not change
the application's health mapping or establish original-service admission,
OIDC/human login, a common restore point, independent WORM/custody/approvals,
physical Agent/current revocations or full RPO/RTO. Phase7 remains open and PR#2
remains draft and unmerged.
