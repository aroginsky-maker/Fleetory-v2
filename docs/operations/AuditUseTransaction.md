# Pinned audit-use transaction

`eng/pilot/audit_use_admission.py` validates a bounded, externally pinned plan
and four frozen metadata records: native plan, audit-only selection, CI evidence
and local Sonar evidence. The nonce and revision must agree. The selected audit
archive must match the native plan's byte count and digest; application/signer
references are validated as metadata and are never opened by this component.

The CI record must contain all five successful jobs and all six exact-revision
checks, including the stable aggregate and official Sonar check. Cancelled,
skipped, neutral, stale, missing and duplicate records are refused. Official
overall/new coverage, native coverage and local coverage must reach 90%; both
official duplication values and the local duplication value must be zero.
Issue/hotspot counters, dependency omissions and secret findings must be zero.
Local analysis identity/revision and metrics are checked separately. Boolean
counters, nonfinite values and mixed native/CI/local pins are rejected.

These checks establish byte-pin and record-semantic agreement. They do **not**
authenticate the origin of JSON, a human approval, current online status or a
data-use permission. `gateOriginAuthenticated`, `existingDataConsentAuthenticated`
and `nativeLaunchAuthorized` remain false. A trusted outer caller must obtain
and authenticate the current records, hold the external trust anchors and check
the already granted data scope before supplying any original roots or bytes.
Self-presented successful records cannot become an independent approval.

`eng/pilot/audit_use_transaction.py` has a library API, with no root/path/process
CLI. Roots come from the trusted caller, not the supplied plan. It claims
`historical-audit-use-<nonce>.json` before an archive-open attempt. Windows uses
CREATE_NEW with no handle sharing and a checked final path. POSIX uses
O_EXCL/O_NOFOLLOW, mode 0600 and a held root descriptor. The checked ledger
descriptor is non-inheritable and stays open across capture and callback
dispatch. Claims and updates are flushed before the corresponding operation;
POSIX also flushes the directory after creation. Existing names are never
overwritten or removed, including after failure. Operator-directory protection
and Windows ACL custody remain responsibilities of the trusted caller.

```python
accepted = audit_use_admission.admit(plan_bytes, external_plan_pin, metadata)
with audit_use_transaction.transaction(trusted_operator_root, accepted) as use:
    frozen = use.capture(trusted_offline_root)
    # One optional slot for a trusted, separately supervised callback:
    opaque_result = use.dispatch(trusted_callback)
```

The existing audit-only adapter performs the single capture with actual-open
containment, ordinary/single-link checks, exact size/digest and header checks.
The capture attempt is consumed even if opening or validation fails. Subsequent
source changes do not affect the frozen bytes. The dispatch attempt is consumed
before the callback runs, so a missing response cannot authorize a retry. The
callback's bounded result is copied and hashed; its contents are not interpreted
as a verified native recovery receipt. Success ends in
`DISPATCH_RETURNED_UNVERIFIED`; failures keep `FAILED_CONSUMED`. No original data
or raw exception text is stored in the ledger. No automatic rollback/reset or
ledger deletion exists. Local rollback resistance and independent custody are
explicitly unverified; this is not an anti-rollback backup of the operator disk.

Twenty-one portable admission methods and twenty-four real-filesystem methods run
on both OSes. Tests cover an eight-thread one-winner race, claim-before-open and
attempt-before-callback order, replay, a new plan reusing a nonce, lost responses,
short/zero writes, flush failure, live ledger replacement, hardlinks, junctions,
immutable capture, private mode/exclusive sharing and non-inheritable handles.
All inputs are generated. The Windows read-only open API is retained alongside
the new exclusive-create API; existing file/capture/source tests guard it.

This closes admission and consumed transaction preparation only. It launches no
process, enforces no process deadline and does not verify callback cleanup or
native output. `processSupervisionVerified`, `ownerCleanupVerified`,
`nativeResultAuthenticated`, execution and full-recovery flags remain false.
Before any original dispatch, the outer controller still needs authenticated
live gate/code/runtime/public-trust checks, bounded process I/O, a known owned
namespace, owner-death supervision and ownership-checked recovery/absence
verification. The native-owner container lifetime alone does not prove this.
Existing audit-data consent persists; this API grants no new secret/PKI/provider
or issuer authority. Original native observation and Phase 7 remain open.
