# Selected PostgreSQL pair byte capture

The original-service integration needs frozen application and signer dump bytes
from the already scoped [native input selection](RetainedNativeInputSelection.md).
`eng/pilot/historical/postgres_pair_capture.py` opens only those two references.
The audit archive, audit export, identity database and provider snapshot are not
opened. This fills the PostgreSQL input boundary for the complete recovery plan;
it does not perform that recovery or authorize a new one.

Run from the invoking operator's protected input directory. Supply the previously
reviewed selection report on stdin and its independently retained digest:

```powershell
python -B <repo>/eng/pilot/historical/postgres_pair_capture.py --expected-selection-sha256 <selection SHA-256>
```

There is no caller-controlled root, arbitrary file or extra-category CLI switch.
The owner supplies the working directory. Its path is not taken from metadata.
The adapter reuses the existing rooted held-descriptor, ordinary single-link file,
containment, bounded streaming digest and unchanged-at-read guards. It validates
the complete frozen three-reference selection before opening either dump, and
the PostgreSQL pair is limited to 64 MiB in total.

The shared metadata-only `retained_input_selection.decode_report` reconstructs
the exact existing report, including its false authority and original-use flags.
The audit-only adapter uses the same decoder and retains its original one-file
purpose. This refactoring does not add file access to the selector or broaden
the separate audit-only or Server two-input profiles.

The adapter returns both immutable byte strings only after both files match
their declared lengths and hashes. It returns no partial pair. Consumers must
use those captured bytes rather than reopen paths. Later caller-buffer or file
replacement does not change them. The data fields are omitted from repr and CLI
output; the CLI prints only the capture report. Actual hashes and operator output
remain private and must not be committed or uploaded in public CI.

`PGDMP` magic is an early sanity check. It does not validate native checksums,
`pg_restore` compatibility, database inventories or the safety of a restore.
The report keeps native restore/checksum, credentials, signatures, execution
authority, full recovery and Phase 7 completion false. A caller-created object
or a PASS report is not a resource or permission capability.

Portable synthetic tests cover the exact two-file open set with unrelated
artifacts absent, scope/path promotion refusal before any open, size bounds,
wrong external pins, corrupted second input, matching-hash invalid magic,
hardlinks, frozen caller buffers, file replacement and sanitized CLI refusal.
They prohibit process, socket and broad six-file verifier use during capture.
Existing selector and audit-only tests guard the shared decoder's unchanged
scope. No original dump, secret, private PKI or provider material is needed.

The invoking controller still needs the exact accepted code/input/build scope,
applicable existing data consent, one-use attempt and owned resource lifetime.
Current original-service/backend authentication, complete PostgreSQL/audit
comparison and the independent cleanup path must be verified before application
admission. New private PKI, identity/provider, privilege or token use requires its
own concrete executable plan and current permission. This adapter renews none
of the consumed one-shot grants. Independent custody, human/physical Agent and
full RPO/RTO remain separate open requirements; Phase 7 stays open.
