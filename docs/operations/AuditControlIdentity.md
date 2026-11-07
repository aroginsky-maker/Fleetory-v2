# Held audit control identity

`eng/pilot/audit_control_identity.py` provides a consumed control namespace for a
future trusted supervisor. It holds the identity of the existing control root,
the exclusively created `audit-control-<nonce>` directory and its immutable
metadata files. This directory is separate from the native owner's public
payload. The existing owner still selects its payload namespace internally;
this component does not change that interface or create a payload for it.

The separately pinned `fleetory.audit-control-plan.v1` byte string contains a
canonical nonce, revision, native-plan/code/probe digests and Python/PowerShell
runtime digests. Its fixed purpose is
`historical-audit-control-identity.v1`. The decoder freezes the bytes and rejects
duplicate/extra fields, invalid types, nonfinite JSON, noncanonical identities,
wrong digests and input beyond 8 KiB before filesystem use. These are binding
metadata; matching hashes do not authenticate their origin or consent.

The caller supplies an existing, trusted, protected control root. On POSIX,
directory descriptors use `O_DIRECTORY`/`O_NOFOLLOW`; ownership and unsafe write
modes are checked. On Windows, ordinary ancestors and the final path are checked
before retaining a non-inheritable directory handle. Its volume serial and
128-bit file ID are compared with a newly opened current directory handle on
every operation. This follows the Windows
[file identity contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info).
The [directory-open flags and sharing rules](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
allow metadata identity checks without following a reparse leaf. Links, ancestor
replacement and directory substitution fail closed. This is a boundary inside
the trusted host account; it does not defend against an administrator controlling
that account or process memory. It does not validate Windows ACL custody for the
caller or replace a protected operator directory.

Exclusive `mkdir` consumes the nonce. An existing file, link, unmarked directory,
incomplete record or corrupt record is never adopted, repaired, reset or deleted.
`reservation.json` pins the frozen plan, native plan, code, probe and runtime
digests, and records the creator's own PID and creation time. Its checked,
single-link descriptor remains held. The record is fully written and flushed
before the claim returns. POSIX also flushes the containing directories.

One optional `binding.json` links a supplied child-PID/start-time/runtime-pin
**assertion** to that reservation. The attempt cannot be retried after validation
or write failure. It does not query a child process, measure its executable,
establish process ownership or authenticate runtime continuity. Both records use
exclusive creation and held, non-inheritable descriptors. Every check compares
directory identities, file identities, link counts, record size and frozen bytes;
POSIX additionally checks the private file mode. A lost response, partial write,
flush error or writer death leaves the nonce consumed. Handles close on normal
exit and failure, including release of the remaining handles after one close
operation raises; no namespace or record is removed by this API.

The returned report keeps `processIdentityAuthenticated`,
`runtimeContinuityVerified`, `launchAuthorized`, `backendNamespaceBound`,
`processSupervisionVerified`, `cleanupAuthorized`, `originalInputsRead`,
`originalPrivatePkiUsed`, `fullSystemRecoveryVerified` and `phase7Complete` false.
There is no launcher, Docker, SSH, source-file reader, issuer, token operation,
recursive cleanup API or operator-path CLI.

```powershell
python -B tests/Fleetory.Tools.Tests/audit_control_identity_tests.py
```

CI requires 32 generated filesystem contracts on Windows and Linux. They cover
an eight-thread one-winner race, replay and changed-plan reuse, preexisting and
corrupt namespaces, directory/record substitution or explicit Windows sharing
refusal, junctions/symlinks, hard links, inherited-handle mutation, allocation
failure cleanup, short/zero writes, flush failure and record corruption. Two
actual generated writer processes are forcibly killed after reservation and
after an unverified binding; durable records remain consumed. These are writer
death contracts, not a native service or backend process-death recovery proof.
No original files, private PKI, provider state or source VPS is involved.

The next integration must measure and pin a fixed launcher/runtime, authenticate
the actual child PID/start identity before releasing input, bind the native
owner's payload/resources to the held control identity and verify bounded
process supervision plus independent ownership-checked backend absence after
normal exit and forced death. Only then can the existing audit-only capture and
consumed purpose transaction be integrated with authenticated current gates and
original public checkpoint trust. Existing data consent persists; this metadata
component grants no new authority. Phase 7 remains open and PR #2 stays draft.
