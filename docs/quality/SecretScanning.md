# Committed-history secret scan

Baseline section 20 requires secret scanning alongside SAST, dependency scanning
and authorization/command abuse tests. `eng/verify-secret-scan.ps1` adds a separate
Gitleaks gate to the Linux quality job. It does not substitute for SonarCloud,
NuGet audit, production credential custody or independent approvals.

Run from a complete normal Git checkout with PowerShell 7.2+ and Docker configured
for Linux containers:

```powershell
pwsh -File ./eng/verify-secret-scan.ps1
pwsh -File ./tests/Fleetory.Tools.Tests/SecretScan.Tests.ps1
```

The upstream MIT-licensed CLI is version 8.30.1, with its official GHCR image
fixed to the immutable manifest digest
`sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f`.
Docker downloads that image if missing; scanning itself has no network access.
This uses no licensed GitHub Action, additional hosted service or budget change.
Review upstream security updates before deliberately updating the version/digest.

The scanner receives only the read-only `.git` database and policy mounts, runs as UID/GID
65532 with all capabilities dropped, a read-only root filesystem, no privilege
escalation, 64-process/512-MiB limits and a 120-second scanner timeout. It receives
no host environment credentials or Docker socket. Existing lab containers and
their secret mounts are not involved.

The fixed policy extends the entire upstream default rule set, with no added
allowlist, baseline or disabled rule. An explicit flag ignores inline
`gitleaks:allow`; the working tree (including `.gitleaksignore` and
repository-supplied configuration) is not mounted. The policy is supplied
explicitly. The source is the exact committed HEAD captured at invocation and
all reachable ancestors, including credentials deleted from later revisions.
Separate merge-parent diffs include tokens introduced only by a merge resolution;
external diff/text-conversion helpers are disabled.
Shallow history, unborn HEAD, linked-worktree Git directories, alternate object
stores and grafts are refused. Replace objects are disabled. CI checkout already
uses `fetch-depth: 0`.

This scope excludes uncommitted/untracked files, other branches/tags not reachable
from HEAD, unreachable objects and external folders such as the local lab. Commit
changes before using the result as evidence for that revision. Gitleaks applies
its upstream rule/decoding behavior; no archive traversal is enabled. A zero result
means no rule matched the scanned content, not that all possible secrets are
absent. No credential-validity request is sent to GitHub or any provider.

Pass requires both scanner exit zero and a valid empty JSON findings array. A
finding (exit 2), engine/scanner failure, timeout or invalid report fails the gate.
Every invocation removes previous evidence from its output directory first.
`artifacts/secret-scan/summary.json` records image, policy SHA-256, HEAD, reachable
commit count and scope. `findings.json` and `scanner.log` use full secret redaction;
the wrapper prints neither matches nor commit messages. Reports are local ignored
artifacts, not automatically uploaded. Treat even redacted metadata as restricted
when investigating findings. A real exposed credential needs issuer-side rotation
and an incident review; deleting it in a later commit cannot clear this history
gate. Do not add a blanket ignore to obtain PASS.

The regression suite uses real disposable Git repositories and the actual pinned
scanner. It accepts clean history and rejects ten failure/bypass cases, including
a runtime-generated inactive token, inline and fingerprint/config suppressions,
a deleted historical token, a merge-only token, unavailable Docker and incomplete history. It checks
that the generated token appears in neither report nor log, and that failed scans
leave no stale success summary. Fixtures remain under ignored `artifacts/` and
are removed after verification.

Upstream references: [CLI and flags](https://github.com/gitleaks/gitleaks/tree/v8.30.1),
[release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1) and
[MIT license](https://github.com/gitleaks/gitleaks/blob/v8.30.1/LICENSE).
