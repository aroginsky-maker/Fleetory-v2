# Native public publication faults

The fixed publisher keeps its 30-second native fence, 20-second compiler limit,
36 selected input inventory and closed public-only protocol. The fault fixture
uses a disposable single-commit public copy with every tracked blob checked
against its Git tree. It does not open original backups, secrets or PKI and
does not access the VPS, a backend, an issuer or a production token.

Three faults are injected through trusted test adapters:

- Kill the live, OS-observed PowerShell owner after its namespace is independently
  bound but before publication authorization.
- After authorization, observe a live pinned dotnet process in the same owned
  Windows Job or Linux process group, retain its process handle or pidfd, and
  kill the live native owner. The normal controller fence must terminate all
  owned running members; the held child process object must independently show
  exit. No scalar child PID is signalled.
- Receive the real complete publication frame, independently validate all
  58 public files, then corrupt its bundle hash at the receiver boundary before
  controller ACK. The actual native sender did not produce the corrupt frame.
  Independent file binding may be recorded, but ACK, native acceptance and
  release must remain absent.

The read-only child observer enumerates only the owned Job's PIDs on Windows,
or filters the existing owner group/session on Linux before reading image
identity. It verifies the pinned dotnet image, membership and birth identity.
It reads no process command lines or environments and has no signal API.
A missing live compiler observation is a failed fixture, not successful fault
evidence. Startup failures, deadlines, wrong profiles, stale inventories,
unverified cleanup and boolean aliases also fail classification.

All three launches remain consumed. Failed namespaces and an unrelated public
sentinel remain present until process cleanup is verified and the trusted
fixture disposes its whole own copy. This is fixture disposal, not a production
cleanup grant. Unknown failed outcomes are retained for diagnosis.

Run publication_faults_tests.py for the generated classification contracts and
native_publication_faults.py for the three actual native faults. CI requires
both on Windows and Linux without soft failures. The positive publisher and
all older native gates remain required.

Native owner death while its controller remains alive does not verify
controller-death cleanup. It also does not authenticate the full compiler/SDK/
package closure, compose native publication with image build, grant an
operational lease, or prove full-system recovery. Phase 7 remains open.
