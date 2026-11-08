# Native public probe container creation

`audit_native_probe_create.py` introduces a separate fixed 46-file source profile.
The historical PowerShell owner starts under the existing PID/birth OS fence and
30-second protocol deadline. It creates one public sleep container from an image
already built, read back and bound by the trusted fixture. The old 45/40/34/32-file
profiles retain their own schemas and authority. This closes native container
creation only; native publication/build remain open.

The initial header pins the Docker executable and the exact frozen runtime intent.
Readiness must match that complete header before the parent offers creation. The
native delegate verifies the exact intent bytes, controller nonce, source code,
image and binding pins, runtime profile, name, labels and original 60-second image
admission expiry. No packet field selects a host path, command, endpoint, context,
mount, port, environment file or cleanup target. The Docker CLI uses only the fixed
local default Unix socket or Docker Desktop Linux named pipe; Linux engine 28+ is
required. Each CLI exchange has bounded pipes and an eight-second timeout. The
admission window is rechecked after the name lookup RPC, immediately before
dispatching create; an expired or clock-regressed window cannot start that RPC.

Creation uses the immutable image ID, `--pull=never`, UID/GID 3322, network none,
read-only root, two bounded noexec/nosuid/nodev tmpfs mounts, all capabilities
dropped, no-new-privileges, memory/CPU/PID limits, disabled core dumps and no ports
or host mounts. It runs only the fixed sleep command. No backend service starts.

The native reply carries its full create ID. The controller re-observes the live
owner identity and selected Docker fields, consumes the one-use runtime binding,
and persists a separate create receipt before the existing typed receipt ACK and
empty-metadata namespace removal. Duplicate, premature, foreign, malformed and
already-bound replies fail closed. A mutable label or partial ID never grants
adoption or cleanup authority.

Portable contract tests run on Windows and Linux. The actual Linux CI/local Docker
fixture starts with an unbound runtime and no pre-created sleep worker, checks the
native-created container, kernel restrictions, durable owner/create receipt and
replay refusal. Its surviving trusted parent removes only the full native create
receipt after matching name, labels and immutable image, then verifies absence
before admission expiry. The stopped public readback container and final image
retain their separate existing receipts; base images are preserved.

This parent cleanup does not prove native cleanup, death before the controller has
recorded the create receipt, controller/supervisor death or operational recovery.
The 660-second sleep is not an extended lease. Non-empty publication namespace,
full compiler/package input continuity, native image build, pre-receipt crash gap,
backend lifecycle, coordinated RPO/RTO and full Phase 7 recovery remain open.
Original data, credentials, private PKI, VPS, provider/root/issuer and production
tokens are unused. New sensitive scope still needs a concrete approved plan.
