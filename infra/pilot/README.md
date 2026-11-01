# Fleetory single-node PILOT

This directory describes a restricted integration pilot, not production approval
or completion of the security Baseline / Phase 7. A single Ubuntu 24.04 VM hosts
all services; its administrator controls every container, volume and database.
Network separation and non-root processes do not provide independent custody
against that administrator. Local snapshots copied off-host are recovery copies,
not independent WORM retention.

Deployment coordinates and verification results reported by the deploying root
agent on 2026-11-01 (this documentation update made no remote requests):

- VM: `195.209.221.38`.
- App: `https://fleetory.195-209-221-38.sslip.io`.
- Authentication: `https://auth.fleetory.195-209-221-38.sslip.io`.
- The app currently exposes health/API endpoints; there is no interactive UI
  or Admin OIDC login/callback implementation.


Operator-only host/provisioning/verification tools live in `eng/pilot/`.
Runtime Compose, Dockerfiles and TLS proxy templates remain in `infra/pilot/`.
The existing quality policy still analyzes operator tools for issues and
duplication; its .NET coverage provider measures production assemblies and does
not instrument PowerShell/shell/Python operator execution. No production source,
Quality Gate or coverage threshold was excluded or relaxed for this layout.

`tests/Fleetory.Tools.Tests/PilotProvisioning.Tests.ps1` separately generates
disposable PKI, validates trust/key/purpose/permissions and rejection paths,
exports both actual EF contexts and provisions isolated PostgreSQL to verify
database ownership and runtime grants. It never uses this VM, operator material,
production credentials or OpenBao initialization.

## Historical pre-initialization snapshot — 2026-11-01

The following records the state observed before OpenBao initialization. It is
historical evidence only; it does not describe the current VM. Current live
state and approvals must be read from PR #2 and the deploying operator's
protected evidence. Never copy credentials, recovery material or root tokens
into this repository.

- Ubuntu was updated and rebooted; Docker `29.9.2`, Compose `5.6.1`. Public
  ingress is limited to TCP 22/80/443.
- Public HTTPS `/health/live` and `/health/ready` returned 200; public Admin
  routing returned 404. Auth OIDC discovery returned 200 with issuer
  `https://auth.fleetory.195-209-221-38.sslip.io/realms/fleetory`.
- Corrected idempotent SQL applied to the existing database without a reset:
  Platform has nine migrations and Core six. A backup taken beforehand is
  preserved privately. Missing raw-SQL terminators were fixed in the sources;
  new exports supersede the earlier scripts.
- Both audit TLS hops passed. The writer has permission `2` on `fleetoryaudit`;
  conditional write/readback returned revision `1`. Signed-state verification
  passed with the pinned P-256 public key and rejected a tampered hash. The
  gateway returned 404 for an administrative route. These results do not
  establish independent custody or successful export of every app audit event.
- Owner UUID `33e1e936-8ec6-4112-adc6-53689c26d3b3` exists with required actions
  `UPDATE_PASSWORD` and `webauthn-register`. Its Admin client certificate was
  issued; authorization bootstrap and certificate registration committed in one
  transaction, creating two actual audit events. Both were exported; the outbox is empty. The real user's password update and passkey enrollment remain
  outstanding. Client `fleetory-pilot` is disabled until a real callback exists.
- At the pre-initialization check, OpenBao returned 501 with
  `initialized=false`, `sealed=true`. This does not establish its current state.
  The signer was OFF at that snapshot; current signer state must be verified
  from operator evidence.
- Local working-tree validation passed: both real EF context scripts applied
  twice to fresh PostgreSQL, the full test suite passed `544/544`, and native
  coverage was `93.80%`. CI is pending; these are not metrics for a new remote
  HEAD or a successful remote CI run.

## Trust and access boundaries

Only SSH and the public HTTPS edge require public ingress: TCP 22, 80 and 443.
Caddy uses host networking and forwards public web/auth traffic to loopback
listeners. Do not proxy the Agent, Admin or signer management listeners through
the public edge. Their host publications must remain `127.0.0.1` and management
access must use the authorized SSH channel with hostname-validating TLS/mTLS.

| Network | Members | Purpose |
| --- | --- | --- |
| `app_net`, `172.30.77.0/24` | PostgreSQL, Keycloak, Server, audit gateway | Application and restricted audit REST |
| `signer_net`, `172.30.78.0/24` | PostgreSQL, OpenBao, signer | Separate signing trust domain |
| `audit_net`, `172.30.79.0/24` | Audit store, audit gateway | Direct immudb administration isolated from Server |

Server has one concrete address, `172.30.77.20`, for its Admin bind setting.
Signer has one network/address so its entrypoint can enforce a specific listener.
PostgreSQL intentionally spans application/signing networks; separate database
roles, verified TLS and explicit permissions remain necessary. Docker/root
administrators remain outside this boundary.

Server resolves `immudb` to the audit gateway. Gateway TLS presents that hostname;
the upstream connects to `audit-store` with SNI/hostname verification and the
approved infrastructure root. `audit-gateway.conf` permits only login, selection
of `fleetoryaudit`, set/get/state and a credential-free root probe; everything
else is denied. The dedicated writer must have access only to `fleetoryaudit`.
Backend administration uses host loopback `18091`; `18090` is the restricted
gateway. Never disable certificate validation to diagnose a failed connection.

## OpenBao custody and initialization procedure

OpenBao 2.7 requires the file audit device to be declared in its HCL
configuration. The generated configuration keeps `audit "file" "pilot-file"`
enabled at `/openbao/data/audit.log`, mode `0600`, with `log_raw = "false"`.
This is local audit output; it does not provide independent retention or WORM
custody. Verify that the audit file is writable by the OpenBao service identity
and that the protected data directory remains mode `0700` before startup.

Initialization, unseal, root-token recovery and Transit provisioning require an
explicitly approved custody plan. Capture pre-initialization status as a dated
historical record. After initialization, current OpenBao and signer status must
come from PR #2 and protected operator evidence; this README is not a live-state
authority.

Keep the initial root token in operator memory only while enabling the
Transit engine and creating the approved key, policy and restricted credential.
Use `auth/token/create-orphan` for the independent signer credential; the
`orphan` field on `auth/token/create` is ignored in OpenBao 2.7. Require only
the signer policy, no default policy, a nonrenewable TTL and explicit maximum of
24 hours. Independently check the issued scope and expiry, then revoke root
before consumer probes. Retain only the approved recovery material under its
separate custody procedure. A user-approved temporary 1/1 recovery quorum may support a
controlled setup but does not establish production custody. Do not claim
independent key custody, WORM retention or production readiness from that
temporary arrangement.

OpenBao 2.7 root-token generation through the CLI requires an authenticated
operator token. The normal TLS listener must keep legacy root-recovery access
disabled. If the documented recovery process requires a recovery-key quorum,
perform the one-off administration only on an explicitly approved isolated
loopback listener that is not published to host or container networks; remove
that listener and verify its absence before normal operation. Do not weaken the
normal listener or leave an unauthenticated recovery interface enabled.

Keep the signer disabled until Transit, its protected key and policy, and the
approved signer credential are verified. Then enable the approved profile only
for readiness/signing probes before admitting consumers.
Never create substitute signing keys, mock Transit, invent approval actors or
represent startup as production custody. Agent command execution and
high-risk/bulk signing remain disabled until their separate controls pass.


## Verified signer deployment checkpoint — 2026-11-01

The deployed application and signer binaries are from `e4833f2`. OpenBao 2.7.1
was initialized under the user's explicit temporary 1/1 custody approval; its
root credentials were revoked after setup and the isolated recovery listener
was removed. Transit key `fleetory-command` version 1 is P-256, nonexportable,
with plaintext backup disabled. The orphan signer token has only key-read and
sign permissions; management requests return 403.

Actual VPS checks over a strict mTLS SSH tunnel passed: readiness 204,
allowed synthetic Inventory.Refresh signing 200, wrong device 403, missing
client certificate rejected during TLS, and duplicate request 409 both before
and after a signer container restart. The returned P1363 signature was checked
independently using the real `SignedCommandEnvelope.GetSigningBytes()` contract;
changing its device invalidated the signature. No physical Agent command was
dispatched.

The verification caller grant expires at **2026-11-02 13:22:44 UTC**; the signer
token expires at **2026-11-02 15:28:27 UTC**. These are bounded pilot credentials,
with no automatic extension; the earlier caller expiry stops signing. Leaf
lifetime does not extend either deadline. Subsequent operators must verify live
state and use a reviewed renewal/custody process.

This checkpoint closes the pilot's real Transit/mTLS signing verification.
It does not close Phase 7's independent production custody, WORM retention,
human approval, real owner WebAuthn login, or physical Agent recovery controls.

## Native operator login

The reviewed native client in `eng/AdminLogin` supplies the bounded real-browser
Authorization Code + S256 PKCE callback for the pilot. It validates signed ID
and access tokens, fresh authentication, state/nonce, subject, audience,
client ID and provider-authenticated WebAuthn AMR before one audited read-only
Admin request over the registered mTLS leaf. Tokens stay in memory.

Follow [AdminOperatorLogin](../../docs/operations/AdminOperatorLogin.md) for the
protected profile, strict pinned SSH wrapper and exact loopback redirect. A
successful preflight or synthetic protocol fixture is not a real owner login.
The owner must complete genuine password/passkey actions and a fresh WebAuthn
authentication; do not mark that acceptance complete automatically. Client
activation must follow a green exact-head CI/Sonar and reviewed provider config.

## Verified real owner admission — 2026-11-01

At 17:04:28 UTC, the actual owner completed the password/passkey actions and the
live Admin API accepted the owner-bound OIDC/WebAuthn request over the registered
mTLS leaf. The expected absent-role sentinel read was authorized and audited.
The event's actor, target, correlation and timestamps matched PostgreSQL and
immudb revision 1; pinned signed state reached transaction 5 and outbox was empty.
This closes the pilot owner's real native-login checkpoint. Independent
production custody, approval separation, immutable retention and full-system
recovery controls remain open. Keep detailed evidence in protected operator
storage and PR #2; never copy credentials or tokens into this repository.

## Identity recovery acceptance

The identity provider has its own PostgreSQL database. After real passkey
registration, preserve that account/credential/configuration state with the
snapshot and isolated restore procedure in
[KeycloakRecovery](../../docs/operations/KeycloakRecovery.md). Capture and
inventory use one exported PostgreSQL snapshot; the verifier restores only in
an owned network-free scratch container and compares complete table data by
aggregate hash. It starts no copied issuer and resets no credentials.

Actual Keycloak dumps contain password hashes and signing private keys. Obtain
specific approval for their transfer/custody and keep them outside Git. A
passing data-preservation fixture does not establish independent production
custody, full-system recovery or a fresh post-restore passkey login.

## Safe preparation and startup order

1. Pin and review the deployed application revision and image digests. Copy the
   reviewed compose/config/build files into the deployment layout rooted at
   `/srv/fleetory`; relative mounts/build paths in `compose.yaml` are interpreted
   from that directory. Review the resolved compose configuration privately.
   Never paste resolved secret-bearing configuration or SQL into logs/chat.
2. Generate material locally using `eng/pilot/New-PilotMaterial.ps1` into a new protected
   directory outside **all Git checkouts**. Upload only the `upload/` subtree.
   Keep `offline/`, CA private keys, `credentials.json`, operator client keys and
   later recovery/root material on the protected operator side. Never mount CA
   private keys, signer credentials or Docker sockets in Server.
3. Provision private Linux ownership/modes for each mounted service directory
   and its files: PostgreSQL UID/GID `999:999`, Server/signer UID `1654`, OpenBao
   `100:1000`, immudb `3322:3322`, nginx `101:101`; verify the pinned images.
   Determine Keycloak's effective UID from its pinned image. Directories must be
   traversable only by their service/administrator; application secret files
   must have no group/other permission bits. Do not make everything world-readable
   to resolve a startup failure. Owner-readable `0400` files and `0500` secret
   directories are suitable after provisioning.
4. Export actual idempotent Platform and Core EF migration SQL offline. Generate
   fresh-cluster PostgreSQL initialization SQL with `eng/pilot/New-PilotDatabaseScript.ps1`,
   using absolute existing input paths and a new private output outside Git.
   This SQL contains passwords: retain it only in the protected initialization
   path. It creates databases outside transactions and fails on existing roles
   or databases; it is not a reset or upgrade tool. Never delete existing data
   directories to make initialization succeed.
5. Start named unaffected services only, from `/srv/fleetory`:

   ```sh
   docker compose up -d postgres
   docker compose up -d keycloak audit-store audit-gateway
   # Provision the dedicated immudb database and restricted writer privately.
   docker compose up -d server caddy
   ```

   Wait for each dependency to work before starting its consumer. `depends_on`
   alone does not establish readiness. Start `openbao` only after following its
   approved initialization and custody procedure. Signer is guarded by the
   `signer-approved` profile and must remain disabled until Transit, policy and
   readiness probes are complete; do not explicitly name/start signer as that
   can bypass the profile's default exclusion.
6. Verify both external HTTPS names, intended host ingress and loopback-only
   management publications. Verify PostgreSQL hostname/root validation from its
   actual clients and both audit TLS hops. `/health/live` is process liveness;
   PostgreSQL readiness uses `SELECT 1`, not schema/privilege validation. Check
   both migration histories and actual runtime operations separately. An empty
   audit queue does not prove successful delivery: retain evidence from an
   actual audit write, readback and signed-state verification.
7. Configure the `fleetory` Keycloak realm with required genuine WebAuthn
   registration/authentication, an authentication-derived AMR mapper and audience
   `fleetory-admin-api`. Do not copy lab password grants, virtual authenticators,
   lab browser redirects or hardcoded `amr=webauthn`. Provision only the actual
   intended authorization-code/PKCE client and redirect; Server expects
   `azp=fleetory-pilot`. Real user enrollment cannot be performed by manufacturing
   a test credential or marking a required action complete.
8. On a new deployment, for initial Admin access, create the actual Keycloak user and query its exact
   generated UUID. Issue an Admin client leaf with SAN
   `urn:fleetory:admin:<UUID>`. In a controlled operator transaction run
   `eng/bootstrap-first-admin.sql` and `eng/register-admin-certificate.sql` in
   bootstrap mode with that UUID, the exact uppercase DER SHA-256, actual
   deployment reference and operator identity. These initial scripts do not ask
   for a second approver; never invent one. Runtime has read-only access to the
   Admin certificate registry/denylist. An actual passkey login, matching bearer
   `sub` and registered mTLS leaf are still required for authenticated use.
   The historical snapshot records this bootstrap as committed. Verify current
   state from PR #2 and protected operator evidence before any further action;
   do not repeat or reset it based solely on this README.
9. Retain verification results and off-host recovery copies privately. Document
   remaining custody/approval/recovery gaps truthfully. Do not set Phase 7
   readiness controls or independent-WORM flags to true without actual evidence.

## Secret-provider recovery acceptance

OpenBao uses Integrated Storage (Raft). Its native encrypted snapshot and
original seal material have separate custody requirements. The isolated
synthetic recovery procedure is described in
[OpenBaoRecovery](../../docs/operations/OpenBaoRecovery.md). It does not establish
an actual pilot snapshot, independent custody or full-system recovery. New use
of the real recovery share, administrative recovery, snapshot transfer and
the provider restore target require a concrete approved operation.

## PostgreSQL permissions

`postgres` is the cluster administrator and is never an application login.
`fleetory_migrator` owns the Fleetory database; `fleetory_server` receives direct
runtime grants without membership/ownership/CREATE/TEMP. Keycloak owns its own
database. Signer tables are owned by NOLOGIN `fleetory_signer_owner` in a separate
database; `fleetory_signer` receives only schema USAGE, SELECT/INSERT on the three
journals and SELECT on certificate revocations. Revocation writer access is not
seeded by the generator.

Runtime receives SELECT only on both EF migration histories and the two Admin
certificate tables; SELECT/INSERT on audit events and authorization role/scope
version histories. Other application tables currently receive DML grants.
This is a pilot permission profile, not a claim of fully minimized per-column
access. Audit queue processing specifically requires UPDATE/DELETE. Future
schema changes need a fresh permission review; no default runtime grants exist.

## Enforced settings and remaining acceptance work

- Signer has the `signer-approved` profile guard and stays disabled until its
  Transit, policy and readiness acceptance steps are complete. The material
  generator now limits caller grants to 24 hours independently of client-leaf
  lifetime. Existing material must be reviewed for a current valid grant before
  any future approved activation; changing the generator does not renew it.
- The active HBA restricts each application database/login to its exact client address; all other TCP sources are rejected. Use the postgres Unix socket for reviewed operator/migration work.
- Both actual owner-bootstrap events left the outbox successfully. Retain their readback and signed-state evidence; the signing key stored on this VM is not independent WORM custody.
- Preserve the verified owner/native-login admission and provision future
  operators under their approved identity, certificate and actual passkey
  procedures. The checkpoint above does not authenticate independent approvers.
- Maintain the approved OpenBao recovery/root custody procedure; independently
  validate Transit and signer controls before enabling the signer profile.
- Complete pending CI for the intended revision before attributing the local
  test/coverage results to a remote commit.
- Rotate/reissue the bounded-life internal leaf certificates before expiry and
  test the documented restore/rotation procedures without deleting retained
  evidence. Offline roots are protected filesystem material, not an HSM.
- Further narrow the application's remaining DML rights by actual table/operation
  requirements.

The snapshot records the deploying agent's verified results and their limits.
Real owner WebAuthn admission is verified above. Full-system restore acceptance,
independent retention and production approval remain incomplete; this pilot
does not close the Baseline / Phase 7.
