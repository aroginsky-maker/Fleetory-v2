# Native Admin operator login

The pilot operator client performs a real authorization-code flow with S256 PKCE
in the operator's browser. It is separate from the Admin API's authoritative
OIDC/mTLS admission and from a future general Admin web UI.

The client starts a one-time callback on **127.0.0.1:48329**, exact path
`/auth/callback`. The public OIDC client must register exactly
`http://127.0.0.1:48329/auth/callback`, require S256, and disable password,
implicit and service-account grants. There is no client secret. The fixed port
fails if occupied; it is not replaced with an arbitrary redirect.

## Protected profile and material

Use a new, protected directory outside Git. Only the current operator, local
SYSTEM and Administrators may access Windows files/directories. On Unix,
private files must have no group/other bits and parent directories must not be
group/other writable. Direct reparse points/symlinks are rejected. The existing
file provider bounds strict UTF-8 reads to 16 KiB; use lowercase filenames such
as `profile.json`, `admin-root.crt`, `admin-owner.crt` and `admin-owner.key`.

The example is a schema illustration, not a real identity or approval record:

```json
{
  "schema": "fleetory.admin-login.v1",
  "issuer": "https://auth.example.invalid/realms/fleetory",
  "clientId": "fleetory-pilot",
  "audience": "fleetory-admin-api",
  "personId": "11111111-1111-4111-8111-111111111111",
  "adminApiOrigin": "https://localhost:15444",
  "probeRoleId": "00000000-0000-0000-0000-000000000001",
  "adminServerRootPem": "C:\\ProgramData\\Fleetory\\operator\\admin-root.crt",
  "adminClientLeafPem": "C:\\ProgramData\\Fleetory\\operator\\admin-owner.crt",
  "adminClientKeyPem": "C:\\ProgramData\\Fleetory\\operator\\admin-owner.key"
}
```

Replace the example person with the provisioned provider subject, matching the
registered leaf's sole `urn:fleetory:admin:<UUID>` SAN. Configure a non-empty
sentinel role UUID verified absent in the target database. Do not create a role
or grant just to make a probe pass. The current pilot leaf is directly issued by
the approved Admin root; this profile does not provision client intermediate
chains. Server-supplied intermediates are included in custom-root TLS
validation, while hostname, validity and ServerAuth checks remain enforced.

The key/leaf pair must be current, non-CA, DigitalSignature and explicitly
ClientAuth. On Windows, Schannel uses a temporary current-user key container
without `PersistKeySet`; the PFX buffer is cleared and certificate disposal
releases its import. Tokens and authorization codes are never written to disk.
Do not run the tool under a different identity to bypass file protection.

## Run the reviewed client

Build the approved revision:

```powershell
dotnet build eng/AdminLogin/AdminLogin.csproj -c Release
dotnet eng/AdminLogin/bin/Release/net10.0/AdminLogin.dll C:\ProgramData\Fleetory\operator\profile.json --check-config
```

Preflight checks protected material, SAN identity and actual HTTPS discovery/
JWKS. It performs no human login and does not prove an authenticated Admin
request. It neither enrolls a passkey nor changes the provider.

With the pinned SSH identity and known-hosts file already provisioned, run:

```powershell
./eng/pilot/Start-AdminLogin.ps1 -ProfilePath C:\ProgramData\Fleetory\operator\profile.json -SshIdentityPath C:\operator\deploy_ed25519 -KnownHostsPath C:\operator\known_hosts -HostName 192.0.2.10
```

The example host/paths must be replaced with the authorized deployment. The
wrapper owns only its new loopback SSH forwarding process, requires strict
known-host validation and key-only batch authentication, then closes that
process when login exits. It does not publish the Admin listener.

Complete the real browser interaction. Initial password update/passkey
registration can be required; registration alone does not prove a completed
WebAuthn authentication. If registration finishes without signed WebAuthn AMR,
the attempt fails and a fresh run must perform actual passkey authentication.
The callback and token exchange expire after five minutes; Ctrl+C cancels them.
`--no-browser` on the executable displays the authorization URL for opening in
the operator's browser without launching one automatically.

## Accepted proof and limits

The client validates discovery endpoints under the exact HTTPS issuer,
duplicate-free bounded metadata/JWKS, RS256 key IDs/signatures, issuer,
audiences, expiry, fresh ID-token `auth_time`/`iat`, state, nonce, subject,
authorized party and provider-authenticated `amr=webauthn`. An optional ID-token
`at_hash` is verified. Mismatched, stale, unsigned, oversized or replayed
responses fail closed. Provider redirects and response bodies are not logged.

Only then does the tool send the access token over hostname-validated mTLS for
one audited `GET /admin/authorization/roles/{probeRoleId}/versions`. It displays
status only and discards the response body. An authorized manager receives
404 for an absent sentinel or 200 for an existing lineage; 401, 403 and redirects
fail. The Server still independently checks certificate registration/revocation,
OIDC identity, WebAuthn and RBAC; local client checks cannot grant access.

Synthetic signed JWTs and temporary TLS certificates in automated tests prove
protocol behavior. They do not establish the real owner's passkey enrollment,
independent approval identities or production custody. Complete an actual
operator run before claiming that deployment acceptance. The native client
does not provide a general Admin UI, long-lived sessions, token storage,
automatic refresh, certificate issuance, grant changes or approval workflows.

Protocol references: [OAuth native-app guidance](https://www.rfc-editor.org/rfc/rfc8252)
and [OIDC authorization-code validation](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth).
