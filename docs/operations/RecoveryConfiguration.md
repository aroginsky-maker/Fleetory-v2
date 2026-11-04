# Recovery configuration and File-provider preflight

The recorded Server profile uses `FileSecretProvider`. The signer also reads a
file bundle; its Transit backend is a separate OpenBao dependency. Recovery
must not silently switch Server to OpenBao, combine providers or treat loading
a token string as backend authentication.

`eng/pilot/recovery_configuration.py` renders and validates a closed target
profile: two roles, 17 file slots, production environment, Agent/Admin gateways,
required OIDC and audit export, explicit target paths and test-only identity
origin/audience/client. Unknown keys, direct connection strings, provider
switches, different roots, disabled controls and endpoint changes are refused.
No secret values belong in the profile or command-line arguments.

```text
python -B tests/Fleetory.Tools.Tests/recovery_configuration_tests.py
dotnet publish eng/RecoveryConfiguration/RecoveryConfiguration.csproj -c Release -o artifacts/recovery-configuration
python -B tests/Fleetory.Tools.Tests/recovery_configuration_tests.py --native-publish artifacts/recovery-configuration
```

Eight portable contracts run on Windows and Linux. The native Linux fixture
uses the actual public `FleetoryApplication.Build` and
`SigningHostApplication.Build` methods, then disposes the unstarted applications.
It confirms production environment, an unstarted application lifetime, the
Server's actual File-provider registration and readable required files. The
recovery probe additionally requires exact database/username/CA-path bindings,
VerifyFull and no session options for both target connection strings.

The probe is in the solution so strict build, dependency audit and Sonar analyze
it. It adds no NuGet package. Production source and existing .NET tests are
unchanged. Like other engineering fixtures, `eng/**` remains outside production
coverage; this does not exclude static analysis or weaken any quality gate.

## Native acceptance

The generated-only local fixture accepted both native builders and all 17 file
slots. It rejected **25 cases**: each missing file (17), unknown provider,
OpenBao/File mixing, a direct connection string combined with File, disabled
required OIDC, open file permissions for each role and disabled verified
database TLS for each role. Rejections require exact known native categories
and exit codes; unexpected exceptions or process failures cannot pass.

The worker uses the existing digest-pinned ASP.NET 10 runtime, network none,
no published ports, UID/GID 1654, read-only root, dropped capabilities,
no-new-privileges and fixed memory/CPU/PID limits. Only public published probe
assemblies are mounted read-only. A separate owned tmpfs at
`/run/fleetory-recovery` holds the materials; its 0700 ownership and exact mount
options are checked independently from the runtime's `/tmp`. All synthetic secret files enter this tmpfs
via stdin and are checked for 0600/1654/single-link properties; directories are
0700. Native stdout/stderr are bounded and checked for password/token/private-key
canaries. The native program returns only categorical results. No TCP listeners
were observed after the checks. The owned worker and generated host materials
are removed; no persistent data volume is created.

The fixture generates fresh disposable PKI/passwords, a test-only Transit
credential placeholder and a P-256 public key. It does not load original files,
restore data, start hosted services, open a database, contact OpenBao, activate
an issuer or issue a production token. Successful Build/Dispose is configuration
acceptance, not readiness or secret-provider authentication.

## Original-material boundary

The previous one-time original leaf TLS grant is consumed. Before a native
preflight uses any original material, retain a concrete plan identifying exact
paths, public pins, target overrides, role/file mapping, source/tool revision,
privileges, maximum duration, refusal rules and cleanup. Obtain explicit consent
for that scope. DB-copy consent is not permission for private keys or provider
credentials, and a prepared plan is not a grant.

A separately approved one-time preflight at tool revision
`e59170732ad08c4366f9d683887274fd912e0ee1` accepted both native builders using
13 retained local public/PKI/policy files, including three server leaf private
keys. Both target DB connection strings and the audit/Transit credential
placeholders were regenerated: four slots, with no source passwords or tokens
read. All ten public files were validated before private-key reads; public CA
and leaf pins matched the retained metadata. The original files were unchanged.
The operation took **15.718 seconds**; no listeners were observed and the owned
worker/tmpfs were removed. An independent PID1 expiry with Docker AutoRemove
also bounded the worker to 3300 seconds. No original host disk copy was created.
The one-operation grant is consumed; this record is not permission to repeat it.

The operation did not start service hosts, open a database, contact a backend or
the VPS, read CA/client/state-signing private keys or seal shares, renew source
grants, activate an original issuer or repeat source-root recovery. Original
policy/public-key loading does not prove current caller admission, revocation,
Transit-key continuity, credential lease validity or backend authentication.
The original-material run used exactly two positive Build/Dispose probes; the
25 refusal cases remain generated-only checks and were not repeated on originals.

A separate [retained-provider target-credential recovery](OpenBaoRecovery.md#verified-actual-target-credential-recovery---4-november-2026-utc)
subsequently verified the historical Transit key, a fresh restricted target
lease across restart, a non-command signature, token revocation and target
cleanup. It used the provider CLI in one isolated target; neither native
service builder nor host authenticated to that backend. Its consumed one-shot
grant cannot be reused to start services or copy further PKI/credentials.

Full service startup, common recovery point, human login, physical Agent trust,
revocation, independent WORM/key custody/approvals and full RPO/RTO remain open.
Phase 7 is not complete and PR #2 remains draft.
