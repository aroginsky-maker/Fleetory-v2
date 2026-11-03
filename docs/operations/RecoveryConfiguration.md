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
assemblies are mounted read-only. All synthetic secret files enter owned tmpfs
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

A minimal later preflight can use 13 existing local public/PKI/policy files,
including three server leaf private keys, while regenerating both target DB
connection strings and using disposable audit/Transit credential placeholders.
That requires a new specific original-material grant. It must not read source
passwords/tokens, CA/client/state-signing private keys or seal shares, renew
source grants, activate original issuers, repeat source-root recovery or contact
the VPS. Original policy/public-key loading alone does not prove caller validity,
Transit-key continuity, credential lease validity or backend access.

Full service startup, common recovery point, human login, physical Agent trust,
revocation, independent WORM/key custody/approvals and full RPO/RTO remain open.
Phase 7 is not complete and PR #2 remains draft.
