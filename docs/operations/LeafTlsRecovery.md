# Leaf-only TLS recovery

Baseline section 17 separates retained database authentication from the TLS
materials needed by restored processes. The [LOGIN/SCRAM exercise](RuntimeLoginRecovery.md)
has passed on the retained application/signer pair. This step isolates a narrow
leaf-certificate proof from later real-service and issuer recovery.

```text
python -B tests/Fleetory.Tools.Tests/recovery_tls_tests.py
python -B tests/Fleetory.Tools.Tests/recovery_tls_tests.py --docker
```

The 14 portable tests enforce the closed file/name/root contract, reject scope
expansion, bad pins, duplicate roots, private material in public slots,
hardlinks, oversized files, existing/Git destinations and remote Docker
overrides. Windows and Linux run the portable tests; Linux CI also generates
disposable materials and runs the network-none TLS worker. Original keys,
provider credentials and real backup contents do not enter CI.

## Fixed scope

`eng/pilot/recovery_tls.py` accepts only seven triples: a public CA certificate,
public server certificate and private server leaf key. The role, expected SNI
and root class cannot be changed by an input plan:

| Role | Expected server name | Public root class |
| --- | --- | --- |
| PostgreSQL | postgres | infrastructure |
| OpenBao listener | openbao | infrastructure |
| immudb store | audit-store | infrastructure |
| Audit gateway | immudb | infrastructure |
| Agent gateway | localhost | agent |
| Admin gateway | localhost | admin |
| Command signer listener | command-signer | infrastructure |

The three distinct DER SHA-256 root pins are mandatory. Root CA private keys,
client keys, state-signing keys, passwords, provider tokens and seal shares are
outside this contract. `stage` is a library operation, not permission to use
original materials. Its caller must have specific authorization for the exact
21 source files. The CLI exposes only the fixed internal `/material` probe.

The stage operation opens bounded ordinary single-link files through the
existing descriptor/path checks. It checks each CA pin before that role's key,
refuses links/reparse points and existing destinations, and creates a new
private directory outside every Git checkout. POSIX directories/files use
0700/0600; Windows uses a protected owner/System/Administrators ACL. A refused
operation may leave partial protected staging, which the owning caller must
remove. Source files are read only and never rotated or overwritten.

## Worker and acceptance

The host helper refuses remote Docker overrides/contexts, requires the cached
digest-pinned Python image and a fresh random container name, then checks its
ownership and runtime settings before starting. The worker has network `none`,
no published ports, a read-only root, non-root UID/GID, all capabilities dropped,
no-new-privileges and fixed memory/CPU/PID limits. Its only binds are the minimal
staging and public tool directory, both read only. It creates no persistent
volume and starts no real application, database or issuer. Cleanup verifies
ownership and deletes only its own container; the caller deletes its staging.

All TLS traffic stays on loopback inside that worker. Seven successful
handshakes must validate chain, expected server name and TLS 1.2 or newer.
Seven wrong names and seven wrong CA roots must fail specifically with a
certificate-verification error; a connection failure is insufficient. Seven
mismatched certificate/key loads must fail. Reports contain public certificate
fingerprints and counts, without private-key bytes or unfiltered worker errors.

The generated-only local fixture passed seven TLS 1.3 handshakes and all 21
negative cases. CI runs this generated-only acceptance on Linux.

## Approved retained-material result on 3 November 2026

After the user explicitly approved the fixed 21-file/seven-leaf operation, the
reviewed tool at `2cabd97606ebeb1138054ac3a870c94bf5b042c0` also passed against
the seven existing local server leaf pairs. All three public root pins matched;
all seven chains/names validated in TLS 1.3, and all 21 wrong-name, wrong-CA and
mismatched-key cases were rejected. The operation took 3.156 seconds. Source
file metadata remained unchanged; the tool only read the sources. A separate
post-operation check confirmed no owned worker or temporary staging remained.
The sanitized proof, public fingerprints and plan binding are retained privately.

The one-time permission is consumed. No CA private keys, client keys, immudb
state-signing key, passwords, provider tokens or seal shares were read. No VPS,
application, database or issuer was started or changed. Source-root recovery and
production token issuance were not performed. Further original-key operations
require their own applicable explicit scope.

This verifies that the retained pairs were usable for the accepted loopback TLS
proof at that time. It does not establish current VPS equality, mTLS client
authorization, PostgreSQL protocol/TLS integration, service startup, CA custody,
revocation, post-restore human login, a common recovery point or full-system
RPO/RTO. The earlier database, identity and provider proofs retain their separate
limits. Phase 7 remains open.

## Original-material approval boundary

Before original leaf keys are read, the operator must retain a concrete plan
listing the 21 existing local files, three public pins, reviewed tool revision,
protected temporary location, maximum one-hour use, worker limits, acceptance
and cleanup. Obtain explicit approval for each applicable leaf-only use. Existing database
restore permission does not extend to original PKI. Do not use this step to
activate an issuer, repeat source-root recovery or issue production tokens.
