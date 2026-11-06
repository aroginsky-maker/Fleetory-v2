# Bounded native audit observation

Baseline §17 needs a native observation before an archived audit can be admitted
to a later recovery composition. A count of five transactions and four known
events does not establish the number of current keys or the content of the fifth
transaction. The generated history fixture's control key is not an assertion
about a retained archive.

`eng/ServerBackendProbe/AuditObservation.cs` reads the fixed TLS loopback origin
with a reader account. Its input supplies four known event IDs/value digests and
one expected five-transaction point. The observer makes no write request. It
checks the point before and after reading, enumerates current plain KV entries
with an empty prefix and limit 17, and refuses a result outside four to sixteen
keys. Each known event must have one revision, the expected value digest and
event ID, a single history entry, and a matching resolved transaction entry.
References, expiry and nonempty KV metadata are unsupported and refused.

The observer also reads transactions 1 through 5 **without an EntriesSpec
filter**. For every raw native entry it retains the type-prefix byte, key digest,
stored-value digest and length, and metadata digest. It bounds each transaction
to sixteen entries and the native key/value lengths to 4096 bytes/1 MiB. Raw
values and unknown key names are not included in the report. Empty values may
have the protobuf JSON default `vLen` omitted; the observer treats that omission
as zero. A native request or response failure is an operational failure, not a
successful data rejection.

The version-pinned protocol sources are immudb v1.11.2
[schema.proto](https://github.com/codenotary/immudb/blob/v1.11.2/pkg/api/schema/schema.proto),
[meta.go](https://github.com/codenotary/immudb/blob/v1.11.2/pkg/database/meta.go) and
[database.go](https://github.com/codenotary/immudb/blob/v1.11.2/pkg/database/database.go).
Plain KV keys and values have a zero-byte storage prefix. An ordinary KV scan
does not enumerate sorted-set, SQL or document keyspaces; the unfiltered native
transaction summaries retain these entry kinds without interpreting them.

`eng/pilot/audit_observation.py` freezes bounded input bytes and binds the report
to an externally pinned expectation, nonce, container/image/probe identities,
and known event metadata. It cross-checks scan/history/resolved/raw transaction
digests and returns a stable observation fingerprint. It does not authenticate
the producer measurement or verify signatures. The resource owner must measure
the probe and verify both signed states against that instance's own pin. The
decoder has no file, process, socket, restore or host-start API.

Additional state is always reported as unreviewed. Neither complete current KV
enumeration within this bound nor summaries of all native transactions prove a
complete logical SQL/sorted-set/document inventory, independent Merkle inclusion
proofs, original signing-key continuity, or permission to start a restored host.
The report keeps `wholeKeyspaceVerified`, `additionalStateReviewed`,
`startupAuthorized`, `executionAuthorized` and `fullSystemRecoveryVerified` false.

## Generated acceptance

Run the portable contracts and typed refusal policy on Windows and Linux:

```powershell
python -B tests/Fleetory.Tools.Tests/audit_observation_tests.py
./tests/Fleetory.Tools.Tests/AuditObservationPolicy.Tests.ps1
```

Run the native profile with a Linux Docker engine:

```powershell
./tests/Fleetory.Tools.Tests/NativeAuditHistory.Tests.ps1 -Profile observation -Python python3
```

The shared fixture builds and measures its probe before generating keys or
credentials. It uses disposable network-none stores, private tmpfs, read-only
roots, fixed resource limits, no added capabilities, no public ports or host
binds, and canary checks on process output. Generated setup and intentional
reader write-denial probes are separate modes from the read-only observer.

Two generated datasets each contain four revision-one sink events and five
transactions. One adds a sorted-set entry (four current KV keys), the other an
unknown KV entry (five current KV keys). Both keep the extra state unreviewed.
Native negatives cover an altered expected point, an identical-value event
rewrite and an over-bound current keyset. Wrong-password and reader-write
denials are checked separately; transport/configuration failures cannot satisfy
a typed data rejection. Both states use their own fresh signing pins, cross-pins
are refused, and a restart must preserve the observation fingerprint. Normal
and injected-failure cleanup verify deletion of owned containers and images.

This profile uses generated data, TLS and signing keys only. It does not read an
original archive, contact a VPS, reuse original PKI/provider material, start a
Fleetory application or issuer, issue production credentials, or complete Phase 7.
Retained input selection remains metadata-only until a separate bounded native
observation is actually performed within its applicable data authority.
