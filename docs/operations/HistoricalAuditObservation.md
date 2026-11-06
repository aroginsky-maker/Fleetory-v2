# Historical audit observation

Baseline §17 requires historical comparison scope to survive native recovery
observation. The explicit profile `historical-one-null-member-readonly.v1`
accepts the separate historical expectation producer's four known hashes with
exactly one preserved null context member. It cannot establish current writer
admission or authorize service startup.

`eng/pilot/historical_audit_observation.py` builds a separately tagged expectation
from a bounded, frozen, SHA-256-pinned historical producer response. It binds the
source response digest, snapshot digest, source nonce and ordered known-value
commitment to the existing point, nonce and measured producer fields. Its input
and native output comparison objects require exact fields, types and false
authority flags. Every receipt retains the historical profile and limitations.
The ordinary strict protocol rejects the complete historical envelope; removing
or relabelling scope is not an accepted conversion operation. These bindings
require a trusted owning controller; they do not authenticate source provenance
or protect against an actor inventing an entirely different input packet.

`ServerBackendProbe observation-history-read` validates that binding before
login. It shares the bounded reader with the strict observer: four known
revision-one events, four to sixteen current KV keys, five unfiltered native
transactions, history and resolved-entry witnesses, and stable before/after
points. The owner verifies both signed states using that instance's public pin
and supplies container/image/probe measurements. The pure policy performs no
file, process, socket, restore or host-start operation. Unknown keys and entry
kinds remain unreviewed. This is not an independent inclusion proof or complete
logical keyspace inventory.

Run the portable contracts on either OS:

```powershell
python -B tests/Fleetory.Tools.Tests/historical_audit_observation_tests.py
./tests/Fleetory.Tools.Tests/AuditObservationPolicy.Tests.ps1
```

Run the generated native lifecycle with a Linux Docker engine:

```powershell
./tests/Fleetory.Tools.Tests/NativeAuditHistory.Tests.ps1 -Profile historical-observation -Python python3
```

The generated fixture obtains expected values from a separate generated SQL-row
snapshot through the closed historical producer before reading immudb. It seeds
four sink events, including one literal null member, and a fifth sorted-set
transaction. It captures, verifies and restores the generated archive into a
fresh target, then checks source and target observations. Tests reject strict
mode projection, changed authority/commitment, wrong expected point/value,
wrong password, reader writes and cross-instance signing pins. Restart preserves
the observation and the source remains unchanged. Normal and injected-failure
cleanup verify removal of owned containers, image and payload.

The shared fixture uses generated credentials, TLS and signing keys, network
none, private tmpfs, read-only roots, fixed resource limits, capability drop and
output-canary checks. No original archive, private PKI, provider material or VPS
is used. Native setup and reader-write refusal probes are separate from the
read-only observation mode. CI runs the eighteen portable contracts on both OSes
and the generated native lifecycle on Linux.

This closes a generated protocol and lifecycle preparation step only. An
original observation still needs a concrete owned controller, input/code/public
trust pins, applicable data authority and a fresh one-use purpose record.
`writerAdmissionVerified`, `originalStrictExpectationsAccepted`,
`additionalStateReviewed`, `wholeKeyspaceVerified`, `executionAuthorized` and
`fullSystemRecoveryVerified` remain false. Phase 7 stays open and PR #2 stays
draft and unmerged.
