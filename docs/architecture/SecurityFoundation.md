# Fleetory PHASE 7 Security Foundation

**Status:** IN PROGRESS — first Command Plane verification slice, 16 October 2026.

The Fleetory Development Baseline places Agent identity, mTLS, certificate lifecycle, RBAC enforcement, durable audit, secret abstraction, signed commands and replay protection in PHASE 7, before Agent Protocol v2 and the first Agent deployment. A compromised application server must not automatically gain authority to command the whole fleet.

## Implemented first slice

`Fleetory.Core.Contracts` owns `SignedCommandEnvelope` and the public verification-key, replay-store and local execution-policy interfaces. `Fleetory.Core` provides `SignedCommandVerifier`. The verifier accepts a command only after checking:

1. format, bounded identifiers, payload and signature size;
2. exact target device, issue/expiry times and a maximum five-minute lifetime;
3. a trusted target-specific P-256 public key and ECDSA/SHA-256 signature;
4. local command policy;
5. atomic consumption of both command ID and nonce by a durable replay store.

The signature input is a deterministic binary sequence: each variable field has a 32-bit big-endian byte length; numeric fields use big-endian integers. The field order is domain separator `Fleetory.Command.v1`, format version, target `DeviceId` as 32 lowercase hexadecimal UTF-8 characters, command ID in the same form, command type UTF-8, SHA-256 of exact payload bytes, issue and expiry UTC ticks, nonce UTF-8 and signing-key ID UTF-8. ECDSA signatures use the 64-byte IEEE P1363 `r || s` form. A signing key ID is included in the signed material to prevent key substitution. The incoming payload and signature are copied before storage. The verifier returns a separate payload copy for execution.

This is a security contract, **not** the PHASE 8 Agent wire protocol. Private signing keys and command signing are not implemented in Fleetory Server. The key provider must bind a trusted public key to the local target device and support revocation. The replay store must atomically reject reuse of either command ID or nonce for that device and persist across restarts; failure to read or write the store must prevent execution. The Agent-side policy must classify commands and deny unsupported or high-risk operations without the required approval. No permissive production implementations of these interfaces are registered.

The new Core security tests cover valid signatures, target mismatch, expiry/future/overlong windows, payload and nonce tampering, unknown and malformed keys, policy denial, repeated commands and nonce reuse, oversized/malformed envelopes, input-copy isolation and replay-store failure. Architecture tests keep the contracts in Core ownership.

## Remaining PHASE 7 work

- Per-device X.509 identity, mTLS transport, proof-of-possession enrollment, certificate rotation and revocation.
- A protected signing service and trust distribution, plus production durable Agent-side replay storage and policy enforcement.
- Human authentication with MFA/WebAuthn foundation, RBAC and scope enforcement.
- Durable local security audit with asynchronous export and explicit failure behavior.
- Secret Provider abstraction and production secret loading; no plaintext production secrets.
- Abuse, negative authorization, recovery and cross-platform security tests, then the full Sonar Quality Gate.

PHASE 7 remains open until these controls are integrated and independently verified. No Agent execution endpoint or privileged command route is exposed by this slice.
