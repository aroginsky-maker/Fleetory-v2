# Retained service data capture

The original-service controller needs four already scoped data inputs: the
application and signer PostgreSQL pair, the native audit archive and the separate
PostgreSQL audit export used to obtain expected event values. The fixed-purpose
`eng/pilot/historical/retained_service_inputs.py` composes their existing readers.
It does not introduce a general recovery-file reader or use the broad six-file
verifier. Provider and identity artifacts remain unopened.

Every caller buffer and digest is frozen before parsing. The complete selection,
export metadata and all four artifact references are checked before the first
artifact is opened. The selection and export must name the same pinned manifest;
each selected PostgreSQL/audit reference must equal its manifest entry. A valid
selection digest cannot substitute another set of bytes under that manifest.
The existing path/ordinary-file/held-descriptor guards remain in effect. The
export's declared absolute path is compared within the owner root, never opened
as an independent path. The four inputs are bounded to 64 MiB in total.

The owner chooses the protected working directory. The CLI receives base64
selection/manifest/checkpoint metadata on stdin and externally retained pins via
`--selection-sha256`, `--manifest-sha256`, `--checkpoint-sha256`, plus a fresh
`--nonce`. No root, arbitrary artifact, provider or identity option exists. Only
a summary is emitted; paths and input values stay private. Real metadata,
artifact hashes and reports must stay outside Git and public CI.

`capture` returns one immutable bundle after all four reads succeed. It returns
no partial bundle on a late archive or export failure. Application, signer and
native audit packets contain the frozen original input bytes. The `audit-export`
packet contains the canonical event snapshot extracted by the existing export
reader, not the full raw export; its retained artifact pin still identifies the
full input export. Consumers must use these frozen packets and not reopen paths.

The snapshot supplies expected values independently of the target audit Get
results. It does not authenticate source independence or custody. Magic matching
and byte hashes do not prove `pg_restore` compatibility, native checksums,
inventories, signatures, current login, original PKI continuity or global atomicity.
The bundle and its summary grant no resource, restore, application or secret
authority. Publicly constructible objects cannot stand in for controller admission.

Portable generated tests cover exact four opens with excluded artifacts absent,
all metadata frozen before parsing, cross-manifest/reference substitution,
pre-open path and export refusals, the total bound, late partial-capture refusal,
immutable results after path replacement and sanitized CLI errors. They prohibit
process, socket and broad-verifier use inside capture. No original retained data,
secret, private PKI or provider material is needed for these tests.

The [PostgreSQL data-stage controller](RetainedPostgresDataStage.md) now consumes
the frozen packets in generated native tests, binds its own resource and compares
the two restored database inventories. The combined audit/Server controller still
needs the exact code, build/image and configuration scope, fresh attempt and
independent cleanup before payload release, with full PostgreSQL/audit readback
before Server admission and refusal/retry/shutdown checks through that same path.
Original service execution has not been performed by this reader. Existing
data permission is not expanded; consumed leaf/config/provider grants are not
renewed. New private PKI, identity/provider, privileged recovery or tokens require
their own concrete executable plan and current permission. Independent WORM and
actors, original service/PKI/identity, human/physical Agent and full RPO/RTO remain
open. Phase 7 remains incomplete and PR #2 stays draft/unmerged.
