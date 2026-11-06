# Retained native input selection

The previously pinned recovery-files manifest describes six artifacts. A new
application/signer/audit observation needs a narrower input set. Successful
historical six-file byte verification does not renew identity/provider permissions
or justify reading all six files again.

`eng/pilot/retained_input_selection.py` consumes three bounded, externally pinned
**metadata packets** over stdin: that manifest, the accepted application/signer
restore report and the accepted immudb restore report. All packets and their external pins are frozen
before parsing; a caller changing its pin dictionary during decoding cannot
change the pins reported for accepted metadata. No referenced path is opened, resolved, hashed or followed. The
CLI has no read, restore, root-directory, permission or execution switch.

The selector validates the retained v2 table profiles and historical partial
reports using existing validators. It binds the two database dump digests and
native audit backup digest/length to the manifest. It requires exactly the six
known manifest categories, rejects duplicate digests and case-folded path aliases,
and returns only these three immutable references:

| Category | Planning scope |
| --- | --- |
| Application PostgreSQL | Existing scoped data consent; current coherent pair |
| Signer PostgreSQL | Existing scoped data consent; same capture directory |
| Native immudb archive | Existing scoped audit-data consent |
| Audit JSON export | Excluded from this native-only purpose; existing data consent persists |
| Keycloak PostgreSQL | Excluded; no renewed identity/key/issuer permission |
| OpenBao Raft | Excluded; no renewed provider/share/root/token permission |

Lexical paths reuse the existing recovery path policy, including traversal,
Windows device-name and short-alias refusals. The retained profile additionally
requires the known coherent PostgreSQL and immudb directory/filename families;
application and signer dumps must belong to the same directory. Native labels
cannot be redirected to the Keycloak/provider paths even if a caller re-pins the
changed manifest. This is a planning constraint, not filesystem containment or
independent authentication of caller-supplied pins.

Output keeps `executionAuthorized=false`, `artifactBytesVerified=false` and
`filesystemContainmentVerified=false`. Historical use of locally saved signing
material does not grant reuse. No source password, private key, provider token or
original data body is returned. Selected relative paths and digests are private
operator output and must remain outside Git/public CI. A future byte reader must
bind this exact selection to its permitted purpose and recheck containment,
ordinary-file identity, size and digest at the actual open. It must preserve the
existing descriptor/link guards rather than invoke the broad six-file verifier.

The accepted metadata reports four known revision-one events and five native
transactions. It does not establish an exhaustive keyspace, each event's
transaction ID, the type/content of the additional transaction, or original
private-key recovery. It does not imply five current keys or authorize the
generated control record used in the rehearsal. Original-role supplemental state,
current backend authentication and coordinated recovery remain separate checks.

The local metadata-only application selects three references totaling **58,040
declared bytes** from the retained manifest. These are declared archive lengths,
not a new reading or byte verification of those archives. Three metadata inputs
and five byte/semantic mutations are checked with file/process/socket operations
disabled during selection; the metadata files remain unchanged. No original
restore, signature verification, source-VPS operation or sensitive input is repeated.
Portable generated contract tests run on Windows and Linux CI. Unchanged local
native/.NET suites and closed original recovery operations need not be rerun.

Next prepare the smallest bounded original native observation adapter and test it
on generated vectors. Record its specific missing-evidence purpose and audit the
existing data consent before opening original archives. New secret/PKI, source
VPS, issuer/service or privileged provider actions require their own concrete
plan and current specific permission. Source-root recovery remains excluded.
Independent custody/WORM/approvals, release authenticity, original services/PKI,
revocation/physical Agent/human identity and full RPO/RTO remain open. Phase 7 is
incomplete; PR #2 remains draft/unmerged. No costs, gates, exclusions, runners,
timeouts, Actions budget, repository visibility or TUX settings are changed.
