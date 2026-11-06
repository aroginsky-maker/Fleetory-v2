"""Metadata-only selection of existing application/signer/audit native archives."""
from dataclasses import asdict, dataclass
import json
import re
import sys

import fresh_server_pair as packet
import recovery_composition as composition
from recovery_files import KINDS as FILE_KINDS, SCHEMA as FILES_SCHEMA, relative_parts
from retained_pair_review import APPLICATION_COUNTS, SIGNER_COUNTS, inventory_profile

SCHEMA = 'fleetory.retained-native-input-selection.v1'
KINDS = frozenset(FILE_KINDS)
NATIVE = ('application-postgres', 'signer-postgres', 'audit-immudb')
MAX_REPORT = 64 * 1024
MAX_BODY = 300 * 1024


@dataclass(frozen=True)
class ArtifactReference:
    kind: str
    path: str
    bytes: int
    sha256: str


@dataclass(frozen=True)
class Selection:
    artifacts: tuple
    metadata_pins: tuple

    def report(self):
        return dict(schema=SCHEMA, purpose='metadata-plan-for-original-native-observation',
            selected=[asdict(ref) for ref in self.artifacts], selectedBytes=sum(ref.bytes for ref in self.artifacts),
            metadataPins=dict(self.metadata_pins), excludedKinds=sorted(KINDS - set(NATIVE)),
            metadataOnly=True, metadataPinsMatched=True, artifactBytesVerified=False,
            filesystemContainmentVerified=False, executionAuthorized=False, existingConsentExpanded=False,
            sourceSigningMaterialReuseAuthorized=False, providerRootOrTokenUseAuthorized=False,
            identityIssuerStartAuthorized=False, originalRawInputsOpened=False,
            originalInventoryV2Recomputed=False, originalCompleteKeysetVerified=False,
            originalPerEventTransactionBindingsVerified=False, originalPrivateKeyRecoveryVerified=False,
            cryptographicVerificationRepeated=False, completedOriginalRestoresRepeated=False,
            releaseSourceRevisionAuthenticated=False, fullSystemRecoveryVerified=False, phase7Complete=False)


def manifest_entries(manifest):
    packet.keys(manifest, 'schema artifacts')
    packet.require(manifest['schema'] == FILES_SCHEMA)
    packet.require(type(manifest['artifacts']) is dict and set(manifest['artifacts']) == KINDS)
    paths, hashes = set(), set()
    for entry in manifest['artifacts'].values():
        packet.keys(entry, 'path bytes sha256')
        path = '/'.join(relative_parts(entry['path'])).casefold()
        digest = packet.hex_value(entry['sha256'])
        packet.require(type(entry['bytes']) is int and 0 < entry['bytes'] <= 64 * 1024 * 1024)
        packet.require(path not in paths and digest not in hashes)
        paths.add(path)
        hashes.add(digest)
    return manifest['artifacts']


def native_path_profile(entries):
    app = entries['application-postgres']['path']
    signer = entries['signer-postgres']['path']
    audit = entries['audit-immudb']['path']
    packet.require(re.fullmatch(r'coherent-postgres-[a-f0-9]{32}/fleetory\.dump', app) is not None)
    packet.require(signer == app.rpartition('/')[0] + '/fleetory_signer.dump')
    packet.require(re.fullmatch(r'immudb-restore-[a-f0-9]{32}/backup\.bin', audit) is not None)


def select(packets, pins):
    packet.keys(packets, 'manifest database audit')
    packet.keys(pins, 'manifest database audit')
    expected = {name: packet.hex_value(pins[name]) for name in ('manifest', 'database', 'audit')}
    # Freeze every supplied metadata buffer before validation. No referenced path is followed.
    frozen = {}
    for name, data in packets.items():
        packet.require(type(data) in (bytes, bytearray) and 0 < len(data) <= MAX_REPORT)
        frozen[name] = bytes(data)
    records = {}
    for name, data in frozen.items():
        packet.require(packet.digest(data) == expected[name])
        records[name] = packet.strict_json(data, MAX_REPORT)
    entries = manifest_entries(records['manifest'])
    native_path_profile(entries)
    database, audit = records['database'], records['audit']
    for record in (database, audit):
        composition.partial(record)
    declarations = {name: database[name] for name in ('sourceApplicationCommit', 'sourceConfigurationCommit')}
    packet.require(all(type(value) is str and re.fullmatch('[a-f0-9]{40}', value) for value in declarations.values()))
    composition.database(database, declarations)
    composition.audit(audit, database, declarations)
    for name, counts in (('fleetory', APPLICATION_COUNTS), ('fleetory_signer', SIGNER_COUNTS)):
        inventory_profile(database['databaseInventories'][name], counts)
    composition.expect(database, {'currentAuditEvents': 4, 'immudbCheckpointTransactions': 5})
    for kind, database_name in (('application-postgres', 'fleetory'), ('signer-postgres', 'fleetory_signer')):
        packet.require(entries[kind]['sha256'] == composition.digest(database['dumpSha256'][database_name]))
    packet.require(entries['audit-immudb']['sha256'] == composition.digest(audit['backupSha256']))
    packet.require(type(audit['backupBytes']) is int and entries['audit-immudb']['bytes'] == audit['backupBytes'])
    # Historical local signing-material use is a fact, not a reusable permission.
    return Selection(tuple(ArtifactReference(kind=kind, **entries[kind]) for kind in NATIVE),
                     tuple((name, expected[name]) for name in sorted(expected)))


def run():
    packet.require(len(sys.argv) == 1)
    body = packet.strict_json(sys.stdin.buffer.read(MAX_BODY + 1), MAX_BODY)
    packet.keys(body, 'packets pins')
    packet.keys(body['packets'], 'manifest database audit')
    return select({name: packet.decode(value, MAX_REPORT) for name, value in body['packets'].items()}, body['pins']).report()


if __name__ == '__main__':
    try:
        result = run()
    except Exception:
        print('Retained native input selection refused; no contents logged.', file=sys.stderr)
        sys.exit(1)
    # Selected references are private operator output, not an authorization token.
    print(json.dumps(result, sort_keys=True))
