"""Generated native fixture writer; no original-file or provider/identity reader."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng' / 'pilot'))
from historical import retained_service_inputs as policy

packet, archive = policy.packet, policy.expectations.archive


def prepare(raw, root):
    body = packet.strict_json(raw, 24 * 1024 * 1024)
    packet.keys(body, 'fixture application signer audit snapshot')
    nonce = packet.identity(body['fixture'])
    blobs = {kind: packet.decode(body[name], 8 * 1024 * 1024) for kind, name in
             zip(policy.KINDS[:3], ('application', 'signer', 'audit'))}
    snapshot = archive.parse(packet.decode(body['snapshot'], 128 * 1024), 128 * 1024)
    packet.require(len(archive.event_map(snapshot)) == 4 and snapshot['pendingExportCount'] == 0)
    receipt = dict(schema='fleetory.audit-archive-receipt.v1', sequence=1,
        capturedAt='2026-01-01T00:00:00.000000Z', snapshotSha256=archive.digest(snapshot), previousReceiptSha256='0' * 64)
    blobs['audit-export'] = archive.canonical(dict(schema='fleetory.audit-archive-export.v1', receipts=[receipt], snapshot=snapshot))
    suffix = nonce.replace('-', '')
    relatives = dict(zip(policy.KINDS, ('coherent-postgres-' + suffix + '/fleetory.dump',
        'coherent-postgres-' + suffix + '/fleetory_signer.dump', 'immudb-restore-' + suffix + '/backup.bin',
        'audit-archive-20260101T000000Z-' + suffix + '/export.json')))
    entries = {kind: dict(path='not-created-' + kind + '/backup.bin', bytes=100, sha256=str(i + 1) * 64)
               for i, kind in enumerate(sorted(policy.files.KINDS))}
    for kind, data in blobs.items():
        path = root / relatives[kind]
        path.parent.mkdir(exist_ok=True)
        with path.open('xb') as stream:
            stream.write(data)
        entries[kind] = dict(path=relatives[kind], bytes=len(data), sha256=packet.digest(data))
    manifest = archive.canonical(dict(schema=policy.files.SCHEMA, artifacts=entries))
    export = blobs['audit-export']
    checkpoint = archive.canonical(dict(source='Generated native fixture only',
        artifactPath=str(root / relatives['audit-export']), exportSha256=packet.digest(export), bytes=len(export),
        snapshotCount=1, eventCount=4, lastReceiptSha256=archive.digest(receipt), portableVerification='PASS',
        isolatedFileRestore='PASS', checkpointVerified=True, tamperedRestoreRejected=True,
        independentCustodyVerified=False, administratorTamperProof=False, fullSystemRecoveryVerified=False,
        verifiedAtUtc='2026-01-01T00:00:01+00:00'))
    refs = tuple(policy.selection.ArtifactReference(kind=kind, **entries[kind]) for kind in policy.selection.NATIVE)
    selected = archive.canonical(policy.selection.Selection(refs, (('audit', 'a' * 64),
        ('database', 'b' * 64), ('manifest', packet.digest(manifest)))).report())
    from base64 import b64encode
    return dict(nonce=nonce, pins=dict(selection=packet.digest(selected), manifest=packet.digest(manifest),
        checkpoint=packet.digest(checkpoint)), generatedPaths=relatives, body={name: b64encode(data).decode('ascii') for name, data in
        (('selection', selected), ('manifest', manifest), ('checkpoint', checkpoint))}, generatedFixtureOnly=True)


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['sql']:
            print(archive.SQL)
        else:
            packet.require(sys.argv[1:] == ['prepare'])
            print(json.dumps(prepare(sys.stdin.buffer.read(24 * 1024 * 1024 + 1), Path.cwd()), sort_keys=True))
    except Exception:
        print('Generated retained fixture refused; no data logged.', file=sys.stderr)
        sys.exit(1)
