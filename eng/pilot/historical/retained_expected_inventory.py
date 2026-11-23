"""Original inventory metadata to the existing native target; no file or execution API."""
import re
import audit_archive as archive
import retained_input_selection as selection
import retained_pair_review as review

packet = selection.packet
SCHEMA = 'fleetory.retained-service-expected-inventories.v1'
MAX_METADATA = 65536
TARGET_POLICY_V1 = '662f7a2135b10287c4209050d9775022ad2fae4154b8d05511ce385a9e940381'
DATABASES = (('fleetory', 'application-postgres', review.APPLICATION_COUNTS),
             ('fleetory_signer', 'signer-postgres', review.SIGNER_COUNTS))


def _frozen(metadata, pins):
    packet.keys(metadata, 'selection capture database')
    packet.keys(pins, 'selection capture database')
    names = ('selection', 'capture', 'database')
    expected = {n:packet.hex_value(pins[n]) for n in names}
    values = {}
    for name in names:
        raw = metadata[name]
        packet.require(type(raw) in (bytes, bytearray) and 0 < len(raw) <= MAX_METADATA)
        values[name] = bytes(raw)
    for name in names:
        packet.require(packet.digest(values[name]) == expected[name])
    return values


def build(metadata, pins):
    """Trusted host supplies pinned metadata; PASS never grants original-use permission."""
    frozen = _frozen(metadata, pins)
    selected, _ = selection.decode_report(frozen['selection'], packet.digest(frozen['selection']))
    packet.require(dict(selected.metadata_pins)['database'] == packet.digest(frozen['database']))
    capture = packet.strict_json(frozen['capture'], MAX_METADATA)
    database = packet.strict_json(frozen['database'], MAX_METADATA)
    selection.composition.partial(database)
    declarations = {n: database[n] for n in ('sourceApplicationCommit', 'sourceConfigurationCommit')}
    packet.require(all(type(v) is str and re.fullmatch('[a-f0-9]{40}',v) for v in declarations.values()))
    selection.composition.database(database, declarations)
    review.composition.expect(capture, dict(schema='fleetory.coherent-database-capture.v1',
        observedStableCaptureWindow=True, sourceRolesPasswordsOrPoliciesModified=False,
        sourceRootRecoveryRepeated=False))
    review.composition.partial(capture)
    packet.keys(capture['databases'], 'fleetory fleetory_signer')
    packet.require(review.state_point(capture['immudbBefore']) == review.state_point(capture['immudbAfter']))
    references = {r.kind:r for r in selected.artifacts}
    expected = {}
    for name, kind, counts in DATABASES:
        entry = capture['databases'][name]
        inventory = database['databaseInventories'][name]
        review.inventory_profile(inventory, counts)
        review.same(entry['inventory'], inventory)
        review.composition.expect(entry, dict(singleMvccSnapshotForDumpAndInventory=True, dumpContainsOwnersAndAcls=True))
        packet.require(entry['dumpSha256'] == database['dumpSha256'][name] == references[kind].sha256)
        packet.require(type(entry['dumpBytes']) is int and entry['dumpBytes'] == references[kind].bytes)
        # Historical source did not measure this later digest. Never use a restored
        # target's observation to invent a missing source expectation.
        packet.require('additionalSecuritySha256' not in entry and 'additionalSecuritySha256' not in inventory)
        expected[name] = dict(inventory=inventory, additionalSecuritySha256=TARGET_POLICY_V1)
    snapshot = expected['fleetory']['inventory']['audit']
    packet.require(type(snapshot['events']) is int and snapshot['events'] == 4 and
                   type(snapshot['pendingExportCount']) is int and snapshot['pendingExportCount'] == 0)
    packet.hex_value(snapshot['snapshotSha256'])
    return archive.canonical(dict(schema=SCHEMA, expected=expected,
        metadataPins={n:packet.digest(v) for n,v in frozen.items()},
        additionalSecurityComparisonScope='fresh-target-role-policy-v1',
        originalAdditionalSecurityMeasurementAvailable=False,
        targetPolicyIsOriginalSourceMeasurement=False,
        referencedArtifactBytesOpened=False, originalRawInputsOpened=False,
        originalSourceImageAuthenticated=False, consentAuthenticated=False,
        executionAuthorized=False, fullSystemRecoveryVerified=False, phase7Complete=False))
