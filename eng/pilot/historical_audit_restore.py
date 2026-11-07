"""Bounded native historical-controller input. This decoder grants no data authority."""
import re
import sys
import json

import historical_audit_observation as history
import fresh_server_pair as packet

SCHEMA = 'fleetory.historical-audit-restore-plan.v1'
PACKET = 'fleetory.historical-audit-restore-packet.v1'
PURPOSE = 'historical-known-events-sandbox-observation.v1'
MAX_ARCHIVE = 65536
MAX_BODY = 131072
FALSE_FLAGS = ('writerAdmissionVerified stateMutationAuthorized sourceOriginAuthenticated sourceIndependenceAuthenticated '
               'productionTokensIssued originalPrivatePkiUsed providerAdminSession executionAuthorized fullSystemRecoveryVerified phase7Complete').split()


def plan(data, pin):
    packet.require(type(data) in (bytes, bytearray) and 0 < len(data) <= 16384)
    frozen = bytes(data)
    packet.require(packet.digest(frozen) == packet.hex_value(pin))
    value = packet.strict_json(frozen, 16384)
    packet.keys(value, 'schema purpose nonce revision codeSha256 probeSha256 ciEvidenceSha256 localEvidenceSha256 inputs scope limits')
    packet.require(value['schema'] == SCHEMA and value['purpose'] == PURPOSE)
    packet.identity(value['nonce'])
    packet.require(type(value['revision']) is str and re.fullmatch('[a-f0-9]{40}', value['revision']) is not None)
    for name in ('codeSha256', 'probeSha256', 'ciEvidenceSha256', 'localEvidenceSha256'):
        packet.hex_value(value[name])
    inputs = value['inputs']
    packet.keys(inputs, 'archiveBytes archiveSha256 valuesSha256 stateSha256 publicKeySha256')
    history.core.integer(inputs['archiveBytes'], 64, MAX_ARCHIVE)
    for name in ('archiveSha256', 'valuesSha256', 'stateSha256', 'publicKeySha256'):
        packet.hex_value(inputs[name])
    packet.keys(value['scope'], 'historicalComparisonOnly ' + ' '.join(FALSE_FLAGS))
    packet.require(value['scope']['historicalComparisonOnly'] is True)
    packet.require(all(value['scope'][name] is False for name in FALSE_FLAGS))
    packet.keys(value['limits'], 'nativeSeconds containerSeconds maximumArchiveBytes maximumPacketBytes')
    for name, number in (('nativeSeconds', 600), ('containerSeconds', 660), ('maximumArchiveBytes', MAX_ARCHIVE), ('maximumPacketBytes', MAX_BODY)):
        history.core.integer(value['limits'][name], number, number)
    return value


def admit(data, pin):
    packet.require(type(data) in (bytes, bytearray) and 0 < len(data) <= MAX_BODY)
    frozen = bytes(data)
    body = packet.strict_json(frozen, MAX_BODY)
    packet.keys(body, 'schema planBase64 archiveBase64 valuesBase64 stateBase64 publicKeyBase64')
    packet.require(body['schema'] == PACKET)
    declared = plan(packet.decode(body['planBase64'], 16384), pin)
    archive = packet.decode(body['archiveBase64'], MAX_ARCHIVE)
    values = packet.decode(body['valuesBase64'], history.core.MAX_EXPECTED)
    state = packet.decode(body['stateBase64'], 4096)
    public = packet.decode(body['publicKeyBase64'], 1024)
    packet.require(len(archive) == declared['inputs']['archiveBytes'] and archive.startswith(b'IMMUBACKUP'))
    for name, value in (('archive', archive), ('values', values), ('state', state), ('publicKey', public)):
        packet.require(packet.digest(value) == declared['inputs'][name + 'Sha256'])
    packet.require(re.fullmatch(rb'-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----(?:\r?\n)?', public) is not None)
    source = packet.strict_json(state, 4096)
    point = dict(database='fleetoryaudit', tx=5, txHash=source['txHash'])
    history.core.state(source, point)
    packet.require(len(packet.decode(point['txHash'], 32)) == 32)
    # Validate known values through the historical builder, without reading an audit Get.
    history.build(values, declared['inputs']['valuesSha256'], declared['nonce'], point,
        dict(containerId='a' * 64, imageId='sha256:' + 'b' * 64, probeSha256=declared['probeSha256']))
    return dict(schema='fleetory.historical-audit-restore-admission.v1', nonce=declared['nonce'], point=point,
        knownEvents=4, nullContextMembers=1, archiveBytes=len(archive), frozenPacket=True, inputDigestsMatched=True,
        historicalComparisonOnly=True, signaturesVerified=False, externalGatesAuthenticated=False,
        sourceFileOpened=False, originalKeyContinuityVerified=False, executionAuthorized=False,
        fullSystemRecoveryVerified=False, phase7Complete=False)


if __name__ == '__main__':
    try:
        packet.require(len(sys.argv) == 2)
        result = admit(sys.stdin.buffer.read(MAX_BODY + 1), sys.argv[1])
    except Exception:
        print('Historical controller input refused; no paths, values or credentials logged.', file=sys.stderr)
        sys.exit(1)
    print(json.dumps(result, sort_keys=True))
