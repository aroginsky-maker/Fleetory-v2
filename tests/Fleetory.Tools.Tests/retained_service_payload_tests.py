"""Private transport carries frozen generated packets; the summary CLI does not."""
import base64
import dataclasses
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'eng' / 'pilot'))
from historical import retained_service_payload as policy
import retained_service_inputs_tests as fixture


class RetainedServicePayloadTests(unittest.TestCase):
    def setUp(self):
        self.source = fixture.RetainedServiceInputsTests('runTest')
        self.source.setUp()
        self.addCleanup(self.source.doCleanups)

    def test_frozen_four_packets_and_digests_without_io_or_process(self):
        captured = self.source.capture()
        with patch.object(policy.inputs.files, 'inspect_file', side_effect=AssertionError('Reopen')), \
             patch('subprocess.Popen', side_effect=AssertionError('Process')), \
             patch('socket.socket', side_effect=AssertionError('Socket')):
            result = policy.payload(captured)
        self.assertEqual(set(result['packets']), set(policy.inputs.KINDS))
        for kind in policy.inputs.KINDS:
            data = base64.b64decode(result['packets'][kind], validate=True)
            self.assertEqual(data, captured.packet(kind))
            self.assertEqual(result['packetSha256'][kind], policy.inputs.packet.digest(data))
        self.assertFalse(result['nativeRestorePerformed'])
        self.assertFalse(result['executionAuthorized'])

    def test_native_consumer_bound_is_checked_before_artifact_open(self):
        source = self.source
        first = source.record['selected'][0]
        first['bytes'] = policy.MAX_INPUT
        source.source.manifest['artifacts']['application-postgres']['bytes'] = first['bytes']
        source.source.pin()
        source.record['metadataPins']['manifest'] = source.source.pins['manifest']
        source.record['selectedBytes'] = sum(item['bytes'] for item in source.record['selected'])
        source.pin()
        with patch.object(policy.inputs.files, 'inspect_file', side_effect=AssertionError('No open')) as opened:
            with self.assertRaises(ValueError):
                policy.inputs.capture(source.root, source.raw, source.pin_value, source.source.metadata,
                    source.source.pins, fixture.source_tests.NONCE, maximum_input=policy.MAX_INPUT)
            self.assertEqual(opened.call_count, 0)

    def test_constructed_object_does_not_bypass_private_consumer_bound(self):
        captured = self.source.capture()
        with self.assertRaises(ValueError):
            policy.payload(dataclasses.replace(captured, input_bytes=policy.MAX_INPUT + 1))

    def test_private_cli_exact_packet_set_and_sanitized_argument_refusal(self):
        source = self.source
        body = dict(selection=base64.b64encode(source.raw).decode(), **{name: base64.b64encode(value).decode()
            for name, value in source.source.metadata.items()})
        command = [sys.executable, '-B', str(Path(policy.__file__)), '--selection-sha256', source.pin_value,
            '--manifest-sha256', source.source.pins['manifest'], '--checkpoint-sha256', source.source.pins['checkpoint'],
            '--nonce', fixture.source_tests.NONCE]
        raw = json.dumps(body).encode()
        result = subprocess.run(command, input=raw, cwd=source.root, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        decoded = json.loads(result.stdout)
        self.assertEqual(set(decoded['packets']), set(policy.inputs.KINDS))
        denied = subprocess.run(command + ['--root', 'PRIVATE_CANARY'], input=raw,
            cwd=source.root, capture_output=True, timeout=10)
        self.assertNotEqual(denied.returncode, 0)
        self.assertFalse(denied.stdout)
        self.assertNotIn(b'PRIVATE_CANARY', denied.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
