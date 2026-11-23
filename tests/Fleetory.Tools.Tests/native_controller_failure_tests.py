"""An invalid controller request must close its pipe and await the actual child."""
import io
import subprocess
import sys
import unittest
from unittest.mock import patch

import native_controller_loss as fixture


class ControllerFailureTests(unittest.TestCase):
    def test_invalid_request_waits_for_real_child_eof_cleanup_instead_of_killing_it(self):
        original = subprocess.Popen
        children = []

        def launch(*_args, **_kwargs):
            child = original([sys.executable, '-I', '-S', '-B', '-c',
                'import sys,time;sys.stdin.buffer.read();time.sleep(.1);print("OWN CLEANUP COMPLETED",flush=True)'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            children.append(child)
            return child

        incoming = io.TextIOWrapper(io.BytesIO(b'x'), encoding='ascii')
        try:
            with patch.object(fixture.subprocess, 'Popen', side_effect=launch), patch.object(fixture.sys, 'stdin', incoming):
                with self.assertRaisesRegex(ValueError, 'Unexpected fixed fault request'):
                    fixture.controller('unused-fixed-test-runtime')
            self.assertEqual(len(children), 1)
            child = children[0]
            self.assertEqual(child.poll(), 0)
            self.assertEqual(child.stdout.read().splitlines(), [b'OWN CLEANUP COMPLETED'])
            self.assertEqual(child.stderr.read(), b'')
        finally:
            incoming.close()
            for child in children:
                # Only the test's own actual non-Docker probe can be cancelled on failure.
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                if child.stdin is not None and not child.stdin.closed:
                    child.stdin.close()
                child.stdout.close()
                child.stderr.close()


if __name__ == '__main__':
    unittest.main()
