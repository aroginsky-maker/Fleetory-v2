"""Fixed metadata-only source-pinned launch and held payload binding; no backend launcher."""
import threading

import audit_launch_bundle as bundle
import audit_payload_binding as binding
import audit_process_fence as process
import fresh_server_pair as packet


class _ReservationPumps(process._Pumps):
    def __init__(self, child, data, command, session, fence, start, seconds):
        super().__init__(child, data)
        self.command, self.session, self.fence = command, session, fence
        self.start_time, self.seconds = start, seconds
        self.value = binding.header(data[:-1], packet.digest(data[:-1]))
        self.ready, self.pending = threading.Event(), bytearray()
        self.frames, self.bound = [], None

    def _on_output(self, category, data):
        if category != 'stdout-bound':
            return
        self.pending.extend(data)
        packet.require(len(self.pending) <= binding.MAX_FRAME)
        while b'\n' in self.pending:
            raw, _, rest = self.pending.partition(b'\n')
            self.pending[:] = rest
            value = packet.strict_json(bytes(raw), binding.MAX_FRAME)
            packet.require(len(self.frames) < 2)
            if not self.frames:
                packet.keys(value, 'schema nonce ownerSha256 payloadDirectorySha256')
                packet.require(value['schema'] == 'fleetory.audit-payload-ready.v1' and value['nonce'] == self.value['nonce'])
                packet.hex_value(value['ownerSha256'])
                packet.hex_value(value['payloadDirectorySha256'])
                self.bound = binding.BoundPayload(self.command, self.session, self.process, self.fence, value, self.value)
                self.frames.append(value)
                self.ready.set()
            else:
                self.frames.append(value)

    def _write(self):
        try:
            self._send(self.data)
            while not self.ready.wait(0.01):
                if self.errors or self.stopping.is_set():
                    return
                process._check_deadline(self.start_time, self.seconds)
            self.bound.check()
            process._check_deadline(self.start_time, self.seconds)
            release = dict(schema='fleetory.audit-payload-finish.v1', nonce=self.value['nonce'],
                ownerSha256=self.frames[0]['ownerSha256'], releaseSha256=self.bound.release())
            data = bundle.canonical(release) + b'\n'
            self.expected_input_bytes += len(data)
            self._send(data)
        except Exception:
            self.errors.append('payload-release-refused')
        finally:
            self._close_input()

    def finalize_binding(self, child, ended, failed):
        self.resource_metadata = dict(schema='fleetory.audit-payload-binding-result.v1',
            bundleSha256=self.value['bundleSha256'], declaredComponentFilesPinned=True,
            payloadNamespaceBound=False, payloadRemovedVerified=False,
            backendNamespaceBound=False, backendCleanupVerified=False,
            runtimeDependenciesAuthenticated=False, originalInputsRead=False, cleanupAuthorized=False)
        try:
            packet.require(not failed and child.returncode == 0 and ended['noRunningMembersVerified'])
            packet.require(not self.pending and len(self.frames) == 2 and self.bound is not None)
            final = self.frames[1]
            packet.keys(final, 'schema nonce releaseRequested')
            packet.require(final['schema'] == 'fleetory.audit-payload-closed.v1' and
                final['nonce'] == self.value['nonce'] and final['releaseRequested'] is True)
            self.bound.verify_removed()
            self.session.check()
            self.resource_metadata.update(payloadNamespaceBound=True, payloadRemovedVerified=True)
        finally:
            if self.bound is not None:
                self.bound.close()


def reserve_payload(trusted_repository, trusted_python, manifest_bytes, manifest_sha256, session):
    """One fixed Python owner; no user data, command, endpoint or root wire interface."""
    with bundle.HeldBundle(trusted_repository, trusted_python, manifest_bytes, manifest_sha256, session) as held:
        report = session.report()
        value = dict(schema='fleetory.audit-payload-reservation.v1', nonce=report['nonce'],
            controlSha256=report['reservationSha256'], controlDirectorySha256=binding.directory_hash(session._directory),
            bundleSha256=held.digest)
        data = bundle.canonical(value)
        owner = held.sources['eng/pilot/audit_payload_owner.py']
        command = process._Command(held.python, (*held.sources.values(), held.root),
            ('-I', '-B', str(owner.path), packet.digest(data)), held.repository,
            process.environment(held.python), 'payload-reservation')
        result = process._run_owned(command, session, data + b'\n', 10)
    packet.require(result.exit_code == 0 and result.stderr == b'')
    return result


if __name__ == '__main__':
    raise SystemExit('Payload launch is a fixed library; no operator data, command, endpoint or root CLI is provided.')
