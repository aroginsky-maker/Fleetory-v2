"""Linux owned unreaped leader/pidfd and verified process-group lifetime fencing."""
import os
from pathlib import Path
import signal
import time


def require(value):
    if not value:
        raise OSError('Owned Linux process observation refused.')


def process_fields(pid):
    text = (Path('/proc') / str(pid) / 'stat').read_text(encoding='ascii')
    end = text.rfind(')')
    require(end > 0)
    values = text[end + 1:].split()
    require(len(values) >= 20)
    return dict(state=values[0], parent=int(values[1]), group=int(values[2]), session=int(values[3]), birth=values[19])


class GroupFence:
    def __init__(self, process):
        self.process, self.pidfd = process, None
        info = process_fields(process.pid)
        require(info['group'] == info['session'] == process.pid and info['state'] not in ('Z', 'X'))
        self.birth = info['birth']
        try:
            self.pidfd = os.pidfd_open(process.pid, 0)
            os.set_inheritable(self.pidfd, False)
        except BaseException:
            self.close()
            raise

    def exited(self):
        # Observe, do not reap: the owned leader reserves its numeric group ID until cleanup.
        value = os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        return value is not None

    def identity(self, process, pinned):
        info = process_fields(process.pid)
        require(info['birth'] == self.birth and info['group'] == info['session'] == process.pid)
        require(info['state'] not in ('Z', 'X') and not self.exited())
        actual = (Path('/proc') / str(process.pid) / 'exe').stat()
        expected = os.fstat(pinned.fd)
        require((actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino))
        pinned.check()
        return dict(pid=process.pid, imageSha256=pinned.digest, birthKind='linux-proc-start-ticks',
            birthToken=self.birth, ownedPidfd=True, actualImageMatched=True)

    def _members(self):
        members = []
        for entry in Path('/proc').iterdir():
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            try:
                info = process_fields(int(entry.name))
            except (FileNotFoundError, ProcessLookupError):
                continue
            if info['group'] == info['session'] == self.process.pid:
                members.append(info)
        return members

    def terminate(self):
        info = process_fields(self.process.pid)
        require(info['birth'] == self.birth and info['group'] == info['session'] == self.process.pid)
        # Leader is still owned and unreaped, preventing group-ID reuse during this signal.
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            require(not any(value['state'] not in ('Z', 'X') for value in self._members()))
        deadline = time.monotonic_ns() + 3_000_000_000
        while True:
            members = self._members()
            if not any(info['state'] not in ('Z', 'X') for info in members):
                break
            require(time.monotonic_ns() < deadline)
            time.sleep(0.01)
        return dict(kind='linux-process-group', activeMembers=0, noRunningMembersVerified=True,
            zombieEntries=sum(info['state'] == 'Z' for info in members),
            escapedSessionContainmentVerified=False, supervisorDeathKillOnCloseConfigured=False)

    def close(self):
        if self.pidfd is not None:
            fd, self.pidfd = self.pidfd, None
            os.close(fd)


def pid_is_running(pid):
    try:
        return process_fields(pid)['state'] not in ('Z', 'X')
    except (FileNotFoundError, ProcessLookupError):
        return False
