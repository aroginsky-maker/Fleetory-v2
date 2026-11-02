#!/usr/bin/env python3
"""Root-owned pilot audit snapshots. Same-host administration is not WORM custody."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import stat
import subprocess
import sys
import tempfile
import threading
import uuid

MAX_SNAPSHOT = 8 * 1024 * 1024
MAX_EXPORT = 16 * 1024 * 1024
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_EVENTS = 10000
COMMAND_TIMEOUT = 25
ZERO = '0' * 64
HEX = re.compile(r'[0-9a-f]{64}\Z')
SEQUENCE = re.compile(r'[0-9]{12}\Z')
UTC = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z')
EVENT_FIELDS = {'event_id', 'actor_subject_id', 'actor_kind', 'action', 'target_type',
                'target_id', 'correlation_id', 'occurred_at', 'recorded_at', 'context_json'}
SQL = """
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL timezone = 'UTC';
SELECT json_build_object(
  'schema', 'fleetory.audit-snapshot.v1',
  'pendingExportCount', (SELECT count(*) FROM platform.audit_export_queue),
  'events', COALESCE((SELECT json_agg(e ORDER BY event_id) FROM (
    SELECT event_id, actor_subject_id, actor_kind, action, target_type, target_id,
      correlation_id,
      to_char(occurred_at, 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS occurred_at,
      to_char(recorded_at, 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS recorded_at,
      context_json::text AS context_json
    FROM platform.audit_events ORDER BY event_id LIMIT 10001
  ) AS e), '[]'::json));
COMMIT;
"""


class ArchiveError(Exception):
    """A fail-closed archive contract rejection; never includes event content."""


def require(condition):
    if not condition:
        raise ArchiveError('Audit archive validation failed.')


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(',', ':')).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def parse(data, limit):
    require(0 < len(data) <= limit)
    value = json.loads(data.decode('utf-8'), object_pairs_hook=unique_object, parse_float=Decimal,
                       parse_constant=lambda _: require(False))
    require(type(value) is dict)
    return value


def fields(value, names):
    require(type(value) is dict and set(value) == set(names))


def utc(value):
    require(type(value) is str and UTC.fullmatch(value))
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)


def validate_event(event):
    fields(event, EVENT_FIELDS)
    identity = event['event_id']
    require(type(identity) is str and str(uuid.UUID(identity)) == identity)
    require(type(event['actor_kind']) is int)
    for name, limit in (('actor_subject_id', 128), ('action', 128), ('correlation_id', 128)):
        require(type(event[name]) is str and 0 < len(event[name]) <= limit)
    for name, limit in (('target_type', 64), ('target_id', 128)):
        require(event[name] is None or (type(event[name]) is str and len(event[name]) <= limit))
    utc(event['occurred_at'])
    utc(event['recorded_at'])
    context = event['context_json']
    require(context is None or type(context) is str)
    if context is not None:
        # Preserve PostgreSQL's JSON text exactly; validation must not round numeric values.
        json.loads(context, object_pairs_hook=unique_object, parse_float=Decimal,
                   parse_constant=lambda _: require(False))
    return identity


def event_map(snapshot):
    fields(snapshot, ('schema', 'events', 'pendingExportCount'))
    require(snapshot['schema'] == 'fleetory.audit-snapshot.v1')
    pending = snapshot['pendingExportCount']
    require(type(pending) is int and 0 <= pending <= 2147483647)
    events = snapshot['events']
    require(type(events) is list and len(events) <= MAX_EVENTS)
    require(len(canonical(snapshot)) <= MAX_SNAPSHOT)
    result = {}
    for event in events:
        identity = validate_event(event)
        require(identity not in result)
        result[identity] = canonical(event)
    require(list(result) == sorted(result))
    return result


def extends(before, after):
    require(all(after.get(key) == value for key, value in before.items()))


def receipt_chain(receipts):
    require(type(receipts) is list and 0 < len(receipts) <= MAX_ENTRIES)
    previous = ZERO
    previous_time = datetime.min.replace(tzinfo=timezone.utc)
    for sequence, receipt in enumerate(receipts, 1):
        fields(receipt, ('schema', 'sequence', 'capturedAt', 'snapshotSha256', 'previousReceiptSha256'))
        require(receipt['schema'] == 'fleetory.audit-archive-receipt.v1')
        require(type(receipt['sequence']) is int and receipt['sequence'] == sequence)
        require(type(receipt['snapshotSha256']) is str and HEX.fullmatch(receipt['snapshotSha256']))
        require(receipt['previousReceiptSha256'] == previous)
        instant = utc(receipt['capturedAt'])
        require(instant >= previous_time)
        previous, previous_time = digest(receipt), instant
    return previous


def read_file(path, limit):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit)
        data = stream.read(limit + 1)
    require(0 < len(data) <= limit)
    return data


def private_path(path, mode, directory):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and info.st_uid == os.geteuid())
    require(stat.S_IMODE(info.st_mode) == mode)
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
    if not directory:
        require(info.st_nlink == 1)


def validate_ancestry(root):
    require(root.is_absolute() and '..' not in root.parts)
    for path in (root, *root.parents):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == 0)
        writable = info.st_mode & 0o022
        require(not writable or bool(info.st_mode & stat.S_ISVTX))


def initialize(root):
    require(os.name == 'posix' and os.geteuid() == 0)
    validate_ancestry(root.parent)
    root.mkdir(mode=0o700, exist_ok=True)
    private_path(root, 0o700, True)
    (root / 'entries').mkdir(mode=0o700, exist_ok=True)
    private_path(root / 'entries', 0o700, True)
    for path in (root / 'entries', root, root.parent):
        sync_directory(path)


@contextmanager
def archive_lock(root):
    import fcntl
    require(os.geteuid() == 0)
    validate_ancestry(root)
    private_path(root, 0o700, True)
    private_path(root / 'entries', 0o700, True)
    descriptor = os.open(root / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        private_path(root / '.lock', 0o600, False)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def inspect(root):
    require(set(path.name for path in root.iterdir()) <= {'entries', '.lock'})
    entries = sorted((root / 'entries').iterdir())
    require(len(entries) <= MAX_ENTRIES)
    receipts, snapshot, previous_events, total = [], None, {}, 0
    for sequence, entry in enumerate(entries, 1):
        require(SEQUENCE.fullmatch(entry.name) and int(entry.name) == sequence)
        private_path(entry, 0o700, True)
        require(set(path.name for path in entry.iterdir()) == {'receipt.json', 'snapshot.json'})
        values = {}
        for name, limit in (('receipt', 1024), ('snapshot', MAX_SNAPSHOT)):
            path = entry / (name + '.json')
            private_path(path, 0o400, False)
            data = read_file(path, limit)
            values[name] = parse(data, limit)
            require(data == canonical(values[name]))
            total += len(data)
        require(total <= MAX_ARCHIVE)
        snapshot = values['snapshot']
        current = event_map(snapshot)
        extends(previous_events, current)
        previous_events = current
        require(digest(snapshot) == values['receipt']['snapshotSha256'])
        receipts.append(values['receipt'])
    if receipts:
        receipt_chain(receipts)
    return receipts, snapshot, total


def summary(receipts, snapshot, total, status):
    return {'status': status, 'snapshotCount': len(receipts), 'archiveBytes': total,
            'eventCount': len(snapshot['events']) if snapshot else 0,
            'lastReceiptSha256': digest(receipts[-1]) if receipts else ZERO,
            'latestSnapshotSha256': digest(snapshot) if snapshot else ZERO,
            'independentCustodyVerified': False, 'administratorTamperProof': False,
            'sourceSignedStateVerified': False}


def write_sealed(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish(root, snapshot):
    current = event_map(snapshot)
    with archive_lock(root):
        receipts, previous, total = inspect(root)
        if previous:
            extends(event_map(previous), current)
            if canonical(previous) == canonical(snapshot):
                return summary(receipts, previous, total, 'unchanged')
        require(len(receipts) < MAX_ENTRIES)
        receipt = {'schema': 'fleetory.audit-archive-receipt.v1', 'sequence': len(receipts) + 1,
                   'capturedAt': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                   'snapshotSha256': digest(snapshot),
                   'previousReceiptSha256': digest(receipts[-1]) if receipts else ZERO}
        receipt_chain(receipts + [receipt])
        encoded = canonical(snapshot)
        require(total + len(encoded) + len(canonical(receipt)) <= MAX_ARCHIVE)
        require(os.statvfs(root).f_bavail * os.statvfs(root).f_frsize >= 512 * 1024 * 1024)
        with tempfile.TemporaryDirectory(prefix='.pending-', dir=root) as temporary:
            staged = Path(temporary)
            write_sealed(staged / 'snapshot.json', encoded)
            write_sealed(staged / 'receipt.json', canonical(receipt))
            sync_directory(staged)
            target = root / 'entries' / f'{receipt["sequence"]:012d}'
            require(not target.exists())
            os.rename(staged, target)
            sync_directory(root / 'entries')
            sync_directory(root)
        checked, latest, used = inspect(root)
        return summary(checked, latest, used, 'created')


def bounded_command(arguments):
    output = queue.Queue(maxsize=1)
    with subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        def collect():
            try:
                output.put(process.stdout.read(MAX_SNAPSHOT + 1))
            except OSError:
                output.put(b'')
        reader = threading.Thread(target=collect, daemon=True)
        reader.start()
        try:
            data = output.get(timeout=COMMAND_TIMEOUT)
            require(len(data) <= MAX_SNAPSHOT)
            require(process.wait(timeout=3) == 0)
            return parse(data, MAX_SNAPSHOT)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            reader.join(timeout=3)


def capture(root):
    arguments = ['/usr/bin/docker', 'exec', '--user', '999:999',
                 '-e', 'PGCONNECT_TIMEOUT=5',
                 '-e', 'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=2000',
                 'fleetory-pilot-postgres-1', 'psql', '-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
                 '-U', 'postgres', '-d', 'fleetory', '-c', SQL]
    return publish(root, bounded_command(arguments))


def export(root):
    with archive_lock(root):
        receipts, snapshot, _ = inspect(root)
        require(receipts)
        value = {'schema': 'fleetory.audit-archive-export.v1', 'receipts': receipts, 'snapshot': snapshot}
        data = canonical(value)
        require(len(data) <= MAX_EXPORT)
        return data


def validate_export(data):
    value = parse(data, MAX_EXPORT)
    fields(value, ('schema', 'receipts', 'snapshot'))
    require(value['schema'] == 'fleetory.audit-archive-export.v1')
    last = receipt_chain(value['receipts'])
    events = event_map(value['snapshot'])
    require(digest(value['snapshot']) == value['receipts'][-1]['snapshotSha256'])
    return value, last, events


def verify_export(data, expected, checkpoint=None, expected_checkpoint=None):
    require(type(expected) is str and HEX.fullmatch(expected))
    require(hashlib.sha256(data).hexdigest() == expected)
    value, last, events = validate_export(data)
    require((checkpoint is None) == (expected_checkpoint is None))
    if checkpoint is not None:
        require(type(expected_checkpoint) is str and HEX.fullmatch(expected_checkpoint))
        require(hashlib.sha256(checkpoint).hexdigest() == expected_checkpoint)
        prior, _, before = validate_export(checkpoint)
        count = len(prior['receipts'])
        require(len(value['receipts']) >= count and value['receipts'][:count] == prior['receipts'])
        extends(before, events)
    return {'status': 'verified', 'snapshotCount': len(value['receipts']), 'eventCount': len(events),
            'exportSha256': expected, 'lastReceiptSha256': last,
            'checkpointVerified': checkpoint is not None,
            'independentCustodyVerified': False, 'administratorTamperProof': False,
            'sourceSignedStateVerified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('init', 'capture', 'verify', 'export'):
        command = commands.add_parser(name)
        command.add_argument('--root', type=Path, default=Path('/var/lib/fleetory-audit-archive'))
    command = commands.add_parser('verify-export')
    command.add_argument('--input', type=Path, required=True)
    command.add_argument('--expected-sha256', required=True)
    command.add_argument('--checkpoint', type=Path)
    command.add_argument('--expected-checkpoint-sha256')
    args = parser.parse_args()
    if args.command == 'verify-export':
        result = verify_export(read_file(args.input, MAX_EXPORT), args.expected_sha256,
                               read_file(args.checkpoint, MAX_EXPORT) if args.checkpoint else None,
                               args.expected_checkpoint_sha256)
    else:
        require(os.name == 'posix' and os.geteuid() == 0)
        if args.command == 'init':
            initialize(args.root)
        if args.command == 'capture':
            result = capture(args.root)
        elif args.command == 'export':
            sys.stdout.buffer.write(export(args.root))
            return
        else:
            with archive_lock(args.root):
                receipts, snapshot, total = inspect(args.root)
                result = summary(receipts, snapshot, total, 'verified')
    print(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (ArchiveError, OSError, ValueError, KeyError, TypeError, RecursionError,
            queue.Empty, subprocess.SubprocessError):
        print('Audit archive operation failed.', file=sys.stderr)
        sys.exit(1)
