"""Closed SDK tar byte policy only: no extraction, filesystem, runtime or custody grant."""
import hashlib
import json
import re
from types import MappingProxyType

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_CONTENT = 15 * 1024 * 1024
MAX_FILES = 128
REQUIRED = frozenset(('ServerBackendProbe.dll', 'ServerBackendProbe.deps.json',
                      'ServerBackendProbe.runtimeconfig.json', 'Fleetory.Server.dll'))
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\.(?:dll|json|pdb)\Z')
RUNTIME = {'runtimeOptions': {'tfm': 'net10.0', 'frameworks': [
    {'name': 'Microsoft.NETCore.App', 'version': '10.0.0'},
    {'name': 'Microsoft.AspNetCore.App', 'version': '10.0.0'}],
    'configProperties': {'System.Reflection.Metadata.MetadataUpdater.IsSupported': False,
        'System.Reflection.NullabilityInfoContext.IsSupported': True,
        'System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization': False}}}


def require(value):
    if not value:
        raise ValueError('Closed SDK output refused')


def _text(field):
    body, separator, padding = field.partition(b'\0')
    require(not separator or not any(padding))
    require(all(32 <= c < 127 for c in body))
    return body.decode('ascii')


def _octal(field):
    value = field.rstrip(b'\0 ')
    require(bool(value) and all(48 <= c <= 55 for c in value))
    return int(value, 8)


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def _json(data):
    require(type(data) is bytes and 0 < len(data) <= 1048576)
    def refuse_constant(_):
        raise ValueError('Closed SDK output refused')
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=_object, parse_constant=refuse_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('Closed SDK output refused') from error
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        require(depth <= 24)
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
    return value


def _header(header):
    require(sum(header[:148]) + 8 * 32 + sum(header[156:]) == _octal(header[148:156]))
    require(header[257:265] in (b'ustar\00000', b'ustar  \0'))
    require(not any(header[157:257]) and not any(header[345:]))
    _text(header[265:297]); _text(header[297:329])
    for field in (header[329:337], header[337:345]):
        require(not any(field) or _octal(field) == 0)
    mode, uid, gid, size, mtime = (_octal(header[a:b]) for a, b in
                                  ((100,108), (108,116), (116,124), (124,136), (136,148)))
    require(mode <= 0o777 and uid <= 0xffffffff and gid <= 0xffffffff and mtime <= 0x7fffffffffffffff)
    return _text(header[:100]), header[156:157], size


def inspect(raw, expected_sha256):
    """Return immutable file bytes. Hash/metadata do not authenticate SDK origin."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_ARCHIVE and len(raw) % 512 == 0)
    require(type(expected_sha256) is str and re.fullmatch('[a-f0-9]{64}', expected_sha256))
    require(hashlib.sha256(raw).hexdigest() == expected_sha256)
    files, aliases = {}, set()
    offset = total = entries = 0
    while True:
        require(offset + 1024 <= len(raw))
        header = raw[offset:offset + 512]
        if not any(header):
            require(not any(raw[offset:]))
            break
        name, kind, size = _header(header)
        entries += 1
        require(entries <= MAX_FILES + 1)
        offset += 512
        if kind == b'5':
            require(entries == 1 and name in ('.', './') and size == 0)
            continue
        # Archive permission bits are discarded; target context fixes regular files to 0644.
        require(kind in (b'0', b'\0'))
        if name.startswith('./'):
            name = name[2:]
        require(NAME.fullmatch(name) and name.lower() not in aliases and len(files) < MAX_FILES)
        stem = name.split('.')[0].upper()
        require(stem not in {'CON', 'PRN', 'AUX', 'NUL'} and not re.fullmatch(r'(COM|LPT)[1-9]', stem))
        require(0 < size <= MAX_CONTENT and total + size <= MAX_CONTENT)
        end = offset + size
        padded = (end + 511) // 512 * 512
        require(padded + 1024 <= len(raw) and not any(raw[end:padded]))
        files[name] = raw[offset:end]
        aliases.add(name.lower())
        total += size
        offset = padded
    require(REQUIRED <= files.keys())
    runtime = _json(files['ServerBackendProbe.runtimeconfig.json'])
    require(json.dumps(runtime, sort_keys=True, separators=(',', ':')) ==
            json.dumps(RUNTIME, sort_keys=True, separators=(',', ':')))
    deps = _json(files['ServerBackendProbe.deps.json'])
    require(type(deps) is dict and deps.keys() == {'runtimeTarget', 'compilationOptions', 'targets', 'libraries'})
    require(deps['runtimeTarget'] == {'name': '.NETCoreApp,Version=v10.0', 'signature': ''})
    require(type(deps['targets']) is dict and deps['targets'].keys() == {'.NETCoreApp,Version=v10.0'})
    require(type(deps['libraries']) is dict and type(deps['compilationOptions']) is dict)
    return MappingProxyType(files)
