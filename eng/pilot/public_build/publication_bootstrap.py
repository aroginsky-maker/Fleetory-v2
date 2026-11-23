"""Fixed in-memory publication entry. Code digest is supplied by the original trusted launcher."""
import sys
import os
import hashlib
import json
import base64
import re
import types
import importlib.abc
import importlib.util
import threading

MAX_FRAME = 12 * 1024 * 1024


def require(value):
    if not value:
        raise ValueError('Publication code frame refused')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def read_exact(length):
    require(type(length) is int and 0 < length <= MAX_FRAME)
    result = bytearray()
    while len(result) < length:
        part = os.read(0, min(65536, length - len(result)))
        require(part)
        result.extend(part)
    return bytes(result)


def admitted_modules(raw, expected):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_FRAME)
    require(type(expected) is str and re.fullmatch('[a-f0-9]{64}', expected))
    require(hashlib.sha256(raw).hexdigest() == expected)
    value = json.loads(raw, object_pairs_hook=unique)
    require(type(value) is dict and set(value) == {'schema', 'modules'})
    require(value['schema'] == 'fleetory.publication-code-frame.v1')
    entries = value['modules']
    require(type(entries) is dict and 0 < len(entries) <= 448)
    result, total = {}, 0
    for name, entry in entries.items():
        require(type(name) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*', name))
        require(type(entry) is dict and set(entry) == {'source', 'sha256'})
        source = base64.b64decode(entry['source'], validate=True)
        require(0 < len(source) <= 1048576)
        require(hashlib.sha256(source).hexdigest() == entry['sha256'])
        total += len(source)
        require(total <= 8388608)
        result[name] = source
    require('public_build.publication_peer' in result)
    return types.MappingProxyType(result)


class MemorySource(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, modules):
        self.modules = modules
        self.packages = frozenset(name.rsplit('.', 1)[0] for name in modules if '.' in name)
        # Standard runtime modules were loaded before this boundary. Project sources
        # may not replace an already imported runtime module or its namespace.
        require(not (set(modules) | set(self.packages)) & set(sys.modules))

    def find_spec(self, fullname, path=None, target=None):
        if fullname in self.modules or fullname in self.packages:
            return importlib.util.spec_from_loader(fullname, self, is_package=fullname in self.packages)
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        name = module.__spec__.name
        if name in self.packages:
            module.__path__ = []
        if name in self.modules:
            origin = '<fleetory-reviewed-source>/' + name.replace('.', '/') + '.py'
            module.__file__ = origin
            module.__cached__ = None
            exec(compile(self.modules[name], origin, 'exec', dont_inherit=True), module.__dict__)


def main():
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)
    require(len(sys.argv) == 4)
    # Independent upper bound, including a stalled code frame and loader startup.
    def expire():
        threading.Event().wait(60)
        os._exit(37)
    threading.Thread(target=expire, daemon=True).start()
    expected, root, nonce = sys.argv[1:]
    length = int.from_bytes(read_exact(4), 'big')
    modules = admitted_modules(read_exact(length), expected)
    sys.meta_path.insert(0, MemorySource(modules))
    # The entry and import namespace are fixed; neither wire input nor argv selects code.
    from public_build.publication_peer import serve
    serve(root, nonce)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.stderr.write('Publication code frame refused; no contents logged.\n')
        sys.exit(37)
