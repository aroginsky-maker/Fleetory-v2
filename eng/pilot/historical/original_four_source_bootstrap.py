"""Separate fixed original-purpose entry; the legacy five CLI targets stay closed."""
import sys
import _frozen_importlib_external as external


def main():
    if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
        raise ValueError('Required interpreter isolation absent')
    path = __file__.rsplit('/', 1)[0] if '/' in __file__ else __file__.rsplit('\\', 1)[0]
    path += '/retained_source_bootstrap.py'
    loader = external.SourceFileLoader('retained_source_bootstrap', path)
    module = type(sys)('retained_source_bootstrap')
    module.__file__ = path
    # This one loader reads source before any project import or pyc lookup.
    loader.get_code = lambda fullname: loader.source_to_code(loader.get_data(path), path)
    loader.exec_module(module)
    module._execute('historical/original_four_peer.py', sys.argv[1:])


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.stderr.write('Original four source bootstrap refused; no contents logged.\n')
        sys.exit(1)
