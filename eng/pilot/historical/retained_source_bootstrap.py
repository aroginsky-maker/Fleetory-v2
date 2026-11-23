"""Fixed retained entry points using filesystem source, never filesystem pyc."""
import sys
import _frozen_importlib_external as external


def _source_code(loader, fullname):
    path = loader.get_filename(fullname)
    return loader.source_to_code(loader.get_data(path), path)


def _refuse_sourceless(_loader, _fullname):
    raise ImportError('Sourceless Python code refused')


def main():
    if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
        raise ValueError('Required interpreter isolation absent')
    targets = {'peer': 'historical/retained_service_peer.py',
               'catalog': 'historical/retained_code_catalog.py',
               'inventory': 'pg_inventory_v2.py',
               'observation': 'audit_observation.py',
               'historical-observation': 'historical_audit_observation.py'}
    if len(sys.argv) < 2 or sys.argv[1] not in targets:
        raise ValueError('Unknown fixed source entry')
    _execute(targets[sys.argv[1]], sys.argv[2:])


def _execute(relative, arguments):
    if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
        raise ValueError('Required interpreter isolation absent')
    # Install before pathlib or any project import. Frozen/builtin and external
    # runtime/zip/native loaders are not authenticated by this source boundary.
    external.SourceFileLoader.get_code = _source_code
    external.SourcelessFileLoader.get_code = _refuse_sourceless
    from pathlib import Path
    pilot = Path(__file__).resolve().parent.parent
    target = pilot / relative
    sys.argv = [str(target), *arguments]
    sys.path.insert(0, str(pilot))
    entry = type(sys)('__main__')
    entry.__dict__.update(__file__=str(target), __package__=None, __spec__=None, __cached__=None)
    sys.modules['__main__'] = entry
    loader = external.SourceFileLoader('__main__', str(target))
    entry.__loader__ = loader
    loader.exec_module(entry)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.stderr.write('Retained source bootstrap refused; no contents logged.\n')
        sys.exit(1)
