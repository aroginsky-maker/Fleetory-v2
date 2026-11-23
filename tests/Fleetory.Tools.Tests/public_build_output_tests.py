"""Generated tar policy tests; no file extraction, compiler, daemon or original data."""
from pathlib import Path
import hashlib
import importlib.util
import io
import json
import tarfile
import unittest

path = Path(__file__).resolve().parents[2] / 'eng/pilot/public_build/output.py'
spec = importlib.util.spec_from_file_location('closed_sdk_output', path)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def make(files=None, root=True):
    if files is None:
        files = {'Fleetory.Server.dll': b'generated server', 'ServerBackendProbe.dll': b'generated probe',
            'ServerBackendProbe.runtimeconfig.json': json.dumps(policy.RUNTIME).encode(),
            'ServerBackendProbe.deps.json': json.dumps({'runtimeTarget': {'name': '.NETCoreApp,Version=v10.0', 'signature': ''},
                'compilationOptions': {}, 'targets': {'.NETCoreApp,Version=v10.0': {}}, 'libraries': {}}).encode()}
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        if root:
            entry = tarfile.TarInfo('./');entry.type=tarfile.DIRTYPE;entry.mode=0o700;archive.addfile(entry)
        for name, data in files.items():
            entry = tarfile.TarInfo('./'+name);entry.size=len(data);entry.mode=0o700
            archive.addfile(entry, io.BytesIO(data))
    return stream.getvalue()


def pin(raw):
    return hashlib.sha256(raw).hexdigest()


def header(raw, start, value, offset=512):
    changed=bytearray(raw)
    changed[offset+start:offset+start+len(value)]=value
    changed[offset+148:offset+156]=b' '*8
    checksum=sum(changed[offset:offset+512])
    changed[offset+148:offset+156]=('{:06o}\0 '.format(checksum)).encode()
    return bytes(changed)


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.raw=make()

    def refuse(self, raw, expected=None):
        with self.assertRaises(ValueError):
            policy.inspect(raw, pin(raw) if expected is None else expected)

    def test_original_flat_bytes_immutable_and_permission_metadata_discarded(self):
        files=policy.inspect(self.raw,pin(self.raw))
        self.assertEqual(4,len(files));self.assertEqual(b'generated probe',files['ServerBackendProbe.dll'])
        with self.assertRaises(TypeError):files['extra.dll']=b'not accepted'
        self.assertEqual(4,len(policy.inspect(make(root=False),pin(make(root=False)))))

    def test_byte_type_length_and_independent_pin_required(self):
        for raw in (b'',b'x',self.raw[:-1],bytearray(self.raw)):
            with self.subTest(raw_type=type(raw),length=len(raw)):self.refuse(raw,'0'*64)
        for expected in ('0'*64,'f'*63,'F'*64,True):
            with self.subTest(expected=expected):self.refuse(self.raw,expected)
        self.refuse(self.raw+self.raw,'0'*64)

    def test_links_special_entries_and_extension_records_refused(self):
        for kind in (b'1',b'2',b'3',b'4',b'6',b'x',b'g',b'L',b'K',b'S'):
            with self.subTest(kind=kind):self.refuse(header(self.raw,156,kind))
        self.refuse(header(self.raw,157,b'foreign.dll'))

    def test_paths_aliases_and_platform_device_names_refused(self):
        for name in ('../x.dll','/x.dll','nested/x.dll','././x.dll','.dll','x.DLL','x .dll','CON.dll','LPT9.dll'):
            with self.subTest(name=name):self.refuse(header(self.raw,0,name.encode().ljust(100,b'\0')))
        files=dict(policy.inspect(self.raw,pin(self.raw)));files['fleetory.server.dll']=b'case alias'
        raw=make(files);self.refuse(raw)

    def test_checksum_magic_numeric_and_hidden_header_fields_refused(self):
        changed=bytearray(self.raw);changed[512+148]^=1;self.refuse(bytes(changed))
        for start,value in ((257,b'unknown!'),(136,b'\x80'+b'\0'*11),(108,b'-000001\0'),
                            (100,b'0004700\0'),(345,b'hidden-prefix'),(500,b'X'),(329,b'0000001\0')):
            with self.subTest(start=start,value=value):self.refuse(header(self.raw,start,value))
        self.refuse(header(self.raw,0,b'abc\0hidden'.ljust(100,b'\0')))

    def test_truncation_padding_and_concatenated_tar_refused(self):
        self.refuse(self.raw[:1024])
        changed=bytearray(self.raw);changed[1024+len(b'generated server')]=1;self.refuse(bytes(changed))
        self.refuse(self.raw+b'x'*512)
        self.refuse(self.raw+make())

    def test_root_only_first_and_file_bounds_preserved(self):
        self.refuse(header(self.raw,156,b'5'))
        self.refuse(header(self.raw,124,('{:011o}\0'.format(policy.MAX_CONTENT+1)).encode()))
        self.refuse(header(self.raw,124,b'00000000000\0'))
        files=dict(policy.inspect(self.raw,pin(self.raw)))
        files.update({f'x{n}.dll':b'x' for n in range(125)})
        raw=make(files);self.refuse(raw)

    def test_required_files_and_non_net10_runtime_refused(self):
        files=dict(policy.inspect(self.raw,pin(self.raw)));del files['ServerBackendProbe.dll']
        raw=make(files);self.refuse(raw)
        files=dict(policy.inspect(self.raw,pin(self.raw)))
        for config in (b'{"runtimeOptions":{"tfm":"net9.0"}}',
                       b'{"runtimeOptions":{},"runtimeOptions":{}}',
                       json.dumps(policy.RUNTIME).replace('false','0').encode(),
                       json.dumps(policy.RUNTIME).replace('"net10.0"','"net10.0","additionalProbingPaths":["/foreign"]').encode()):
            changed=dict(files);changed['ServerBackendProbe.runtimeconfig.json']=config
            raw=make(changed);self.refuse(raw)

    def test_json_duplicate_keys_constants_bad_utf8_and_excess_depth_refused(self):
        files=dict(policy.inspect(self.raw,pin(self.raw)))
        for deps in (b'{"targets":{},"targets":{}}',b'NaN',b'\xff',b'['*100+b'0'+b']'*100,b'{}'):
            changed=dict(files);changed['ServerBackendProbe.deps.json']=deps
            raw=make(changed);self.refuse(raw)


if __name__=='__main__':unittest.main()
