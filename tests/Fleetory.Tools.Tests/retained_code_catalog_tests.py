"""Fixed namespace metadata to held-code plans; no native work or original inputs."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'eng/pilot'))
from historical import retained_code_catalog as catalog

C,H=catalog.C,catalog.H
REFUSALS=(ValueError,OSError,KeyError,TypeError,catalog.lease.files.archive.ArchiveError)


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fleetory-code-catalog-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        names=(*catalog.lease.prep.ROOTS,*('tests/Fleetory.Tools.Tests/'+n for n in catalog.HELPERS),
               'eng/pilot/helper.py','eng/pilot/.gitattributes','eng/pilot/public_build/context.py',
               'eng/pilot/public_build/trust.py','src/Product/Product.csproj','src/Product/Code.cs')
        self.snapshot=dict(schema='fleetory.historical-code-snapshot.v2',revision='1'*40,sourcePins={})
        for name in names:
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True)
            data=('public '+name).encode('ascii');path.write_bytes(data)
            self.snapshot['sourcePins'][name]=dict(bytes=len(data),sha256=H(data))
        self.nonce='12345678-1234-4123-8123-123456789abc'

    def test_catalog_reuses_complete_supplied_pins_and_holds_hidden_source_attributes(self):
        plan=catalog.build(self.root,self.snapshot,self.nonce)
        names=catalog.names(self.root)
        with catalog.lease.hold(self.root,plan,H(plan),names) as lease:
            self.assertEqual(len(names),lease.report()['files'])
            self.assertFalse(lease.report()['originalDataUseAuthorized'])

    def test_unsupported_source_basename_is_refused_before_content_or_lease_open(self):
        path=self.root/'eng/pilot/public_build/__init__.py'
        path.write_bytes(b'generated namespace marker')
        with patch.object(Path,'read_bytes') as read,patch.object(catalog.lease,'_HeldCode') as held:
            with self.assertRaises(REFUSALS):catalog.names(self.root)
            read.assert_not_called();held.assert_not_called()

    def test_unlisted_filesystem_code_cannot_enter_a_git_snapshot_plan(self):
        unexpected=self.root/'src/Product/unlisted.json';unexpected.write_bytes(b'generated-canary')
        with patch.object(Path,'read_bytes') as read:
            with self.assertRaises(REFUSALS):
                catalog.build(self.root,self.snapshot,self.nonce)
            read.assert_not_called()

    def test_unrelated_snapshot_paths_do_not_expand_the_fixed_runtime_namespace(self):
        value=copy.deepcopy(self.snapshot)
        value['sourcePins']['provider/private.key']=dict(bytes=1,sha256='a'*64)
        plan=catalog.build(self.root,value,self.nonce)
        decoded=catalog.packet.strict_json(plan,catalog.lease.MAX_PLAN)
        self.assertNotIn('provider/private.key',decoded['sourcePins'])

    def test_build_and_cache_outputs_are_not_promoted_to_source_authority(self):
        before=catalog.names(self.root)
        for directory in ('obj','bin','__pycache__'):
            path=self.root/'src/Product'/directory;path.mkdir()
            (path/'not-a-source.bin').write_bytes(b'generated')
        self.assertEqual(before,catalog.names(self.root))

    def test_missing_pins_and_invalid_scope_are_closed(self):
        for key in ('eng/pilot/helper.py','.editorconfig'):
            value=copy.deepcopy(self.snapshot);del value['sourcePins'][key]
            with self.assertRaises(REFUSALS):catalog.build(self.root,value,self.nonce)
        value=copy.deepcopy(self.snapshot);value['schema']='other'
        with self.assertRaises(REFUSALS):catalog.build(self.root,value,self.nonce)
        with self.assertRaises(REFUSALS):catalog.build(self.root,self.snapshot,'bad-nonce')

    def test_metadata_only_catalog_never_reads_source_contents(self):
        with patch.object(Path,'read_bytes') as read,patch('builtins.open') as opened:
            catalog.build(self.root,self.snapshot,self.nonce)
            read.assert_not_called();opened.assert_not_called()


if __name__=='__main__':unittest.main()
