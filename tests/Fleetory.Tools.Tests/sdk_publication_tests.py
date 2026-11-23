"""Generated SDK archive -> real held publication; native owner/fence are models, no backend."""
from pathlib import Path
import os
import sys
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'eng/pilot'))
import audit_publication_namespace as ns
from publication_namespace_tests import PublicationNamespaceContracts
import public_build_output_tests as sdk
import audit_probe_image_tests as legacy

packet=ns.packet


class SdkPublicationTests(unittest.TestCase):
    session=PublicationNamespaceContracts.session
    pair=PublicationNamespaceContracts.pair

    def setUp(self):
        PublicationNamespaceContracts.setUp(self)
        self.archive=sdk.make()
        self.expected=sdk.pin(self.archive)
        self.content=sdk.policy.inspect(self.archive,self.expected)
        self.manifest=ns.bundle.manifest_from_files(self.content)
        self.manifest_pin=packet.digest(self.manifest)

    def test_sdk_bytes_seal_same_files_and_descriptors_through_context(self):
        with self.pair() as (_,owned,bound):
            receipt=owned.publish_sdk(self.archive,self.expected)
            self.assertEqual(4,receipt['files'])
            self.assertFalse(receipt['actualNativePublicationVerified'])
            self.assertEqual(dict(self.content),{n:p.read_bytes() for n,p in
                ((n,owned.output.path/n) for n in self.content)})
            self.assertEqual(legacy.measure(owned.output.path),ns.bundle.packet.strict_json(self.manifest,98304))
            before={n:pin.fd for n,pin in owned.published.pins.items()}
            context=owned.published.context(b'FROM separately-approved-pinned-base\n')
            self.assertTrue(context);self.assertEqual(before,{n:pin.fd for n,pin in owned.published.pins.items()})
            other=bound.seal(self.manifest);self.assertEqual(receipt,other)
            with self.assertRaises(ValueError):owned.publish_sdk(self.archive,self.expected)
            with self.assertRaises(ValueError):owned.seal(self.manifest)

    def test_invalid_archive_consumes_attempt_before_any_public_file_write(self):
        with self.pair() as (_,owned,_):
            changed=self.archive[:600]+b'X'+self.archive[601:]
            with self.assertRaises(ValueError):owned.publish_sdk(changed,self.expected)
            self.assertEqual([],list(owned.output.path.iterdir()))
            with self.assertRaises(ValueError):owned.publish_sdk(self.archive,self.expected)
            with self.assertRaises(ValueError):owned.seal(self.manifest)

    def test_wrong_intent_manifest_refuses_before_file_creation(self):
        self.manifest_pin='f'*64
        with self.pair() as (_,owned,_):
            with self.assertRaises(ValueError):owned.publish_sdk(self.archive,self.expected)
            self.assertEqual([],list(owned.output.path.iterdir()))

    def test_foreign_existing_file_is_preserved_and_not_overwritten(self):
        with self.pair() as (_,owned,_):
            file=owned.output.path/'ServerBackendProbe.dll';file.write_bytes(b'foreign generated public bytes')
            with self.assertRaises(ValueError):owned.publish_sdk(self.archive,self.expected)
            self.assertEqual(b'foreign generated public bytes',file.read_bytes())
            self.assertEqual(1,len(list(owned.output.path.iterdir())))

    def test_partial_write_is_preserved_and_cannot_be_repaired_or_sealed(self):
        with self.pair() as (_,owned,_):
            original=ns.empty._write_all
            calls=[]
            def interrupted(fd,data):
                original(fd,data);calls.append(fd)
                raise OSError('Injected generated-only public file write interruption')
            with patch.object(ns.empty,'_write_all',interrupted),self.assertRaises(OSError):
                owned.publish_sdk(self.archive,self.expected)
            self.assertEqual(1,len(calls));self.assertEqual(1,len(list(owned.output.path.iterdir())))
            with self.assertRaises(ValueError):owned.publish_sdk(self.archive,self.expected)
            with self.assertRaises(ValueError):owned.seal(self.manifest)
            self.assertIsNone(owned.published)

    def test_manifest_factory_rejects_mutable_data_aliases_paths_and_missing_probe(self):
        for content in ({}, {'../escape.dll':b'x'}, {'Folder/x.dll':b'x'},
                        {**self.content,True:b'not a file name'},
                        {**self.content,'serverbackendprobe.dll':b'alias'},
                        {n:(bytearray(v) if n=='ServerBackendProbe.dll' else v) for n,v in self.content.items()},
                        {n:v for n,v in self.content.items() if n!='ServerBackendProbe.dll'}):
            with self.subTest(names=list(content)),self.assertRaises(ValueError):ns.bundle.manifest_from_files(content)


if __name__=='__main__':unittest.main()
