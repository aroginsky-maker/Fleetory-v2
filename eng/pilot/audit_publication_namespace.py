"""Separate held public publication namespace; no publisher, backend, cleanup or private-input CLI."""
from contextlib import ExitStack
import json
import os
from pathlib import Path

import audit_probe_bundle as bundle
import audit_payload_binding as empty

packet,control,process,files=bundle.packet,bundle.control,bundle.process,bundle.files
SCHEMA='fleetory.publication-namespace-intent.v1'
MARKER,OUTPUT='publication-owner.json','publish'
MAX_FRAME=4096
SOURCES=tuple('eng/pilot/'+n+'.py' for n in bundle.prep.PYTHON_SOURCES)+(
    'eng/pilot/audit_probe_bundle.py','eng/pilot/audit_publication_namespace.py')


def name(nonce):
    return 'native-probe-publication-'+packet.identity(nonce)


def prepare(session,manifest_pin,source_pin):
    report=session.report()
    return bundle.prep.canonical(dict(schema=SCHEMA,nonce=report['nonce'],controlSha256=report['reservationSha256'],
        controlDirectorySha256=empty.directory_hash(session._directory),manifestSha256=manifest_pin,selectedSourcesSha256=source_pin))


def admit(data,expected):
    packet.require(type(data) is bytes and 0<len(data)<=MAX_FRAME and packet.digest(data)==expected)
    value=packet.strict_json(data,MAX_FRAME)
    packet.keys(value,'schema nonce controlSha256 controlDirectorySha256 manifestSha256 selectedSourcesSha256')
    packet.require(value['schema']==SCHEMA);packet.identity(value['nonce'])
    for key in ('controlSha256','controlDirectorySha256','manifestSha256','selectedSourcesSha256'):packet.hex_value(value[key])
    return value


def marker(value,pid,root_pin,output_pin):
    packet.require(type(pid) is int and 0<pid<=0xffffffff)
    return dict(schema='fleetory.publication-namespace-owner.v1',nonce=value['nonce'],controlSha256=value['controlSha256'],
        intentSha256=packet.digest(bundle.prep.canonical(value)),controlDirectorySha256=value['controlDirectorySha256'],
        manifestSha256=value['manifestSha256'],selectedSourcesSha256=value['selectedSourcesSha256'],ownerPid=pid,
        namespaceDirectorySha256=root_pin,outputDirectorySha256=output_pin)


def _mkdir(parent,leaf):
    parent.check()
    if os.name=='nt':os.mkdir(parent.path/leaf,mode=0o700)
    else:os.mkdir(leaf,mode=0o700,dir_fd=parent.fd);os.fsync(parent.fd)
    parent.check()


def _record(directory,data):
    fd=files.windows_create_new(directory.path/MARKER) if os.name=='nt' else os.open(
        MARKER,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory.fd)
    try:
        view=memoryview(data)
        while view:
            count=os.write(fd,view);packet.require(0<count<=len(view));view=view[count:]
        os.fsync(fd)
    finally:os.close(fd)
    if os.name=='posix':os.fsync(directory.fd)


class _HeldNamespace:
    def _check_tree(self):
        self.parent.check();self.directory.check();self.output.check();self.pin.check()
        packet.require(set(os.listdir(self.directory.path))=={MARKER,OUTPUT})
        if self.published is not None:self.published.check()

    def close(self):
        self._held.close()

    def __enter__(self):return self
    def __exit__(self,*_):self.close()


class OwnedPublication(_HeldNamespace):
    """Actual owner creates a fresh namespace. Close preserves all outcomes; no deletion API."""
    def __init__(self,repository,data,expected):
        self.value=admit(data,expected);self._held=ExitStack();self.published=None;self._attempted=False
        try:
            self.parent=self._held.enter_context(control.DirectoryLease(Path(repository)/'artifacts'))
            _mkdir(self.parent,name(self.value['nonce']))
            self.directory=self._held.enter_context(control.DirectoryLease(self.parent.path/name(self.value['nonce'])))
            _mkdir(self.directory,OUTPUT)
            self.output=self._held.enter_context(control.DirectoryLease(self.directory.path/OUTPUT))
            self.root_pin,self.output_pin=empty.directory_hash(self.directory),empty.directory_hash(self.output)
            raw=bundle.prep.canonical(marker(self.value,os.getpid(),self.root_pin,self.output_pin))
            self.owner_pin=packet.digest(raw);_record(self.directory,raw)
            self.pin=self._held.enter_context(process.PinnedFile(self.directory.path/MARKER,self.owner_pin))
            self.check()
        except BaseException:self.close();raise

    def check(self):
        self._check_tree()

    def ready(self):
        self.check()
        return dict(schema='fleetory.publication-namespace-ready.v1',nonce=self.value['nonce'],pid=os.getpid(),
            intentSha256=packet.digest(bundle.prep.canonical(self.value)),ownerSha256=self.owner_pin,
            namespaceDirectorySha256=self.root_pin,outputDirectorySha256=self.output_pin,privateInputsAccepted=False)

    def seal(self,data):
        packet.require(not self._attempted);self._attempted=True;self.check()
        self.published=self._held.enter_context(bundle.HeldProbeBundle(self.output.path,data,self.value['manifestSha256']))
        self.check()
        return dict(schema='fleetory.publication-namespace-sealed.v1',nonce=self.value['nonce'],ownerSha256=self.owner_pin,
            namespaceDirectorySha256=self.root_pin,outputDirectorySha256=self.output_pin,manifestSha256=self.value['manifestSha256'],
            bundleSha256=self.published.value['sha256'],files=self.published.value['files'],bytes=self.published.value['bytes'],
            privateInputsAccepted=False,actualNativePublicationVerified=False)


class BoundPublication(_HeldNamespace):
    """Controller independently observes live owner and namespace; holds all publication descriptors."""
    def __init__(self,command,session,child,fence,data,expected,ready):
        self.command,self.session,self.child,self.fence=command,session,child,fence
        self._held=ExitStack();self.published=None;self._attempted=False;self.released=False;self.acknowledged=False
        session._write_once('publication-attempt.json',dict(schema='fleetory.publication-namespace-attempt.v1',nonce=session._plan['nonce']))
        try:
            self.value=admit(data,expected);self.ready=ready
            packet.require(self.value['nonce']==session._plan['nonce'] and self.value['controlSha256']==session.report()['reservationSha256'] and
                self.value['controlDirectorySha256']==empty.directory_hash(session._directory))
            observed=self.owner_identity()
            packet.keys(ready,'schema nonce pid intentSha256 ownerSha256 namespaceDirectorySha256 outputDirectorySha256 privateInputsAccepted')
            packet.require(ready['schema']=='fleetory.publication-namespace-ready.v1' and ready['nonce']==self.value['nonce'] and
                type(ready['pid']) is int and ready['pid']==observed['pid'] and ready['intentSha256']==expected and ready['privateInputsAccepted'] is False)
            self.parent=self._held.enter_context(control.DirectoryLease(command.directory/'artifacts'))
            self.directory=self._held.enter_context(control.DirectoryLease(self.parent.path/name(self.value['nonce'])))
            self.output=self._held.enter_context(control.DirectoryLease(self.directory.path/OUTPUT))
            packet.require(empty.directory_hash(self.directory)==ready['namespaceDirectorySha256'] and
                empty.directory_hash(self.output)==ready['outputDirectorySha256'])
            self.pin=self._held.enter_context(process.PinnedFile(self.directory.path/MARKER,ready['ownerSha256']))
            packet.require(self.pin.digest==packet.digest(bundle.prep.canonical(marker(self.value,observed['pid'],
                ready['namespaceDirectorySha256'],ready['outputDirectorySha256']))))
            self.check()
            session._write_once('publication-namespace.json',dict(schema='fleetory.publication-namespace-bound.v1',
                nonce=self.value['nonce'],intentSha256=expected,ownerSha256=ready['ownerSha256'],actualOwnedProcess=observed,
                namespaceDirectorySha256=ready['namespaceDirectorySha256'],outputDirectorySha256=ready['outputDirectorySha256'],
                privateInputsAccepted=False,actualNativePublicationVerified=False))
        except BaseException:self.close();raise

    def owner_identity(self):
        self.command.check();self.session.check()
        return self.fence.identity(self.child,self.command.executable)

    def check(self):
        packet.require(not self.released);self.owner_identity();self._check_tree()

    def seal(self,data):
        self.check();packet.require(not self._attempted);self._attempted=True
        self.session._write_once('publication-seal-attempt.json',dict(schema='fleetory.publication-seal-attempt.v1',nonce=self.value['nonce']))
        self.published=self._held.enter_context(bundle.HeldProbeBundle(self.output.path,data,self.value['manifestSha256']))
        self.check()
        value=dict(schema='fleetory.publication-namespace-sealed.v1',nonce=self.value['nonce'],ownerSha256=self.ready['ownerSha256'],
            namespaceDirectorySha256=self.ready['namespaceDirectorySha256'],outputDirectorySha256=self.ready['outputDirectorySha256'],
            manifestSha256=self.value['manifestSha256'],bundleSha256=self.published.value['sha256'],files=self.published.value['files'],
            bytes=self.published.value['bytes'],privateInputsAccepted=False,actualNativePublicationVerified=False)
        self.session._write_once('publication-binding.json',dict(schema='fleetory.publication-files-bound.v1',
            nonce=self.value['nonce'],actualOwnedProcess=self.owner_identity(),receipt=value,manifestSha256=self.value['manifestSha256'],
            fileDescriptorsHeld=len(self.published.pins),runtimeDependenciesAuthenticated=False,softwareOriginAuthenticated=False))
        return value

    def acknowledge(self,value):
        self.check();packet.require(not self.acknowledged and self.published is not None)
        expected=json.loads(self.session._records['publication-binding.json'][1])['receipt']
        packet.require(value==expected and type(value['files']) is int and type(value['bytes']) is int and
            value['privateInputsAccepted'] is value['actualNativePublicationVerified'] is False)
        self.session._write_once('publication-owner-ack.json',dict(schema='fleetory.publication-owner-ack.v1',
            nonce=self.value['nonce'],actualOwnedProcess=self.owner_identity(),bindingSha256=packet.digest(self.session._records['publication-binding.json'][1])))
        self.acknowledged=True

    def release(self):
        self.check();packet.require(self.acknowledged)
        self.session._write_once('publication-release.json',dict(schema='fleetory.publication-release.v1',nonce=self.value['nonce'],
            bindingSha256=packet.digest(self.session._records['publication-binding.json'][1]),backendCleanupAuthorized=False))
        pin=packet.digest(self.session._records['publication-release.json'][1]);self.close();self.released=True
        return pin


if __name__=='__main__':raise SystemExit('Public namespace library only; no root, publisher, cleanup, backend or private-input CLI.')
