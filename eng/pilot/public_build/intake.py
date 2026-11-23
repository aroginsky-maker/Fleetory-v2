"""Trusted public-input capture; no native entry point or data grant."""
from contextlib import ExitStack
import datetime as dt
import json
import os
from pathlib import Path
import re
import threading
import time
import weakref

from . import context as policy
from historical import retained_code_lease as code

files, control = code.files, code.control
_LIVE = weakref.WeakKeyDictionary()
LIFETIME = 420
SDK_START_MARGIN = 305
SDK_BYTES = (json.dumps({'sdk': {'version': '10.0.402', 'rollForward': 'disable'}},separators=(',',':'))+'\n').encode()


def require(value):
    if not value:
        raise ValueError('Public input capture refused')


def _pin(value, maximum, fields):
    require(type(value) is dict and value.keys() == fields)
    require(type(value['bytes']) is int and 0 < value['bytes'] <= maximum)
    require(type(value['sha256']) is str and re.fullmatch('[a-f0-9]{64}', value['sha256']))
    return {'bytes':value['bytes'], 'sha256':value['sha256']}


def _plans(sources, packages, crls):
    require(all(type(v) is dict for v in (sources, packages, crls)))
    require(0 < len(sources) <= 768 and 0 < len(packages) <= 64 and 0 < len(crls) <= 32)
    require(set(policy.ROOTS).issubset(sources) and policy.PROJECT in sources)
    sp, pp, cp = {}, {}, {}
    for name, value in sources.items():
        code._name(name)
        sp[name] = _pin(value, 1048576, {'bytes','sha256'})
    require(len({n.casefold() for n in sp}) == len(sp))
    require(sum(p['bytes'] for p in sp.values()) <= 8388608)
    require(sp['global.json'] == {'bytes':len(SDK_BYTES), 'sha256':policy.digest(SDK_BYTES)})
    for name, value in packages.items():
        require(type(name) is str and re.fullmatch(r'[a-z0-9][a-z0-9_.+-]{0,180}\.nupkg', name))
        pin = _pin(value, policy.MAX_CONTEXT, {'path','bytes','sha256'})
        parts = files.relative_parts(value['path'])
        require(len(parts) == 3 and parts[-1] == name and name == parts[0]+'.'+parts[1]+'.nupkg')
        pp[name] = dict(pin, path=value['path'])
    now = dt.datetime.now(dt.timezone.utc)
    for name, value in crls.items():
        require(type(name) is str and re.fullmatch(r'[a-f0-9]{8}\.[a-f0-9]{8}\.crl', name))
        pin = _pin(value, 4194304, {'bytes','sha256','thisUpdate','nextUpdate'})
        for key in ('thisUpdate','nextUpdate'):
            require(type(value[key]) is dt.datetime and value[key].tzinfo is not None)
        require(value['thisUpdate'] <= now and now+dt.timedelta(seconds=LIFETIME) < value['nextUpdate'])
        cp[name] = dict(pin, thisUpdate=value['thisUpdate'], nextUpdate=value['nextUpdate'])
    total = sum(p['bytes'] for group in (sp,pp,cp) for p in group.values())
    require(total <= policy.MAX_CONTEXT-1048576-len(policy.DOCKERFILE)-len(policy.SCRIPT)-len(policy.trust.render()))
    return sp, pp, cp


def _check_time(started_ns, margin_seconds=0):
    elapsed_ns = time.monotonic_ns()-started_ns
    require(0 <= elapsed_ns and elapsed_ns+margin_seconds*1_000_000_000 < LIFETIME*1_000_000_000)


class CapturedPublicInputs:
    __slots__ = ('__weakref__',)

    def _state(self):
        require(type(self) is CapturedPublicInputs and self in _LIVE)
        state = _LIVE[self]
        require(state['pid'] == os.getpid() and state['thread'] == threading.get_ident())
        _check_time(state['startedNs'])
        return state

    def take(self):
        state = self._state()
        require(not state['taken'])
        state['taken'] = True
        return state['archive']

    def check_before_sdk(self):
        state = self._state()
        require(state['taken'] and not state['sdkAttempted'])
        state['sdkAttempted'] = True
        _check_time(state['startedNs'],SDK_START_MARGIN)
        now = dt.datetime.now(dt.timezone.utc)
        require(all(p['thisUpdate'] <= now and now+dt.timedelta(seconds=SDK_START_MARGIN) < p['nextUpdate'] for p in state['crls'].values()))
        state['sdkAdmitted'] = True

    def report(self):
        state = self._state()
        return dict(contextSha256=policy.digest(state['archive']),contextBytes=len(state['archive']),
            taken=state['taken'],sdkAttempted=state['sdkAttempted'],sdkAdmitted=state['sdkAdmitted'],originalLifetimeSeconds=LIFETIME,
            nativeExecutionAuthorized=False,signatureVerificationPerformed=False,originalInputsRead=False,phase7Complete=False)


def capture(trusted_roots, expected_sources, expected_packages, expected_crls):
    started_ns = time.monotonic_ns()
    # Finish schema, path, limits and time checks before any input is opened.
    sp, pp, cp = _plans(expected_sources,expected_packages,expected_crls)
    require(type(trusted_roots) is tuple and len(trusted_roots) == 3)
    roots = tuple(Path(p).absolute() for p in trusted_roots)
    require(len(set(roots)) == 3)
    source, packages, crls = {'global.json':SDK_BYTES}, {}, {}
    with ExitStack() as held:
        source_root, package_root, crl_root = [held.enter_context(control.DirectoryLease(p)) for p in roots]
        for name, pin in sp.items():
            _check_time(started_ns)
            if name == 'global.json':
                continue
            path = source_root.path / name
            with control.DirectoryLease(path.parent) as parent:
                handle = code._HeldCode(parent,code.CodeReference(name,pin['bytes'],pin['sha256']))
                try:
                    os.lseek(handle.fd,0,os.SEEK_SET)
                    with os.fdopen(os.dup(handle.fd),'rb') as stream:
                        data = stream.read(pin['bytes']+1)
                    handle.check();parent.check()
                finally:
                    handle.close()
            policy.pinned(data,pin,1048576);source[name] = data
        for target, root, refs in ((packages,package_root,pp),(crls,crl_root,cp)):
            for name, pin in refs.items():
                _check_time(started_ns)
                digest,size,data = files.inspect_file(root.path,root.fd,pin.get('path',name),pin['bytes'],retain=True)
                require(size == pin['bytes'] and digest == pin['sha256'])
                root.check();target[name] = data
        for root in (source_root,package_root,crl_root):root.check()
    archive = policy.prepare(source,sp,packages,{n:{k:p[k] for k in ('bytes','sha256')} for n,p in pp.items()},crls,cp,dt.datetime.now(dt.timezone.utc))
    _check_time(started_ns)
    value = CapturedPublicInputs()
    _LIVE[value] = dict(pid=os.getpid(),thread=threading.get_ident(),startedNs=started_ns,archive=archive,
                        taken=False,sdkAttempted=False,sdkAdmitted=False,crls=cp)
    return value
