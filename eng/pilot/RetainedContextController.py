"""Fixed retained public-source child. Binary context output and close only; no Docker."""
from contextlib import ExitStack
import os
from pathlib import Path
import shutil
import sys
import threading
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_retained_context_transport as transport

packet,publication,C,H=transport.packet,transport.publication,transport.C,transport.H


def _write(data):
    view=memoryview(data)
    while view:
        count=os.write(sys.stdout.fileno(),view[:65536]);packet.require(0<count<=len(view));view=view[count:]


def _close_input(box):
    try:
        raw=bytearray()
        while len(raw)<=transport.MAX_CLOSE:
            data=os.read(sys.stdin.fileno(),1)
            if not data or data==b'\n':break
            raw.extend(data)
        packet.require(data==b'\n' and 0<len(raw)<=transport.MAX_CLOSE and os.read(sys.stdin.fileno(),1)==b'')
        box['raw']=bytes(raw)
    except Exception:box['error']=True
    finally:box['done']=True


def run():
    packet.require(len(sys.argv)==1)
    header=sys.stdin.buffer.readline(transport.MAX_HEADER+1)
    packet.require(header.endswith(b'\n') and len(header)<=transport.MAX_HEADER)
    raw=header[:-1];value,plan,native_plan,manifest=transport._header(raw)
    repository=Path(__file__).resolve().parents[2]
    with ExitStack() as held:
        held.enter_context(transport.process.control.DirectoryLease(repository))
        sources=[held.enter_context(publication.prep._RootInputPin(repository/name,value['sourcePins'][name])) for name in transport.SOURCES]
        python=held.enter_context(transport.process.PinnedFile(Path(sys.executable),value['runtimes']['python'],True))
        parent=held.enter_context(transport.guard.identity.HeldLocalPeer('parent',python,value['parent']))
        own=held.enter_context(transport.guard.identity.HeldLocalPeer('self',python,value['controller']))
        runtimes={}
        roles=(('powershell','pwsh'),('git','git'),('dotnet','dotnet'))
        if value['schema']==transport.GUARDIAN_HEADER:roles+= (('docker','docker'),)
        for role,name in roles:
            path=Path(shutil.which(name) or '').resolve(strict=True)
            runtimes[role]=held.enter_context(transport.process.PinnedFile(path,value['runtimes'][role],True))
        root=repository/'artifacts'/('retained-context-controller-'+plan['nonce']);root.mkdir(mode=0o700,exist_ok=False)
        control=dict(schema=transport.process.control.SCHEMA,purpose=transport.process.control.PURPOSE,nonce=plan['nonce'],
            revision=plan['revision'],nativePlanSha256=H(native_plan),codeSha256=plan['codeSha256'],probeSha256=plan['probeSha256'],
            runtimes={name:value['runtimes'][name] for name in ('python','powershell')})
        control_raw=C(control)
        session=held.enter_context(transport.process.control.claim(root,control_raw,H(control_raw)))
        selected={name:value['sourcePins'][name] for name in publication.SOURCES}
        with publication.retain_owner(repository,runtimes['powershell'].path,python.path,runtimes['git'].path,runtimes['dotnet'].path,
                native_plan,selected,session,git_sha256=runtimes['git'].digest,dotnet_sha256=runtimes['dotnet'].digest,manifest=manifest) as retained:
            packet.require(parent.snapshot()['state']==own.snapshot()['state']=='live')
            descriptors={name:pin.fd for name,pin in retained._bundle.pins.items()}
            image=retained.image(value['bases']);context=image.build_bytes();report=retained.report()
            packet.require(descriptors=={name:pin.fd for name,pin in retained._bundle.pins.items()})
            offer=dict(schema=transport.SCHEMA,headerSha256=H(raw),controller=value['controller'],nonce=plan['nonce'],
                reservationSha256=session.report()['reservationSha256'],imageIntentBase64=transport.encode(C(image.intent)),
                contextBytes=len(context),contextSha256=H(context),publicationDescriptorsHeld=len(descriptors),
                heldDescriptorsSha256=report['heldDescriptorsSha256'],publicationBindingSha256=report['bindingSha256'],
                nativeOwnerExited=report['nativeOwnerExited'],nativeOwnedMembersAbsent=retained.native_result['fence']['noRunningMembersVerified'],
                retainedOpenedNs=retained.opened,retainedExpiresNs=retained.expires)
            _write(transport.frame(offer,transport.MAX_OFFER));_write(context)
            if value['schema']==transport.GUARDIAN_HEADER:
                import audit_retained_guard_protocol as guardian
                guardian.serve(retained,image,parent,session,repository,runtimes,root,raw,offer,descriptors,_write)
            else:
                box={'done':False};threading.Thread(target=_close_input,args=(box,),daemon=True).start()
                while not box['done']:
                    retained.check();packet.require(parent.snapshot()['state']=='live');time.sleep(0.05)
                packet.require(not box.get('error') and packet.strict_json(box['raw'],transport.MAX_CLOSE)==transport.close_request(plan['nonce'],H(context)))
                retained.check();packet.require(descriptors=={name:pin.fd for name,pin in retained._bundle.pins.items()})
        for fd in descriptors.values():
            try:os.fstat(fd)
            except OSError:pass
            else:raise ValueError('Public descriptor survived source closure.')
        for source in sources:source.check()
        closed=dict(schema='fleetory.retained-context-closed.v1',nonce=plan['nonce'],contextSha256=H(context),
            sourceDescriptorsClosed=len(descriptors),originalInputsRead=False,dockerOperationsPerformed=0)
        _write(transport.frame(closed,transport.MAX_CLOSE))


if __name__=='__main__':
    try:run()
    except Exception:
        print('Owned retained context controller refused; no paths, values or credentials logged.',file=sys.stderr);raise SystemExit(1)
