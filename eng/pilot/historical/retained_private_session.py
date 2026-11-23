"""Fixed private four-packet exchange. Factories/checks come only from trusted host code."""
import os
from historical import retained_service_use as use

packet,C,H=use.packet,use.C,use.H


def serve(reader,send,source_check,factory,parent,nonce,plan_sha,header_sha,code_sha,code_files,mode):
    packet.require(type(parent) is use.identity.HeldLocalPeer and parent.role=='parent')
    packet.require(all(callable(v) for v in (send,source_check,factory)))
    packet.require(mode in ('normal','exit-after-release','exit-on-request','expire-after-restore'))
    current=None;count=0

    def check():
        source_check()
        packet.require(parent.snapshot()['state']=='live')
        if current is not None:current.report()

    def consume(payload):
        nonlocal count
        check()
        send(C(dict(kind='payload',nonce=nonce,planSha256=plan_sha,payloadSha256=H(payload),
                    payloadBytes=len(payload),consumer=parent.snapshot()['identity'])))
        send(payload)
        if mode=='exit-after-release':os._exit(37)
        while True:
            message=packet.strict_json(reader.next(check),184320)
            packet.require(message.get('nonce')==nonce)
            if mode=='exit-on-request' and message.get('kind')=='generated-fault-exit':
                packet.keys(message,'kind nonce payloadSha256')
                packet.require(message['payloadSha256']==H(payload));os._exit(37)
            if message.get('kind')=='status':
                packet.keys(message,'kind nonce sequence payloadSha256');count+=1
                packet.require(count<=256 and type(message['sequence']) is int and message['sequence']==count
                               and message['payloadSha256']==H(payload))
                send(C(dict(kind='live',nonce=nonce,sequence=count,payloadSha256=H(payload))))
            else:
                packet.keys(message,'kind nonce resultSha256')
                packet.require(message['kind']=='result')
                result=reader.next(check);packet.require(H(result)==packet.hex_value(message['resultSha256']))
                return result

    with factory(consume) as current:
        check()
        send(C(dict(kind='bound',nonce=nonce,headerSha256=header_sha,planSha256=plan_sha,
                    consumer=parent.snapshot()['identity'],owner=current.report()['heldProcessIdentity'],
                    codePlanSha256=code_sha,codeFiles=code_files)))
        start=packet.strict_json(reader.next(check),512);packet.keys(start,'kind nonce')
        packet.require(start==dict(kind='capture',nonce=nonce))
        current.capture();result=current.dispatch()
        send(C(dict(kind='receipt',nonce=nonce,resultSha256=H(result),planSha256=plan_sha,statusChecks=count,
                    actualParentIdentityBound=True,nativeResultAuthenticated=False,executionAuthorized=False,
                    phase7Complete=False,codePlanSha256=code_sha,codeFiles=code_files)))
        stop=packet.strict_json(reader.next(check),512)
        packet.require(stop==dict(kind='close',nonce=nonce))
    send(C(dict(kind='closed',nonce=nonce,phase7Complete=False)))


if __name__=='__main__':raise SystemExit('Private exchange library; no root, permission or native command CLI.')
