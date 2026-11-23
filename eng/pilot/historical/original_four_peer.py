"""Fixed original-four private channel. Binding integrity is not user/native authority."""
import argparse
import base64
import os
from pathlib import Path
import sys

from historical import retained_service_peer as peer
from historical import original_four_use as policy

C,H,packet=policy.C,policy.H,policy.packet
BINDING='fleetory.original-four-peer-binding.v1'
MAX_BINDING=32768
EXPECTED_KEYS='root artifacts revision imageId probeSha256 configurationSha256 executionInventorySha256 policySha256'


def expected(value):
    packet.keys(value,EXPECTED_KEYS)
    packet.keys(value['artifacts'],' '.join(sorted(policy.KINDS)))
    artifacts=[]
    for kind,ref in sorted(value['artifacts'].items()):
        packet.keys(ref,'path bytes sha256')
        artifacts.append((kind,ref['path'],ref['bytes'],ref['sha256']))
    result=policy.ExpectedOriginalFour(value['root'],tuple(artifacts),value['revision'],value['imageId'],
        value['probeSha256'],value['configurationSha256'],value['executionInventorySha256'],value['policySha256'])
    policy._expected(result)
    packet.require(result.policy_sha256==H(Path(policy.__file__).read_bytes()))
    return result


def prepare(raw):
    value=packet.strict_json(raw,peer.MAX_CONTROL);packet.keys(value,'request expected')
    wanted=expected(value['expected'])
    prepared=peer.prepare(C(value['request']))
    header=packet.strict_json(packet.decode(prepared['header'],peer.MAX_CONTROL),peer.MAX_CONTROL)
    service=packet.strict_json(packet.decode(header['plan'],policy.legacy.MAX_PLAN),policy.legacy.MAX_PLAN)
    packet.require(wanted.root==service['root']==str(Path.cwd().resolve(strict=True)))
    packet.require(wanted.revision==service['revision'] and wanted.image_id==service['imageId']
                   and wanted.probe_sha256==service['probeSha256']
                   and wanted.configuration_sha256==service['configurationSha256'])
    plan=C(dict(schema=policy.SCHEMA,purpose=policy.PURPOSE,nonce=service['nonce'],root=wanted.root,
        artifacts=policy._expected(wanted),servicePlanSha256=header['planSha256'],
        executionInventorySha256=wanted.execution_inventory_sha256,
        consumerIdentitySha256=H(C(header['parent']))))
    binding=C(dict(schema=BINDING,expected=value['expected'],plan=base64.b64encode(plan).decode('ascii'),
        planSha256=H(plan),sourceCodePlanSha256=header['codePlanSha256']))
    packet.require(len(binding)<=MAX_BINDING)
    return dict(prepared,binding=base64.b64encode(binding).decode('ascii'),bindingSha256=H(binding),
                originalPlanSha256=H(plan))


def run(header_pin,binding_pin):
    frozen=peer._receive();packet.require(H(frozen)==packet.hex_value(binding_pin))
    binding=packet.strict_json(frozen,MAX_BINDING)
    packet.keys(binding,'schema expected plan planSha256 sourceCodePlanSha256')
    packet.require(binding['schema']==BINDING)
    wanted=expected(binding['expected'])
    original=packet.decode(binding['plan'],policy.MAX_PLAN)
    packet.require(H(original)==packet.hex_value(binding['planSha256']))
    raw=peer._receive();packet.require(H(raw)==packet.hex_value(header_pin))
    def bind(parent,service,service_pin,metadata,source_check,code_pin,operator):
        packet.require(code_pin==packet.hex_value(binding['sourceCodePlanSha256']))
        def inventory_check():
            source_check()
            return True
        def factory(consume):
            return policy.use(operator,peer.REPO,wanted,parent,inventory_check,
                original,binding['planSha256'],service,service_pin,metadata,consume)
        return factory,binding['planSha256']
    peer._serve_header(raw,bind)


def main():
    parser=argparse.ArgumentParser(allow_abbrev=False)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare',action='store_true');group.add_argument('--header-sha256')
    parser.add_argument('--binding-sha256')
    args=parser.parse_args()
    try:
        packet.require((args.prepare and args.binding_sha256 is None)
                       or (not args.prepare and args.binding_sha256 is not None))
        if args.prepare:
            raw=sys.stdin.buffer.read(peer.MAX_CONTROL+1)
            print(C(prepare(raw)).decode('utf-8'))
        else:
            run(args.header_sha256,args.binding_sha256)
    except Exception:
        os.write(2,b'Original four peer refused; no input contents logged.\n')
        sys.exit(1)


if __name__=='__main__':main()
