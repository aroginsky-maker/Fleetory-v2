"""Closed public context byte policy; neither file access nor execution authority.

Expected pins and CRL validity windows must come from the trusted worker's live
intake and signature verification. This module does not authenticate that intake.
"""
import datetime
import io
import re
import tarfile

import hashlib
import public_build_trust as trust

SDK = 'mcr.microsoft.com/dotnet/sdk@sha256:8dd1a57fe6b7b8b1b357635db67e272c2f9e9d76d1dd0a32711c4c33c57d7b43'
PROJECT = 'eng/ServerBackendProbe/ServerBackendProbe.csproj'
ROOTS = ('.config/dotnet-tools.json', '.editorconfig', 'Directory.Build.props', 'Directory.Packages.props', 'Directory.Solution.targets', 'Fleetory.sln', 'NuGet.Config', 'global.json')
MAX_CONTEXT = 67108864
MAX_MEMBERS = 1024
DOCKERFILE = b'FROM mcr.microsoft.com/dotnet/sdk@sha256:8dd1a57fe6b7b8b1b357635db67e272c2f9e9d76d1dd0a32711c4c33c57d7b43\nCOPY source/ /payload/source/\nCOPY packages/ /payload/packages/\nCOPY control/ /payload/control/\nUSER 65534:65534\nWORKDIR /work\nENTRYPOINT ["/usr/bin/timeout","--signal=TERM","--kill-after=5s","300s","/bin/sh","/payload/control/build.sh"]\n'

def digest(value):
    return hashlib.sha256(value).hexdigest()


def _source_name(name):
    require(type(name) is str and 0 < len(name) <= 240)
    require(name in ROOTS or re.fullmatch(r'(eng|src|tests/Fleetory\.Tools\.Tests)/[A-Za-z0-9_./-]+', name))
    require(not any(part in ('', '.', '..') for part in name.split('/')))



SCRIPT=b'''#!/bin/sh
set -eu
umask 077
mkdir -p /work/home/.dotnet/corefx/cryptography/crls
cp /payload/control/crls/*.crl /work/home/.dotnet/corefx/cryptography/crls/
test "$#" -eq 0
mkdir -p /work/home /work/artifacts /work/packages /work/output
export HOME=/work/home DOTNET_CLI_HOME=/work/home NUGET_PACKAGES=/work/packages
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_NOLOGO=1 DOTNET_MULTILEVEL_LOOKUP=0
cd /payload/source
dotnet --version
dotnet restore --verbosity diagnostic --disable-build-servers --disable-parallel -p:RestoreBuildInParallel=false -m:1 -nodeReuse:false eng/ServerBackendProbe/ServerBackendProbe.csproj --configfile /payload/control/NuGet.Config --source /payload/packages -p:ArtifactsPath=/work/artifacts
dotnet publish -m:1 -nodeReuse:false -p:UseSharedCompilation=false eng/ServerBackendProbe/ServerBackendProbe.csproj -c Release --no-restore --disable-build-servers -p:UseAppHost=false -p:ArtifactsPath=/work/artifacts -o /work/output
mkfifo /work/release
: > /work/publish.ready
dd if=/work/release of=/dev/null bs=1 count=1 status=none
'''


def require(value):
    if not value:
        raise ValueError('Closed SDK context refused')


def pinned(data, pin, maximum):
    require(type(data) is bytes and 0 < len(data) <= maximum)
    require(type(pin) is dict and pin.keys() == {'bytes', 'sha256'})
    require(type(pin['bytes']) is int and type(pin['sha256']) is str)
    require(re.fullmatch('[a-f0-9]{64}', pin['sha256']) is not None)
    require(len(data) == pin['bytes'] and digest(data) == pin['sha256'])


def prepare(sources, source_pins, packages, package_pins, crls, crl_pins, now):
    require(all(type(v) is dict for v in (sources, source_pins, packages, package_pins, crls, crl_pins)))
    require(sources.keys() == source_pins.keys() and packages.keys() == package_pins.keys() and crls.keys() == crl_pins.keys())
    require(type(now) is datetime.datetime and now.tzinfo is not None)
    require(0 < len(sources) <= 768 and 0 < len(packages) <= 64 and 0 < len(crls) <= 32)
    require(set(ROOTS).issubset(sources) and PROJECT in sources)
    members = {'Dockerfile': DOCKERFILE, 'control/build.sh': SCRIPT, 'control/NuGet.Config': trust.render()}
    for name, data in sources.items():
        _source_name(name)
        pinned(data, source_pins[name], 1048576)
        members['source/' + name] = data
    for name, data in packages.items():
        require(type(name) is str and re.fullmatch(r'[a-z0-9][a-z0-9_.+-]{0,180}\.nupkg', name) is not None)
        pinned(data, package_pins[name], MAX_CONTEXT)
        members['packages/' + name] = data
    for name, data in crls.items():
        require(type(name) is str and re.fullmatch(r'[a-f0-9]{8}\.[a-f0-9]{8}\.crl', name) is not None)
        pin = crl_pins[name]
        require(type(pin) is dict and pin.keys() == {'bytes', 'sha256', 'thisUpdate', 'nextUpdate'})
        pinned(data, {key: pin[key] for key in ('bytes', 'sha256')}, 4194304)
        for key in ('thisUpdate', 'nextUpdate'):
            require(type(pin[key]) is datetime.datetime and pin[key].tzinfo is not None)
        # Require a 420-second margin at admission. The launcher must recheck
        # immediately before SDK start; this policy does not enforce deadlines.
        require(pin['thisUpdate'] <= now and now + datetime.timedelta(seconds=420) < pin['nextUpdate'])
        members['control/crls/' + name] = data
    require(len(members) <= MAX_MEMBERS)
    require(len({name.casefold() for name in members}) == len(members))
    require(sum(map(len, members.values())) <= MAX_CONTEXT - 1048576)
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(members.items()):
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = 0o444
            entry.mtime = 0
            archive.addfile(entry, io.BytesIO(data))
    raw = out.getvalue()
    require(len(raw) <= MAX_CONTEXT)
    return raw


def validate(raw, sources, source_pins, packages, package_pins, crls, crl_pins, now):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_CONTEXT)
    expected = prepare(sources, source_pins, packages, package_pins, crls, crl_pins, now)
    # Exact canonical bytes exclude extra headers, members, links and trailing data.
    require(raw == expected)
    return {'contextBytes': len(raw), 'contextSha256': digest(raw),
            'executionAuthorized': False, 'signatureVerificationPerformed': False,
            'sourceOriginAuthenticated': False, 'originalInputsRead': False}
