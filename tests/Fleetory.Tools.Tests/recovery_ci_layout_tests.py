"""Keep every native recovery gate when independent fixture jobs are rearranged."""
from pathlib import Path
from collections import Counter
import json
import os
import re
import shutil
import subprocess
import unittest
from unittest.mock import patch

WORKFLOW = Path(__file__).resolve().parents[2] / '.github/workflows/quality.yml'
DATA = (
    ('NativeServerBackend.Tests.ps1', ''), ('NativePgDataRoundtrip.Tests.ps1', ''),
    ('NativePgInventoryV2.Tests.ps1', ''), ('NativeImmuDataRoundtrip.Tests.ps1', ''),
    ('NativeAuditHistory.Tests.ps1', ''), ('NativeAuditHistory.Tests.ps1', '-Profile observation'),
    ('NativeAuditHistory.Tests.ps1', '-Profile historical-observation'),
    ('NativeAuditHistory.Tests.ps1', '-Profile historical-controller'))
PROVIDER = (
    ('PilotProvisioning.Tests.ps1', ''), ('IdentityBackup.Tests.ps1', ''),
    ('OpenBaoRaftRecovery.Tests.ps1', ''), ('NativeSignerBackend.Tests.ps1', ''),
    ('NativeJournalBackend.Tests.ps1', ''), ('NativeServerPair.Tests.ps1', ''),
    ('NativeServerPair.Tests.ps1', '-Profile v2'), ('NativeServerPair.Tests.ps1', '-Profile v2-retained'),
    ('NativeRetainedNamespace.Tests.ps1', ''))
RETAINED = (
    ('NativeServerPair.Tests.ps1', '-Profile v2-retained-server'),
    ('NativeServerPair.Tests.ps1', '-Profile v2-retained-historical-server'),
    ('NativeServerPair.Tests.ps1', '-Profile v2-retained-inflight'),
    ('NativeServerPair.Tests.ps1', '-Profile v2-retained-restore-inflight'),
    ('NativeServerPair.Tests.ps1', '-Profile v2-retained-service-use'),
    ('NativeServerPair.Tests.ps1', '-Profile v2-retained-service-use-loss'))
ORIGINAL = tuple(('NativeServerPair.Tests.ps1','-Profile '+profile+' -OriginalPurpose') for profile in ('v2-retained-service-use','v2-retained-service-use-loss','v2-retained-service-use-expiry')) + (('NativeServerPair.Tests.ps1','-Profile v2-retained-service-use-expiry'),)

PUBLICATION_IMAGE_PROGRAM = "import subprocess,sys;sys.path.insert(0,'eng/pilot');import recovery_isolation;subprocess.run(['docker','pull',recovery_isolation.IMAGE],check=True,timeout=120)"
PUBLICATION_IMAGE_PREP = '      - name: Prepare pinned public publication base\n        shell: pwsh\n        run: |\n          python3 -B -c "import subprocess,sys;sys.path.insert(0,\'eng/pilot\');import recovery_isolation;subprocess.run([\'docker\',\'pull\',recovery_isolation.IMAGE],check=True,timeout=120)"\n          if ($LASTEXITCODE -ne 0) { throw \'Pinned public publication base preparation failed.\' }\n\n'


def controller_fault_step(case):
    label = {'eof':'EOF','death':'death','sql-death':'active SQL'}[case]
    return (f'      - name: Verify generated external controller {label} cleanup\n'
            '        shell: pwsh\n        run: |\n'
            '          python3 -B ./tests/Fleetory.Tools.Tests/native_controller_loss.py '
            f'--powershell (Get-Command pwsh).Source --case {case}\n'
            f"          if ($LASTEXITCODE -ne 0) {{ throw 'Generated external controller {label} cleanup failed.' }}\n")


PAIR_ADMISSION = (
    '      - name: Verify coherent native Server pair restore and lifecycle\n'
    '        shell: pwsh\n'
    '        run: |\n'
    '          python3 -B ./tests/Fleetory.Tools.Tests/fresh_server_pair_tests.py\n'
    "          if ($LASTEXITCODE -ne 0) { throw 'Fresh pair admission contract failed.' }\n"
    '          dotnet restore ./eng/ServerBackendProbe/ServerBackendProbe.csproj --disable-parallel\n'
    "          if ($LASTEXITCODE -ne 0) { throw 'Server backend probe restore failed.' }\n"
    '          ./tests/Fleetory.Tools.Tests/NativeServerPair.Tests.ps1 -Python (Get-Command python3).Source\n')


WINDOWS_POLICY = (
    ('Verify signed artifact anti-rollback on Windows', 'pwsh', ('./tests/Fleetory.Tools.Tests/SignedArtifactVerification.Tests.ps1', './tests/Fleetory.Tools.Tests/SignedArtifactConcurrency.Tests.ps1')),
    ('Verify signer evidence snapshot on Windows', 'pwsh', ('./tests/Fleetory.Tools.Tests/SigningJournalSnapshot.Tests.ps1', './tests/Fleetory.Tools.Tests/SigningJournalCheckpoint.Tests.ps1')),
    ('Verify dependency audit gate on Windows', 'pwsh', ('./tests/Fleetory.Tools.Tests/DependencyAudit.Tests.ps1',)),
    ('Verify quality command orchestration', 'pwsh', ('./tests/Fleetory.Tools.Tests/QualityOrchestration.Tests.ps1',)),
    ('Verify exact readiness response on Windows', 'pwsh', ('./tests/Fleetory.Tools.Tests/ReadinessResponse.Tests.ps1',)),
    ('Verify independent production audit expectations on Windows', 'pwsh', ('./tests/Fleetory.Tools.Tests/AuditEventExpectations.Tests.ps1 -Python (Get-Command python).Source',)),
    ('Verify Sonar issue gate on Windows', 'pwsh', ('./tests/Fleetory.Tools.Tests/SonarIssueGate.Tests.ps1',)),
    ('Verify immudb TLS probe on Windows PowerShell 5.1', 'powershell', ('./tests/Fleetory.Tools.Tests/ImmudbTlsProbe.Tests.ps1',)),
    ('Verify PHASE 7 readiness on Windows PowerShell 5.1', 'powershell', ('./tests/Fleetory.Tools.Tests/Phase7Readiness.Tests.ps1',)),
    ('Verify immudb authenticated TLS transport on Windows PowerShell 5.1', 'powershell', ('./tests/Fleetory.Tools.Tests/ImmudbHttpTransport.Tests.ps1',)),
    ('Verify receipt export and anchor binding on Windows PowerShell 5.1', 'powershell', ('./tests/Fleetory.Tools.Tests/ImmudbReceiptExport.Tests.ps1', './tests/Fleetory.Tools.Tests/ImmudbReceiptExportVerification.Tests.ps1')),
    ('Verify receipt checkpoint rollback guard on Windows PowerShell 5.1', 'powershell', ('./tests/Fleetory.Tools.Tests/ImmudbReceiptCheckpoint.Tests.ps1',)),
    ('Verify restore point and deferred anchor on Windows PowerShell 5.1', 'powershell', ('./tests/Fleetory.Tools.Tests/ImmudbStateVerification.Tests.ps1', './tests/Fleetory.Tools.Tests/ImmudbRestoreCheckpoint.Tests.ps1')),
)


def windows_step(item):
    title, shell, commands = item
    start = "      - name: " + title + "\n        shell: " + shell + "\n        run: "
    return start + (commands[0] + "\n\n" if len(commands) == 1 else "|\n" + "".join("          " + c + "\n" for c in commands) + "\n")



def jobs(text):
    text = text.split('jobs:\n', 1)[1]
    matches = list(re.finditer(r'^  ([a-z][a-z-]+):\s*$', text, re.MULTILINE))
    return {m[1]: text[m.start():matches[i + 1].start() if i + 1 < len(matches) else len(text)] for i, m in enumerate(matches)}


def validate(text):
    blocks = jobs(text)
    assert set(blocks) == {'windows-tls-chain', 'windows-policy', 'quality', 'native-data-recovery', 'native-provider-recovery', 'native-retained-recovery', 'native-original-recovery', 'native-publication-faults', 'quality-gate'}
    policy = blocks['windows-policy']
    assert '    runs-on: windows-latest\n' in policy and '    timeout-minutes: 10\n' in policy
    assert '    permissions:\n      contents: read\n' in policy
    assert not re.search(r'^\s*(if:|needs:|continue-on-error:|env:)', policy, re.MULTILINE)
    for action in ('actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803', 'actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68'):
        assert action in policy
    assert 'Copy-Item -LiteralPath eng/global.ci.json -Destination global.json' in policy
    assert '        run: dotnet build src/Fleetory.Server/Fleetory.Server.csproj -c Release\n' in policy
    for item in WINDOWS_POLICY:
        step = windows_step(item)
        assert policy.count(step) == 1
        start = policy.index(step)
        end = policy.find('      - name:', start + len(step))
        assert policy[start:end if end >= 0 else len(policy)].strip() == step.strip()
        for command in item[2]:
            assert command not in blocks['windows-tls-chain']
    policy_commands = re.findall(r'^\s*(?:run: )?(\./tests/Fleetory.Tools.Tests/[^\n]+)', policy, re.MULTILINE)
    assert Counter(policy_commands) == Counter(c for item in WINDOWS_POLICY for c in item[2])
    expected = Counter(name for name, _ in DATA + PROVIDER + RETAINED + ORIGINAL)
    found = Counter(re.findall(r'\./tests/Fleetory.Tools.Tests/([A-Za-z0-9]+\.Tests\.ps1)', text))
    assert all(found[name] == count for name, count in expected.items())
    for key, cases, minutes in (('native-data-recovery', DATA, 20), ('native-provider-recovery', PROVIDER, 15), ('native-retained-recovery', RETAINED, 15), ('native-original-recovery', ORIGINAL, 15)):
        block = blocks[key]
        assert '    runs-on: ubuntu-24.04\n' in block and f'    timeout-minutes: {minutes}\n' in block
        assert not re.search(r'^\s*(if:|needs:|continue-on-error:|SONAR_|env:)', block, re.MULTILINE)
        for action in ('actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803', 'actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68'):
            assert action in block
        assert 'Copy-Item -LiteralPath eng/global.ci.json -Destination global.json' in block
        assert 'dotnet tool restore\n' in block
        assert 'dotnet restore Fleetory.sln --force -warnaserror -p:FleetoryRequireDependencyAudit=true -p:NuGetAudit=true -p:NuGetAuditMode=all -p:NuGetAuditLevel=low -p:RestoreUseStaticGraphEvaluation=false\n' in block
        assert 'dotnet build Fleetory.sln -c Release --no-restore --disable-build-servers --warnaserror\n' in block
        bootstrap = block.split('      - name: Verify ', 1)[0]
        assert bootstrap.count('if ($LASTEXITCODE -ne 0)') == (4 if key in ('native-retained-recovery','native-original-recovery','native-publication-faults') else 3)
        commands = re.findall(r'^\s*(?:run: )?(\./tests/Fleetory.Tools.Tests/[^\n]+)', block, re.MULTILINE)
        for name, profile in cases:
            prefix = './tests/Fleetory.Tools.Tests/' + name + (' ' + profile if profile else '')
            matches = [line for line in commands if line == prefix or line.startswith(prefix + ' -Python ')]
            assert len(matches) == 1, (key, name, profile)
        assert len(commands) == len(cases)
    for case in ('eof','death','sql-death'):
        step=controller_fault_step(case)
        block=blocks['native-original-recovery']
        assert block.count(step)==1
        start=block.index(step)
        end=block.find('      - name:',start+len(step))
        assert block[start:end if end>=0 else len(block)].strip()==step.strip()
        assert text.count('native_controller_loss.py --powershell (Get-Command pwsh).Source --case '+case)==1
    publication=blocks['native-publication-faults']
    assert '    runs-on: ubuntu-24.04\n' in publication and '    timeout-minutes: 15\n' in publication
    assert '    permissions:\n      contents: read\n' in publication
    assert not re.search(r'^\s*(if:|needs:|continue-on-error:|env:|SONAR_)',publication,re.MULTILINE)
    for marker in ('actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803',
                   'actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68',
                   'global-json-file: eng/global.ci.json',
                   'Copy-Item -LiteralPath eng/global.ci.json -Destination global.json',
                   'dotnet tool restore\n',
                   'dotnet restore Fleetory.sln --force -warnaserror -p:FleetoryRequireDependencyAudit=true -p:NuGetAudit=true -p:NuGetAuditMode=all -p:NuGetAuditLevel=low -p:RestoreUseStaticGraphEvaluation=false\n',
                   'dotnet build Fleetory.sln -c Release --no-restore --disable-build-servers --warnaserror\n'):
        assert publication.count(marker)==1
    assert publication.count('if ($LASTEXITCODE -ne 0)')==4
    assert publication.count(PUBLICATION_IMAGE_PREP)==1
    assert publication.index(PUBLICATION_IMAGE_PREP)<publication.index('      - name: Verify actual native publication faults\n')
    retained = blocks['native-retained-recovery']
    probe_step = ('      - name: Prepare retained Server backend probe\n'
        '        shell: pwsh\n'
        '        run: |\n'
        '          dotnet restore ./eng/ServerBackendProbe/ServerBackendProbe.csproj --disable-parallel\n'
        "          if ($LASTEXITCODE -ne 0) { throw 'Retained Server backend probe restore failed.' }\n")
    assert retained.count(probe_step) == 1
    start = retained.index(probe_step)
    end = retained.find('      - name:', start + len(probe_step))
    assert retained[start:end if end >= 0 else len(retained)].strip() == probe_step.strip()
    provider = blocks['native-provider-recovery']
    assert provider.count(PAIR_ADMISSION) == 1
    start = provider.index(PAIR_ADMISSION)
    end = provider.find('      - name:', start + len(PAIR_ADMISSION))
    assert provider[start:end if end >= 0 else len(provider)].strip() == PAIR_ADMISSION.strip()
    assert provider.count('dotnet restore ./eng/ServerBackendProbe/ServerBackendProbe.csproj') == 1
    assert text.count('python3 -B ./tests/Fleetory.Tools.Tests/fresh_server_pair_tests.py') == 1
    for key, platform in (('windows-tls-chain', ' on Windows'), ('quality', '')):
        step = ('      - name: Verify public SDK lifecycle policies' + platform + '\n'
                '        shell: pwsh\n'
                '        run: |\n')
        for filename in ('PublicBuildImageTransaction', 'PublicBuildSdkTransaction',
                         'PublicBuildSdkClient', 'PublicBuildNativeEnvironment'):
            step += ('          ./tests/Fleetory.Tools.Tests/' + filename + '.Tests.ps1\n'
                     "          if ($LASTEXITCODE -ne 0) { throw 'Public SDK lifecycle policy failed.' }\n")
        block = blocks[key]
        assert block.count(step) == 1
        start = block.index(step)
        end = block.find('      - name:', start + len(step))
        assert block[start:end if end >= 0 else len(block)].strip() == step.strip()
    for key, platform in (('windows-tls-chain', ' on Windows'), ('quality', '')):
        step = ('      - name: Verify generated data host callback boundary' + platform + '\n'
                '        shell: pwsh\n'
                '        run: ./tests/Fleetory.Tools.Tests/RetainedDataHostBoundary.Tests.ps1\n')
        assert blocks[key].count(step) == 1
        assert text.count('./tests/Fleetory.Tools.Tests/RetainedDataHostBoundary.Tests.ps1') == 2
    for key, platform in (('windows-tls-chain', ' on Windows'), ('quality', '')):
        step=('      - name: Verify original data host binding refusals'+platform+'\n'
              '        shell: pwsh\n        run: ./tests/Fleetory.Tools.Tests/OriginalFourDataHostBinding.Tests.ps1\n')
        assert blocks[key].count(step)==1
        assert text.count('./tests/Fleetory.Tools.Tests/OriginalFourDataHostBinding.Tests.ps1')==2
    for key, platform in (('windows-tls-chain', ' on Windows'), ('quality', '')):
        for title,filename in (('bounded public build source transport','PublicBuildSourceTransport.Tests.ps1'),
                ('live public build source transaction','PublicBuildSourceTransaction.Tests.ps1')):
            command = './tests/Fleetory.Tools.Tests/' + filename
            step = ('      - name: Verify ' + title + platform + '\n'
                    '        shell: pwsh\n'
                    '        run: ' + command + '\n')
            assert blocks[key].count(step) == 1
            assert text.count(command) == 2
    for key, platform, executable in (('windows-tls-chain', ' on Windows', 'python'), ('quality', '', 'python3')):
        command=executable+' -B ./tests/Fleetory.Tools.Tests/run_original_four_peer_prototype.py (Get-Command pwsh).Source'
        step=('      - name: Verify actual original four-input private channel'+platform+'\n'
              '        shell: pwsh\n        run: '+command+'\n')
        assert blocks[key].count(step)==1
        assert text.count(command)==1
    for key, platform, executable in (('windows-tls-chain', ' on Windows', 'python'), ('quality', '', 'python3')):
        for title, filename in (('held audit control namespace identity', 'audit_control_identity_tests.py'),
                ('four frozen retained service inputs', 'retained_service_inputs_tests.py'),
                ('private frozen service payload', 'retained_service_payload_tests.py'),
                ('live retained service use', 'retained_service_use_tests.py'),
                ('distinct original four-input purpose', 'original_four_use_tests.py'),
                ('fixed retained private exchange', 'retained_private_session_tests.py'),
                ('separate original four-input peer', 'original_four_peer_tests.py'),
                ('original inventory metadata mapping', 'retained_expected_inventory_tests.py'),
                ('held retained source handles', 'retained_code_lease_tests.py'),
                ('fixed retained source catalog', 'retained_code_catalog_tests.py'),
                ('live public build input capture', 'public_build_intake_tests.py'),
                ('private public build source peer', 'public_build_source_peer_tests.py'),
                ('closed public SDK context', 'public_build_context_tests.py'),
                ('separate public build create policy', 'build_runtime_create_profile_tests.py'),
                ('retained source-only entry points', 'retained_source_bootstrap_tests.py'),
                ('isolated retained Python bootstrap', 'retained_python_isolation_tests.py'),
                ('owned process identity and lifetime fence', 'audit_process_fence_tests.py'),
                ('pinned payload reservation and controller binding', 'audit_payload_launch_tests.py'),
                ('consumed generated container binding', 'audit_backend_binding_tests.py'),
                ('consumed untagged image binding', 'audit_image_binding_tests.py'),
                ('close-only native preparation contracts', 'audit_native_preparation_tests.py'),
                ('actual historical owner readiness', 'native_audit_preparation.py'),
                ('native empty payload contracts', 'audit_native_payload_tests.py'),
                ('actual native empty payload handoff', 'native_empty_payload.py'),
                ('linked image and container contracts', 'audit_linked_binding_tests.py'),
                ('native resource receipt contracts', 'audit_native_resource_tests.py'),
                ('actual native resource acknowledgement', 'native_resource_ack.py'),
                ('fixed probe image build contracts', 'audit_probe_image_tests.py'),
                ('fixed probe runtime contracts', 'audit_probe_runtime_tests.py'),
                ('native probe receipt contracts', 'audit_native_probe_tests.py'),
                ('native probe create contracts', 'audit_native_create_tests.py'),
                ('typed publication namespace contracts', 'publication_namespace_tests.py'),
                ('fenced publication namespace handoff', 'native_publication_namespace.py'),
                ('fixed native publication contracts', 'native_publication_tests.py'),
                ('actual native public publisher', 'native_publication.py'),
                ('native publication fault contracts', 'publication_faults_tests.py'),
                ('held publication continuation contracts', 'publication_continuation_tests.py'),
                ('retained publication runtime contracts', 'retained_runtime_tests.py'),
                ('retained guardian preparation contracts', 'retained_guard_preparation_tests.py'),
                ('retained public context transport contracts', 'retained_context_transport_tests.py'),
                ('retained own cleanup contracts', 'retained_cleanup_guard_tests.py'),
                ('public cleanup protocol contracts', 'cleanup_protocol_tests.py'),
                ('read-only supervisor identity contracts', 'supervisor_identity_tests.py'),
                ('actual read-only supervisor handoff', 'native_supervisor_observation.py'),
                ('consumed public cleanup attempts', 'cleanup_attempt_tests.py'),
                ('independent public cleanup contracts', 'public_cleanup_guard_tests.py'),
                ('actual native publication faults', 'native_publication_faults.py'),
                ('native create fault contracts', 'native_create_faults_tests.py'),
                ('public probe owner fault contracts', 'public_probe_faults_tests.py'),
                ('actual native probe receipt acknowledgement', 'native_probe_receipt_ack.py')):
            suffix = (' --continuation-image --owned-cleanup' if key=='quality' else ' --continuation') if filename=='native_publication_faults.py' else ''
            step = ('      - name: Verify ' + title + platform + '\n'
                '        shell: pwsh\n'
                '        run: ' + executable + ' -B ./tests/Fleetory.Tools.Tests/' + filename + suffix + '\n')
            block = blocks['native-publication-faults'] if key=='quality' and filename=='native_publication_faults.py' else blocks[key]
            assert block.count(step) == 1
            start = block.index(step)
            end = block.find('      - name:', start + len(step))
            assert block[start:end if end >= 0 else len(block)].strip() == step.strip()
        step = ('      - name: Verify historical application input snapshots' + platform + '\n'
            '        shell: pwsh\n'
            '        run: ./tests/Fleetory.Tools.Tests/HistoricalAuditInputPins.Tests.ps1\n')
        block = blocks[key]
        assert block.count(step) == 1
        start = block.index(step)
        end = block.find('      - name:', start + len(step))
        assert block[start:end if end >= 0 else len(block)].strip() == step.strip()
    guard_step = ('      - name: Verify actual independent public cleanup\n'
        '        shell: pwsh\n'
        '        run: python3 -B ./tests/Fleetory.Tools.Tests/native_public_cleanup_guard.py\n')
    block = blocks['quality']
    assert block.count(guard_step) == 1
    start = block.index(guard_step)
    end = block.find('      - name:', start + len(guard_step))
    assert block[start:end if end >= 0 else len(block)].strip() == guard_step.strip()
    native_step = ('      - name: Verify actual generated Docker control binding\n'
        '        shell: pwsh\n'
        '        run: python3 -B ./tests/Fleetory.Tools.Tests/native_audit_resource_binding.py\n')
    block = blocks['quality']
    assert block.count(native_step) == 1
    start = block.index(native_step)
    end = block.find('      - name:', start + len(native_step))
    assert block[start:end if end >= 0 else len(block)].strip() == native_step.strip()
    image_step = ('      - name: Verify actual untagged Docker image binding\n'
        '        shell: pwsh\n'
        '        run: python3 -B ./tests/Fleetory.Tools.Tests/native_audit_image_binding.py\n')
    assert block.count(image_step) == 1
    start = block.index(image_step)
    end = block.find('      - name:', start + len(image_step))
    assert block[start:end if end >= 0 else len(block)].strip() == image_step.strip()
    pair_step = ('      - name: Verify actual linked image and container pair\n'
        '        shell: pwsh\n'
        '        run: python3 -B ./tests/Fleetory.Tools.Tests/native_audit_linked_pair.py\n')
    assert block.count(pair_step) == 1
    start = block.index(pair_step)
    end = block.find('      - name:', start + len(pair_step))
    assert block[start:end if end >= 0 else len(block)].strip() == pair_step.strip()
    ack_step = ('      - name: Verify actual Docker receipts acknowledged by native owner\n'
        '        shell: pwsh\n'
        '        run: python3 -B ./tests/Fleetory.Tools.Tests/native_resource_docker_ack.py\n')
    assert block.count(ack_step) == 1
    start = block.index(ack_step)
    end = block.find('      - name:', start + len(ack_step))
    assert block[start:end if end >= 0 else len(block)].strip() == ack_step.strip()
    probe_step = ('      - name: Verify actual public probe image build and readback\n'
        '        shell: pwsh\n'
        '        run: python3 -B ./tests/Fleetory.Tools.Tests/native_probe_image.py\n')
    assert block.count(probe_step) == 1
    start = block.index(probe_step)
    end = block.find('      - name:', start + len(probe_step))
    assert block[start:end if end >= 0 else len(block)].strip() == probe_step.strip()
    runtime_step = ('      - name: Verify actual probe runtime and kernel constraints\n'
        '        shell: pwsh\n'
        '        run: python3 -B ./tests/Fleetory.Tools.Tests/native_probe_runtime.py\n')
    assert block.count(runtime_step) == 1
    start = block.index(runtime_step)
    end = block.find('      - name:', start + len(runtime_step))
    assert block[start:end if end >= 0 else len(block)].strip() == runtime_step.strip()
    native_probe_step = ('      - name: Verify actual public probe native receipt handoff\n'
        '        shell: pwsh\n'
        '        run: python3 -B ./tests/Fleetory.Tools.Tests/native_public_probe_receipt.py\n')
    assert block.count(native_probe_step) == 1
    start = block.index(native_probe_step)
    end = block.find('      - name:', start + len(native_probe_step))
    assert block[start:end if end >= 0 else len(block)].strip() == native_probe_step.strip()
    publication_step = ('      - name: Verify real public publication namespace\n'
        '        shell: pwsh\n'
        '        run: python3 -B ./tests/Fleetory.Tools.Tests/native_publication_namespace.py --real-public\n')
    assert block.count(publication_step) == 1
    start = block.index(publication_step)
    end = block.find('      - name:', start + len(publication_step))
    assert block[start:end if end >= 0 else len(block)].strip() == publication_step.strip()
    create_step = ('      - name: Verify actual public native probe creation\n'
        '        shell: pwsh\n'
        '        run: python3 -B ./tests/Fleetory.Tools.Tests/native_public_probe_create.py\n')
    assert block.count(create_step) == 1
    start = block.index(create_step)
    end = block.find('      - name:', start + len(create_step))
    assert block[start:end if end >= 0 else len(block)].strip() == create_step.strip()
    create_fault_step = ('      - name: Verify actual native create fault cleanup\n'
        '        shell: pwsh\n'
        '        run: python3 -B ./tests/Fleetory.Tools.Tests/native_public_create_faults.py\n')
    assert block.count(create_fault_step) == 1
    start = block.index(create_fault_step)
    end = block.find('      - name:', start + len(create_fault_step))
    assert block[start:end if end >= 0 else len(block)].strip() == create_fault_step.strip()
    fault_step = ('      - name: Verify actual public probe owner fault cleanup\n'
        '        shell: pwsh\n'
        '        run: python3 -B ./tests/Fleetory.Tools.Tests/native_public_probe_faults.py\n')
    assert block.count(fault_step) == 1
    start = block.index(fault_step)
    end = block.find('      - name:', start + len(fault_step))
    assert block[start:end if end >= 0 else len(block)].strip() == fault_step.strip()
    for command in ('./eng/verify-quality.ps1', './eng/verify-sonar-issues.ps1', './eng/report-sonar-metrics.ps1'):
        assert text.count(command) == 1 and command in blocks['quality']
    assert '    timeout-minutes: 35\n' in blocks['quality']
    assert '    timeout-minutes: 20\n' in blocks['windows-tls-chain']
    for key, platform, executable in (('windows-tls-chain', ' on Windows', 'python'), ('quality', '', 'python3')):
        command='./tests/Fleetory.Tools.Tests/NativeProcessObservation.Tests.ps1 -Python (Get-Command '+executable+').Source'
        step=('      - name: Verify bounded native process observations'+platform+'\n'
              '        shell: pwsh\n        run: '+command+'\n')
        block=blocks[key]
        assert text.count(command)==1 and block.count(step)==1
        start=block.index(step)
        end=block.find('      - name:',start+len(step))
        assert block[start:end if end>=0 else len(block)].strip()==step.strip()
    aggregate = blocks['quality-gate']
    assert '    name: Strict build, tests, coverage and Sonar\n' in aggregate
    assert '    needs: [quality, windows-tls-chain, windows-policy, native-data-recovery, native-provider-recovery, native-retained-recovery, native-original-recovery, native-publication-faults]\n' in aggregate
    assert '    if: always()\n' in aggregate and 'continue-on-error:' not in aggregate
    assert '    name: Strict build, tests, coverage and Sonar execution\n' in blocks['quality']
    return True


class RecoveryCiLayoutTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding='utf-8')

    def refused(self, text):
        with self.assertRaises(AssertionError):
            validate(text)

    def test_independent_guard_native_gate_cannot_be_removed_or_softened(self):
        step=('      - name: Verify actual independent public cleanup\n'
            '        shell: pwsh\n'
            '        run: python3 -B ./tests/Fleetory.Tools.Tests/native_public_cleanup_guard.py\n')
        self.refused(self.text.replace(step,''))
        self.refused(self.text.replace(step,step+'        continue-on-error: true\n'))

    def test_windows_policy_job_cannot_be_missing_skipped_softened_or_delayed(self):
        block = jobs(self.text)['windows-policy']
        self.refused(self.text.replace(block, ''))
        for option in ('    if: false\n', '    continue-on-error: true\n', '    needs: quality\n', '    env:\n      SONAR_TOKEN: copied\n'):
            self.refused(self.text.replace('  windows-policy:\n', '  windows-policy:\n' + option))
        for minutes in (5, 20, 60):
            self.refused(self.text.replace('timeout-minutes: 10', 'timeout-minutes: ' + str(minutes), 1))

    def test_every_partitioned_windows_command_remains_required_once(self):
        block = jobs(self.text)['windows-policy']
        for item in WINDOWS_POLICY:
            step = windows_step(item)
            for altered in (block.replace(step, ''), block.replace(step, step + step),
                    block.replace(step, step.replace('        shell:', '        continue-on-error: true\n        shell:', 1))):
                self.refused(self.text.replace(block, altered))
        self.refused(self.text.replace('windows-tls-chain, windows-policy,', 'windows-tls-chain,', 1))

    def test_all_existing_gates_are_partitioned_with_strict_bootstrap(self):
        self.assertTrue(validate(self.text))

    def test_missing_duplicated_or_changed_native_command_refused(self):
        for name, profile in DATA + PROVIDER + RETAINED + ORIGINAL:
            needle = './tests/Fleetory.Tools.Tests/' + name + (' ' + profile if profile else '')
            self.refused(self.text.replace(needle, './tests/Fleetory.Tools.Tests/omitted.ps1', 1))
        self.refused(self.text + '\n      - name: Duplicate\n        run: ./tests/Fleetory.Tools.Tests/NativeJournalBackend.Tests.ps1\n')

    def test_skip_or_soft_failure_does_not_hide_a_required_job(self):
        for inserted in ('    if: false\n', '    continue-on-error: true\n', '    needs: quality\n'):
            self.refused(self.text.replace('  native-data-recovery:\n', '  native-data-recovery:\n' + inserted))

    def test_missing_audit_tools_build_or_native_exit_guard_refused(self):
        for old in ('dotnet tool restore', '-p:NuGetAuditLevel=low', ' --warnaserror\n', 'if ($LASTEXITCODE -ne 0)'):
            start = self.text.index('  native-provider-recovery:')
            self.refused(self.text[:start] + self.text[start:].replace(old, 'removed', 1))

    def test_deadlines_or_sonar_ownership_cannot_change_silently(self):
        for minutes in (30, 60):
            self.refused(self.text.replace('runs-on: ubuntu-24.04\n    timeout-minutes: 35',
                f'runs-on: ubuntu-24.04\n    timeout-minutes: {minutes}'))
        for minutes in (15, 60):
            self.refused(self.text.replace('runs-on: windows-latest\n    timeout-minutes: 20',
                f'runs-on: windows-latest\n    timeout-minutes: {minutes}'))
        self.refused(self.text.replace('./eng/verify-sonar-issues.ps1', './eng/omitted.ps1'))
        self.refused(self.text.replace('  native-data-recovery:\n', '  native-data-recovery:\n    env:\n      SONAR_TOKEN: copied\n'))

    def test_control_identity_gate_is_required_once_and_cannot_be_softened(self):
        for executable in ('python', 'python3'):
            command = executable + ' -B ./tests/Fleetory.Tools.Tests/audit_control_identity_tests.py'
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_process_fence_gate_is_required_once_and_cannot_be_softened(self):
        for executable in ('python', 'python3'):
            command = executable + ' -B ./tests/Fleetory.Tools.Tests/audit_process_fence_tests.py'
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_retained_source_gates_cannot_be_omitted_duplicated_or_softened(self):
        for executable in ('python', 'python3'):
            for filename in ('retained_code_lease_tests.py', 'retained_code_catalog_tests.py'):
                command = executable + ' -B ./tests/Fleetory.Tools.Tests/' + filename
                self.refused(self.text.replace(command, 'omitted', 1))
                self.refused(self.text.replace(command, command + '\n          ' + command, 1))
                self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_separate_build_create_policy_gate_cannot_be_softened(self):
        for executable in ('python','python3'):
            command=executable+' -B ./tests/Fleetory.Tools.Tests/build_runtime_create_profile_tests.py'
            self.refused(self.text.replace(command,'omitted',1))
            self.refused(self.text.replace(command,command+'\n          '+command,1))
            self.refused(self.text.replace('run: '+command,'continue-on-error: true\n        run: '+command,1))

    def test_source_only_entry_gate_cannot_be_omitted_duplicated_or_softened(self):
        for executable in ('python', 'python3'):
            command=executable+' -B ./tests/Fleetory.Tools.Tests/retained_source_bootstrap_tests.py'
            self.refused(self.text.replace(command,'omitted',1))
            self.refused(self.text.replace(command,command+'\n          '+command,1))
            self.refused(self.text.replace('run: '+command,'continue-on-error: true\n        run: '+command,1))

    def test_retained_python_isolation_gate_is_required_once_and_cannot_be_softened(self):
        for executable in ('python', 'python3'):
            command = executable + ' -B ./tests/Fleetory.Tools.Tests/retained_python_isolation_tests.py'
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_original_inventory_mapping_gate_is_required_once_and_cannot_be_softened(self):
        for executable in ('python', 'python3'):
            command = executable + ' -B ./tests/Fleetory.Tools.Tests/retained_expected_inventory_tests.py'
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_data_host_callback_boundary_cannot_be_omitted_or_softened(self):
        command = './tests/Fleetory.Tools.Tests/RetainedDataHostBoundary.Tests.ps1'
        self.refused(self.text.replace(command, 'omitted', 1))
        self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_original_host_binding_refusals_are_mandatory(self):
        command='./tests/Fleetory.Tools.Tests/OriginalFourDataHostBinding.Tests.ps1'
        self.refused(self.text.replace(command,'omitted',1))
        self.refused(self.text.replace(command,command+'\n          '+command,1))
        for option in ('if: false','continue-on-error: true'):
            self.refused(self.text.replace('run: '+command,option+'\n        run: '+command,1))

    def test_live_service_use_gate_is_required_once_and_cannot_be_softened(self):
        for executable in ('python', 'python3'):
            command = executable + ' -B ./tests/Fleetory.Tools.Tests/retained_service_use_tests.py'
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_payload_binding_gate_is_required_once_and_cannot_be_softened(self):
        for executable in ('python', 'python3'):
            command = executable + ' -B ./tests/Fleetory.Tools.Tests/audit_payload_launch_tests.py'
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_application_input_gate_is_required_on_both_platforms(self):
        command = './tests/Fleetory.Tools.Tests/HistoricalAuditInputPins.Tests.ps1'
        for offset in (0, self.text.index('  quality:')):
            prefix, tail = self.text[:offset], self.text[offset:]
            self.refused(prefix + tail.replace(command, 'omitted', 1))
            self.refused(prefix + tail.replace(command, command + '\n          ' + command, 1))
            self.refused(prefix + tail.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_container_binding_gate_is_required_on_both_platforms(self):
        for executable in ('python', 'python3'):
            command = executable + ' -B ./tests/Fleetory.Tools.Tests/audit_backend_binding_tests.py'
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_actual_docker_binding_gate_cannot_be_omitted_or_softened(self):
        command = 'python3 -B ./tests/Fleetory.Tools.Tests/native_audit_resource_binding.py'
        self.refused(self.text.replace(command, 'omitted', 1))
        self.refused(self.text.replace(command, command + '\n          ' + command, 1))
        self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_image_binding_gate_is_required_on_both_platforms(self):
        for executable in ('python', 'python3'):
            command = executable + ' -B ./tests/Fleetory.Tools.Tests/audit_image_binding_tests.py'
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_actual_image_gate_cannot_be_omitted_or_softened(self):
        command = 'python3 -B ./tests/Fleetory.Tools.Tests/native_audit_image_binding.py'
        self.refused(self.text.replace(command, 'omitted', 1))
        self.refused(self.text.replace(command, command + '\n          ' + command, 1))
        self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_native_preparation_contracts_are_required_on_both_platforms(self):
        for executable in ('python', 'python3'):
            command = executable + ' -B ./tests/Fleetory.Tools.Tests/audit_native_preparation_tests.py'
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_actual_native_readiness_cannot_be_omitted_or_softened(self):
        for executable in ('python', 'python3'):
            command = executable + ' -B ./tests/Fleetory.Tools.Tests/native_audit_preparation.py'
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_native_empty_payload_gates_cannot_be_omitted_duplicated_or_softened(self):
        for filename in ('audit_native_payload_tests.py', 'native_empty_payload.py'):
            for executable in ('python', 'python3'):
                command = executable + ' -B ./tests/Fleetory.Tools.Tests/' + filename
                self.refused(self.text.replace(command, 'omitted', 1))
                self.refused(self.text.replace(command, command + '\n          ' + command, 1))
                self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_linked_contracts_cannot_be_omitted_duplicated_or_softened(self):
        for executable in ('python', 'python3'):
            command = executable + ' -B ./tests/Fleetory.Tools.Tests/audit_linked_binding_tests.py'
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_linked_native_pair_cannot_be_omitted_duplicated_or_softened(self):
        command = 'python3 -B ./tests/Fleetory.Tools.Tests/native_audit_linked_pair.py'
        self.refused(self.text.replace(command, 'omitted', 1))
        self.refused(self.text.replace(command, command + '\n          ' + command, 1))
        self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_native_receipt_gates_are_required_on_both_platforms(self):
        for filename in ('audit_native_resource_tests.py', 'native_resource_ack.py'):
            for executable in ('python', 'python3'):
                command = executable + ' -B ./tests/Fleetory.Tools.Tests/' + filename
                self.refused(self.text.replace(command, 'omitted', 1))
                self.refused(self.text.replace(command, command + '\n          ' + command, 1))
                self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_native_docker_receipt_gate_cannot_be_omitted_or_softened(self):
        command = 'python3 -B ./tests/Fleetory.Tools.Tests/native_resource_docker_ack.py'
        self.refused(self.text.replace(command, 'omitted', 1))
        self.refused(self.text.replace(command, command + '\n          ' + command, 1))
        self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_probe_image_gates_cannot_be_omitted_duplicated_or_softened(self):
        for command in ('python -B ./tests/Fleetory.Tools.Tests/audit_probe_image_tests.py',
                'python3 -B ./tests/Fleetory.Tools.Tests/audit_probe_image_tests.py',
                'python3 -B ./tests/Fleetory.Tools.Tests/native_probe_image.py'):
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_probe_runtime_gates_cannot_be_omitted_duplicated_or_softened(self):
        for command in ('python -B ./tests/Fleetory.Tools.Tests/audit_probe_runtime_tests.py',
                'python3 -B ./tests/Fleetory.Tools.Tests/audit_probe_runtime_tests.py',
                'python3 -B ./tests/Fleetory.Tools.Tests/native_probe_runtime.py'):
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_native_probe_receipt_gates_cannot_be_omitted_duplicated_or_softened(self):
        for command in ('python -B ./tests/Fleetory.Tools.Tests/audit_native_probe_tests.py',
                'python3 -B ./tests/Fleetory.Tools.Tests/audit_native_probe_tests.py',
                'python -B ./tests/Fleetory.Tools.Tests/native_probe_receipt_ack.py',
                'python3 -B ./tests/Fleetory.Tools.Tests/native_probe_receipt_ack.py',
                'python3 -B ./tests/Fleetory.Tools.Tests/native_public_probe_receipt.py'):
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_native_create_gates_cannot_be_omitted_duplicated_or_softened(self):
        for command in ('python -B ./tests/Fleetory.Tools.Tests/audit_native_create_tests.py',
                'python3 -B ./tests/Fleetory.Tools.Tests/audit_native_create_tests.py',
                'python3 -B ./tests/Fleetory.Tools.Tests/native_public_probe_create.py'):
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_publication_namespace_gates_cannot_be_omitted_duplicated_or_softened(self):
        for command in ('python -B ./tests/Fleetory.Tools.Tests/publication_namespace_tests.py',
                'python3 -B ./tests/Fleetory.Tools.Tests/publication_namespace_tests.py',
                'python -B ./tests/Fleetory.Tools.Tests/native_publication_namespace.py',
                'python3 -B ./tests/Fleetory.Tools.Tests/native_publication_namespace.py',
                'python3 -B ./tests/Fleetory.Tools.Tests/native_publication_namespace.py --real-public'):
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_publication_fault_gates_cannot_be_omitted_duplicated_or_softened(self):
        for executable in ('python', 'python3'):
            for filename in ('publication_faults_tests.py', 'native_publication_faults.py'):
                command = executable + ' -B ./tests/Fleetory.Tools.Tests/' + filename
                self.refused(self.text.replace(command, 'omitted', 1))
                self.refused(self.text.replace(command, command + '\n          ' + command, 1))
                self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_native_publication_gates_cannot_be_omitted_duplicated_or_softened(self):
        for executable in ('python', 'python3'):
            for filename in ('native_publication_tests.py', 'native_publication.py'):
                command = executable + ' -B ./tests/Fleetory.Tools.Tests/' + filename
                self.refused(self.text.replace(command, 'omitted', 1))
                self.refused(self.text.replace(command, command + '\n          ' + command, 1))
                self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_native_create_fault_gates_cannot_be_omitted_duplicated_or_softened(self):
        for command in ('python -B ./tests/Fleetory.Tools.Tests/native_create_faults_tests.py',
                'python3 -B ./tests/Fleetory.Tools.Tests/native_create_faults_tests.py',
                'python3 -B ./tests/Fleetory.Tools.Tests/native_public_create_faults.py'):
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_public_probe_fault_gates_cannot_be_omitted_duplicated_or_softened(self):
        for command in ('python -B ./tests/Fleetory.Tools.Tests/public_probe_faults_tests.py',
                'python3 -B ./tests/Fleetory.Tools.Tests/public_probe_faults_tests.py',
                'python3 -B ./tests/Fleetory.Tools.Tests/native_public_probe_faults.py'):
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            self.refused(self.text.replace('run: ' + command, 'continue-on-error: true\n        run: ' + command, 1))

    def test_moved_server_pair_keeps_cold_runner_restore_and_input_gate(self):
        for line in PAIR_ADMISSION.splitlines()[3:7]:
            with self.subTest(line=line):
                self.refused(self.text.replace(PAIR_ADMISSION, PAIR_ADMISSION.replace(line + '\n', '')))
        self.refused(self.text.replace(PAIR_ADMISSION, '').replace(
            '  native-provider-recovery:\n', PAIR_ADMISSION + '\n  native-provider-recovery:\n', 1))

    def test_actual_aggregate_rejects_failed_cancelled_skipped_or_missing_jobs(self):
        block = jobs(self.text)['quality-gate']
        self.refused(self.text.replace('    if: always()\n', ''))
        script = '\n'.join(line[10:] for line in block.split('        run: |\n', 1)[1].splitlines())
        executable = shutil.which('pwsh')
        self.assertIsNotNone(executable)
        names = ('quality', 'windows-tls-chain', 'windows-policy', 'native-data-recovery', 'native-provider-recovery', 'native-retained-recovery', 'native-original-recovery', 'native-publication-faults')
        success = {name: {'result': 'success', 'outputs': {}} for name in names}
        cases = [(success, True), ({}, False), ({**success, 'extra': {'result': 'success'}}, False)]
        for name in names:
            for result in ('failure', 'cancelled', 'skipped', None):
                cases.append(({**success, name: {'result': result}}, False))
            cases.append(({key: value for key, value in success.items() if key != name}, False))
        for value, accepted in cases:
            env = dict(os.environ, FLEETORY_GATE_RESULTS=json.dumps(value))
            run = subprocess.run([executable, '-NoProfile', '-Command', script], env=env, capture_output=True, timeout=10)
            self.assertEqual(run.returncode == 0, accepted)


    def test_retained_publication_contracts_and_actual_flags_cannot_be_omitted(self):
        for executable,flag in (('python','--continuation'),('python3','--continuation-image')):
            command=executable+' -B ./tests/Fleetory.Tools.Tests/publication_continuation_tests.py'
            self.refused(self.text.replace(command,'omitted',1))
            self.refused(self.text.replace('run: '+command,'continue-on-error: true\n        run: '+command,1))
            self.refused(self.text.replace('native_publication_faults.py '+flag,'native_publication_faults.py',1))


    def test_retained_runtime_contracts_are_required_without_soft_failure(self):
        for executable in ('python','python3'):
            command=executable+' -B ./tests/Fleetory.Tools.Tests/retained_runtime_tests.py'
            self.refused(self.text.replace(command,'omitted',1))
            self.refused(self.text.replace('run: '+command,'continue-on-error: true\n        run: '+command,1))
            self.refused(self.text.replace(command,command+'\n          '+command,1))


    def test_public_cleanup_protocol_contracts_are_required_without_soft_failure(self):
        for executable in ('python','python3'):
            command=executable+' -B ./tests/Fleetory.Tools.Tests/cleanup_protocol_tests.py'
            self.refused(self.text.replace(command,'omitted',1))
            self.refused(self.text.replace('run: '+command,'continue-on-error: true\n        run: '+command,1))
            self.refused(self.text.replace(command,command+'\n          '+command,1))


    def test_readonly_supervisor_gates_are_required_once_without_soft_failure(self):
        for executable in ('python','python3'):
            for filename in ('supervisor_identity_tests.py','native_supervisor_observation.py'):
                command=executable+' -B ./tests/Fleetory.Tools.Tests/'+filename
                self.refused(self.text.replace(command,'omitted',1))
                self.refused(self.text.replace('run: '+command,'continue-on-error: true\n        run: '+command,1))
                self.refused(self.text.replace(command,command+'\n          '+command,1))


    def test_consumed_cleanup_attempt_gate_cannot_be_omitted_duplicated_or_softened(self):
        for executable in ('python','python3'):
            command=executable+' -B ./tests/Fleetory.Tools.Tests/cleanup_attempt_tests.py'
            self.refused(self.text.replace(command,'omitted',1))
            self.refused(self.text.replace('run: '+command,'continue-on-error: true\n        run: '+command,1))
            self.refused(self.text.replace(command,command+'\n          '+command,1))


    def test_retained_guard_preparation_gate_cannot_be_omitted_duplicated_or_softened(self):
        for executable in ('python','python3'):
            command=executable+' -B ./tests/Fleetory.Tools.Tests/retained_guard_preparation_tests.py'
            self.refused(self.text.replace(command,'omitted',1))
            self.refused(self.text.replace('run: '+command,'continue-on-error: true\n        run: '+command,1))
            self.refused(self.text.replace(command,command+'\n          '+command,1))


    def test_retained_context_transport_gate_cannot_be_omitted_duplicated_or_softened(self):
        for executable in ('python','python3'):
            command=executable+' -B ./tests/Fleetory.Tools.Tests/retained_context_transport_tests.py'
            self.refused(self.text.replace(command,'omitted',1))
            self.refused(self.text.replace('run: '+command,'continue-on-error: true\n        run: '+command,1))
            self.refused(self.text.replace(command,command+'\n          '+command,1))


    def test_retained_owned_cleanup_contracts_cannot_be_omitted_or_softened(self):
        for executable in ('python','python3'):
            command=executable+' -B ./tests/Fleetory.Tools.Tests/retained_cleanup_guard_tests.py'
            self.refused(self.text.replace(command,'omitted',1))
            self.refused(self.text.replace('run: '+command,'continue-on-error: true\n        run: '+command,1))
            self.refused(self.text.replace(command,command+'\n          '+command,1))

    def test_actual_owned_cleanup_flag_cannot_be_removed_or_duplicated(self):
        self.refused(self.text.replace(' --owned-cleanup','',1))
        self.refused(self.text.replace(' --owned-cleanup',' --owned-cleanup --owned-cleanup',1))


    def test_combined_server_gates_cannot_be_omitted_duplicated_or_softened(self):
        for profile in ('v2-retained-server', 'v2-retained-historical-server', 'v2-retained-inflight', 'v2-retained-restore-inflight', 'v2-retained-service-use', 'v2-retained-service-use-loss', 'v2-retained-service-use-expiry'):
            command='./tests/Fleetory.Tools.Tests/NativeServerPair.Tests.ps1 -Profile '+profile+' -Python (Get-Command python3).Source'
            self.refused(self.text.replace(command,'omitted',1))
            self.refused(self.text.replace('run: '+command,'continue-on-error: true\n        run: '+command,1))
            self.refused(self.text.replace(command,command+'\n          '+command,1))


    def test_retained_job_requires_independent_strict_bootstrap_and_original_deadline(self):
        block=jobs(self.text)['native-retained-recovery']
        self.refused(self.text.replace(block,''))
        for option in ('    if: false\n','    continue-on-error: true\n','    needs: quality\n'):
            self.refused(self.text.replace('  native-retained-recovery:\n','  native-retained-recovery:\n'+option))
        for old in ('dotnet tool restore','-p:NuGetAuditLevel=low',' --warnaserror\n','dotnet restore ./eng/ServerBackendProbe/ServerBackendProbe.csproj --disable-parallel','if ($LASTEXITCODE -ne 0)'):
            self.refused(self.text.replace(block,block.replace(old,'removed',1)))
        for minutes in (10,20,60):
            self.refused(self.text.replace(block,block.replace('timeout-minutes: 15','timeout-minutes: '+str(minutes),1)))


    def test_native_process_observation_is_required_once_on_both_platforms(self):
        for executable in ('python','python3'):
            command='./tests/Fleetory.Tools.Tests/NativeProcessObservation.Tests.ps1 -Python (Get-Command '+executable+').Source'
            self.refused(self.text.replace(command,'omitted',1))
            self.refused(self.text.replace(command,command+'\n          '+command,1))
            for option in ('if: false','continue-on-error: true'):
                self.refused(self.text.replace('        run: '+command,'        '+option+'\n        run: '+command,1))



    def test_public_sdk_lifecycle_gates_are_required_once_without_soft_failure(self):
        for key in ('windows-tls-chain', 'quality'):
            block = jobs(self.text)[key]
            for filename in ('PublicBuildImageTransaction', 'PublicBuildSdkTransaction',
                             'PublicBuildSdkClient', 'PublicBuildNativeEnvironment'):
                command = './tests/Fleetory.Tools.Tests/' + filename + '.Tests.ps1'
                self.refused(self.text.replace(block, block.replace(command, 'omitted', 1)))
                self.refused(self.text.replace(block, block.replace(command, command + '\n          ' + command, 1)))
            marker = '        run: |\n          ./tests/Fleetory.Tools.Tests/PublicBuildImageTransaction'
            for option in ('if: false', 'continue-on-error: true'):
                self.refused(self.text.replace(block, block.replace(marker, '        ' + option + '\n' + marker, 1)))



    def test_public_build_policy_gates_cannot_be_omitted_duplicated_or_softened(self):
        for executable in ('python', 'python3'):
            for filename in ('public_build_context_tests.py','public_build_intake_tests.py','public_build_source_peer_tests.py'):
                command = executable + ' -B ./tests/Fleetory.Tools.Tests/' + filename
                self.refused(self.text.replace(command, 'omitted', 1))
                self.refused(self.text.replace(command, command + '\n          ' + command, 1))
                for option in ('if: false', 'continue-on-error: true'):
                    self.refused(self.text.replace('run: ' + command, option + '\n        run: ' + command, 1))

        for filename in ('PublicBuildSourceTransport.Tests.ps1','PublicBuildSourceTransaction.Tests.ps1'):
            command = './tests/Fleetory.Tools.Tests/' + filename
            self.refused(self.text.replace(command, 'omitted', 1))
            self.refused(self.text.replace(command, command + '\n          ' + command, 1))
            for option in ('if: false', 'continue-on-error: true'):
                self.refused(self.text.replace('run: ' + command, option + '\n        run: ' + command, 1))

    def test_original_four_input_purpose_gates_cannot_be_omitted_duplicated_or_softened(self):
        for executable in ('python','python3'):
            for filename in ('original_four_use_tests.py','retained_private_session_tests.py','original_four_peer_tests.py','run_original_four_peer_prototype.py (Get-Command pwsh).Source'):
                command=executable+' -B ./tests/Fleetory.Tools.Tests/'+filename
                self.refused(self.text.replace(command,'omitted',1))
                self.refused(self.text.replace(command,command+'\n          '+command,1))
                for option in ('if: false','continue-on-error: true'):
                    self.refused(self.text.replace('run: '+command,option+'\n        run: '+command,1))


    def test_original_native_job_cannot_be_removed_or_softened(self):
        block=jobs(self.text)['native-original-recovery']
        self.refused(self.text.replace(block,''))
        for option in ('    if: false\n','    continue-on-error: true\n','    needs: quality\n'):
            self.refused(self.text.replace('  native-original-recovery:\n','  native-original-recovery:\n'+option))
        for minutes in (10,20):
            self.refused(self.text.replace(block,block.replace('timeout-minutes: 15','timeout-minutes: '+str(minutes),1)))
        for name,profile in ORIGINAL:
            command='./tests/Fleetory.Tools.Tests/'+name+' '+profile+' -Python (Get-Command python3).Source'
            self.refused(self.text.replace(command,'omitted',1))
            self.refused(self.text.replace(command,command+'\n          '+command,1))


    def test_retained_entry_expiry_is_required_once_in_original_job_without_softening(self):
        step=('      - name: Verify original admission expiry and owned cleanup\n'
              '        shell: pwsh\n'
              '        run: ./tests/Fleetory.Tools.Tests/NativeServerPair.Tests.ps1 -Profile v2-retained-service-use-expiry -Python (Get-Command python3).Source\n\n')
        blocks=jobs(self.text)
        self.assertEqual(blocks['native-original-recovery'].count(step),1)
        self.assertNotIn(step,blocks['native-retained-recovery'])
        self.refused(self.text.replace(step,''))
        self.refused(self.text.replace(step,step+step))
        marker='      - name: Verify frozen retained PostgreSQL audit and strict Server lifecycle\n'
        self.refused(self.text.replace(step,'').replace(marker,step+marker))
        for option in ('if: false','continue-on-error: true'):
            self.refused(self.text.replace(step,step.replace('        shell:', '        '+option+'\n        shell:',1)))


    def test_external_controller_fault_gates_cannot_be_omitted_duplicated_or_softened(self):
        for case in ('eof','death','sql-death'):
            step=controller_fault_step(case)
            self.refused(self.text.replace(step,''))
            self.refused(self.text.replace(step,step+step))
            for option in ('if: false','continue-on-error: true'):
                self.refused(self.text.replace(step,step.replace('        shell:', '        '+option+'\n        shell:',1)))


    def test_publication_fault_job_preserves_cold_bootstrap_free_runner_and_required_gate(self):
        block=jobs(self.text)['native-publication-faults']
        self.refused(self.text.replace(block,''))
        for before,after in (('ubuntu-24.04','ubuntu-24.04-4core'),('timeout-minutes: 15','timeout-minutes: 20'),
                             ('dotnet tool restore','omitted'),(' --force -warnaserror',' --force'),
                             ('if ($LASTEXITCODE -ne 0)','if ($false)')):
            self.refused(self.text.replace(block,block.replace(before,after,1)))
        for option in ('if: false','continue-on-error: true','needs: quality'):
            self.refused(self.text.replace('  native-publication-faults:\n','  native-publication-faults:\n    '+option+'\n'))


    def test_publication_pinned_image_preparation_cannot_be_omitted_duplicated_or_softened(self):
        self.refused(self.text.replace(PUBLICATION_IMAGE_PREP,''))
        self.refused(self.text.replace(PUBLICATION_IMAGE_PREP,PUBLICATION_IMAGE_PREP+PUBLICATION_IMAGE_PREP))
        for old,new in (('timeout=120','timeout=121'),('recovery_isolation.IMAGE',"'python:latest'"),
                        ('if ($LASTEXITCODE -ne 0)','if ($false)')):
            self.refused(self.text.replace(PUBLICATION_IMAGE_PREP,PUBLICATION_IMAGE_PREP.replace(old,new)))
        moved=self.text.replace(PUBLICATION_IMAGE_PREP,'')
        self.refused(moved.replace('  quality-gate:\n',PUBLICATION_IMAGE_PREP+'  quality-gate:\n'))

    def test_actual_preparation_releases_cold_cache_preflight_using_only_the_pinned_public_image(self):
        from recovery_isolation_tests import DockerRehearsal,isolation
        rehearsal=DockerRehearsal()
        cached=False
        def metadata(args,*_args,**_kwargs):
            if args==['context','show']:return b'default\n'
            if args[:2]==['context','inspect']:return b'unix:///var/run/docker.sock\n'
            if args[0]=='version':return b'28.0.4\n'
            if args[0]=='info':return b'linux\n'
            if args[:2] in (['container','ls'],['network','ls']):return b''
            if args==['image','inspect',isolation.IMAGE]:
                if not cached:raise RuntimeError('Missing cached pinned image')
                return b'[]'
            raise AssertionError('Unexpected metadata request')
        def pull(args,**kwargs):
            nonlocal cached
            self.assertEqual(args,['docker','pull',isolation.IMAGE])
            self.assertEqual(kwargs,dict(check=True,timeout=120))
            cached=True
        publication=jobs(self.text)['native-publication-faults']
        code=re.search(r'python3 -B -c "([^"\n]+)"',publication).group(1)
        import sys
        before=list(sys.path)
        try:
            with patch.dict(os.environ,{'DOCKER_HOST':''}),patch.object(rehearsal,'call',side_effect=metadata):
                with self.assertRaisesRegex(RuntimeError,'Missing cached pinned image'):rehearsal.preflight()
                with patch.object(subprocess,'run',side_effect=pull) as invoked:
                    exec(compile(code,'<actual-workflow-public-image-preparation>','exec'),{})
                    self.assertEqual(invoked.call_count,1)
                self.assertEqual(rehearsal.preflight(),'28.0.4')
        finally:sys.path[:]=before


if __name__ == '__main__':
    unittest.main()
