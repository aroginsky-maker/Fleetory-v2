"""Fixed public package trust policy; no file/network/store mutation API."""
import xml.etree.ElementTree as ET

FINGERPRINTS=(
    '5A2901D6ADA3D18260B9C6DFE2133C95D74B9EEF6AE0E5DC334C8454D1477DF4',
    '1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D',
)
OWNERS=('AzureAD','EntityFramework','Humanizer','Microsoft','Npgsql','RoslynTeam',
        'VisualStudioExtensibility','aspnet','brar','dotnetfoundation','dotnetframework',
        'jamesnk','kzu','mhutch','newtonsoft','ninofloris','roji')


def render():
    root=ET.Element('configuration')
    sources=ET.SubElement(root,'packageSources');ET.SubElement(sources,'clear')
    ET.SubElement(sources,'add',key='offline',value='/payload/packages')
    config=ET.SubElement(root,'config')
    ET.SubElement(config,'add',key='signatureValidationMode',value='require')
    signers=ET.SubElement(root,'trustedSigners')
    repository=ET.SubElement(signers,'repository',name='nuget.org',serviceIndex='https://api.nuget.org/v3/index.json')
    for fingerprint in FINGERPRINTS:
        ET.SubElement(repository,'certificate',fingerprint=fingerprint,hashAlgorithm='SHA256',allowUntrustedRoot='false')
    ET.SubElement(repository,'owners').text=';'.join(OWNERS)
    ET.indent(root,space='  ')
    return ET.tostring(root,encoding='utf-8',xml_declaration=True)+b'\n'


def validate(raw):
    # Only this reviewed by-value configuration can enter the fixed context.
    # Neither a signer name nor matching XML grants execution or store access.
    if type(raw) is not bytes or raw!=render():raise ValueError('Public package trust policy refused')
