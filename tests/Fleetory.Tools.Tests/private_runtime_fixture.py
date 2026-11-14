"""Prepare public test runtime copies without changing shared host permissions."""
import hashlib
import os
from pathlib import Path
import shutil


def windows_git_core(executable):
    path = Path(executable).resolve(strict=True)
    if path.name.lower() != 'git.exe':
        raise ValueError('Unexpected Windows Git fixture entrypoint.')
    if path.parent.name.lower() == 'bin' and path.parent.parent.name.lower() in ('ucrt64', 'mingw64'):
        return path
    if path.parent.name.lower() not in ('cmd', 'bin'):
        raise ValueError('Unsupported Windows Git fixture layout.')
    root = path.parent.parent
    candidates = [root / name / 'bin/git.exe' for name in ('ucrt64', 'mingw64')]
    present = [p for p in candidates if p.is_file()]
    if len(present) != 1:
        raise ValueError('Windows Git core fixture layout is missing or ambiguous.')
    return present[0]


def private_powershell(executable, root):
    executable = Path(executable).resolve(strict=True)
    if os.name != 'posix':
        return executable
    target = Path(root).resolve(strict=True) / 'powershell'
    expected = hashlib.sha256(executable.read_bytes()).digest()
    shutil.copytree(executable.parent, target, symlinks=True)
    for directory, _, _ in os.walk(target, followlinks=False):
        Path(directory).chmod(0o700)
    copied = target / executable.name
    if hashlib.sha256(copied.read_bytes()).digest() != expected:
        raise ValueError('Private runtime copy differs from selected executable.')
    return copied


def private_git(executable, root):
    executable = Path(executable).resolve(strict=True)
    target = Path(root).resolve(strict=True) / 'git-runtime'
    expected = hashlib.sha256(executable.read_bytes()).digest()
    if os.name == 'nt':
        # The selected Git-for-Windows core entrypoint needs its adjacent public DLLs.
        shutil.copytree(executable.parent, target, symlinks=True)
    else:
        target.mkdir(mode=0o700)
        shutil.copy2(executable, target / executable.name)
    copied = target / executable.name
    if hashlib.sha256(copied.read_bytes()).digest() != expected or copied.stat().st_nlink != 1:
        raise ValueError('Private Git copy differs from selected executable or has aliases.')
    return copied


def _copy_dotnet(executable, root):
    executable=Path(executable).resolve(strict=True)
    target=Path(root).resolve(strict=True)/'dotnet-runtime'
    target.mkdir(mode=0o700)
    expected=hashlib.sha256(executable.read_bytes()).digest()
    shutil.copy2(executable,target/executable.name)
    for name in ('host','shared','packs','sdk-manifests','metadata','templates'):
        source=executable.parent/name
        if source.exists():
            shutil.copytree(source,target/name,symlinks=True)
    sdk=executable.parent/'sdk/10.0.402'
    if not sdk.is_dir():
        raise ValueError('Selected public SDK402 is missing.')
    (target/'sdk').mkdir(mode=0o700)
    shutil.copytree(sdk,target/'sdk/10.0.402',symlinks=True)
    for directory,_,_ in os.walk(target,followlinks=False):
        Path(directory).chmod(0o700)
    copied=target/executable.name
    if hashlib.sha256(copied.read_bytes()).digest()!=expected or copied.stat().st_nlink!=1:
        raise ValueError('Private dotnet copy differs from selected executable or has aliases.')
    return copied


def private_dotnet(executable, root):
    # Pinning the public muxer must not require changing shared runner directory permissions.
    if os.name!='posix':
        return Path(executable).resolve(strict=True)
    return _copy_dotnet(executable,root)
