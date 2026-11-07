"""Prepare public test runtime copies without changing shared host permissions."""
import hashlib
import os
from pathlib import Path
import shutil


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
