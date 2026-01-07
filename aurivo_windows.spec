# -*- mode: python ; coding: utf-8 -*-
# Aurivo Music Player - Windows Dağıtım Spec
# Whisper DAHİL DEĞİL (kullanıcı isteğe bağlı kuracak)

import sys
import os
import glob
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# PyQt5 ve temel bağımlılıklar
hiddenimports = [
    'PyQt5.QtCore',
    'PyQt5.QtGui',
    'PyQt5.QtWidgets',
    'PyQt5.QtMultimedia',
    'PyQt5.QtMultimediaWidgets',
    'PyQt5.QtWebEngineWidgets',
    'mutagen',
    'numpy',
]

# Whisper ve PyTorch EXCLUDE (opsiyonel)
excludes = [
    'whisper',
    'torch',
    'torchvision',
    'torchaudio',
    'tensorflow',
    'matplotlib',
    'pandas',
    'scipy',
]

ROOT_DIR = os.path.abspath(os.path.dirname(__file__))

extra_binaries = []
for pattern in [
    'aurivo_dsp.dll',
    'subtitle_engine*.pyd',
    'viz_engine*.pyd',
]:
    for match in glob.glob(os.path.join(ROOT_DIR, pattern)):
        extra_binaries.append((match, '.'))

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=extra_binaries,
    datas=[
        ('icons', 'icons'),  # Icon klasörünü dahil et
        ('presets', 'presets'),  # ProjectM presetleri (opsiyonel ama önerilir)
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='Aurivo',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Windows GUI modu
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icons/aurivo.ico',  # Ana ikon
)
