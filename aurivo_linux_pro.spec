# -*- mode: python ; coding: utf-8 -*-
# Aurivo Music Player - Linux Dağıtım Spec (PRO)
# Whisper ve PyTorch DAHİL (büyük boyut ~2.5GB)

import sys
import glob
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# PyQt5 ve temel bağımlılıklar + Whisper
hiddenimports = [
    'PyQt5.QtCore',
    'PyQt5.QtGui',
    'PyQt5.QtWidgets',
    'PyQt5.QtMultimedia',
    'PyQt5.QtMultimediaWidgets',
    'PyQt5.QtWebEngineWidgets',
    'mutagen',
    'numpy',
    'OpenGL',
    'OpenGL.GL',
    'OpenGL.GLU',
    'OpenGL.GLUT',
    'OpenGL.arrays',
    'OpenGL.platform',
    'OpenGL.platform.egl',
    'OpenGL.platform.glx',
    'OpenGL_accelerate',
    # Whisper ve PyTorch
    'whisper',
    'torch',
    'torchaudio',
]

# Sadece gereksiz paketleri exclude et
excludes = [
    'tensorflow',
    'matplotlib',
    'pandas',
    'scipy',
]

# Native binaries'i glob ile bul (Python versiyonundan bağımsız)
extra_binaries = []
for pattern in ['subtitle_engine*.so', 'aurivo_dsp.so']:
    matches = glob.glob(pattern)
    for match in matches:
        extra_binaries.append((match, '.'))

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=extra_binaries,
    datas=[
        ('icons', 'icons'),  # Icon klasörünü dahil et
        ('aurivo.desktop', '.'),  # Desktop dosyası
        ('icons/aurivo.png', '.'),  # Ana simge
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='aurivo',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # GUI modu
    icon='icons/aurivo.png',  # Ana simge
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='aurivo-pro',
)

