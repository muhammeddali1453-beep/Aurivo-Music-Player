# -*- mode: python ; coding: utf-8 -*-
# Aurivo Music Player - Linux Dağıtım Spec
# Whisper DAHİL DEĞİL (kullanıcı isteğe bağlı kuracak)

import sys
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
    'OpenGL',
    'OpenGL.GL',
    'OpenGL.GLU',
    'OpenGL.GLUT',
    'OpenGL.arrays',
    'OpenGL.platform',
    'OpenGL.platform.egl',
    'OpenGL.platform.glx',
    'OpenGL_accelerate',
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

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[
        ('subtitle_engine.cpython-313-x86_64-linux-gnu.so', '.'),  # C++ altyazı modülü
        ('aurivo_dsp.so', '.'),  # C++ DSP efekt modülü
    ],
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
    name='aurivo',
)
