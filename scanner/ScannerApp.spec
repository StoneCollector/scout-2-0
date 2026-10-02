# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all
from pathlib import Path
import os

block_cipher = None

datas = [
    ('app/web/dist', 'web/dist'),
]
binaries = []
hiddenimports = [
    'uvicorn.logging',
    'uvicorn.loops.auto',
    'uvicorn.protocols.http.auto',
    'uvicorn.protocols.websockets.auto',
    'uvicorn.lifespan.on',
    'websockets',
    'sqlalchemy.dialects.sqlite',
    'asn1crypto',
    'olefile',
    'pefile',
    'pyclamd',
    'yaml',
    'dotenv',
    'tkinter',
    'tkinter.font',
    'tkinter.filedialog',
    'engine.folder_browser',
]

# Collect yara dependencies
yara_datas, yara_binaries, yara_hidden = collect_all('yara')
datas += yara_datas
binaries += yara_binaries
hiddenimports += yara_hidden

# Collect asn1crypto dependencies
asn1_datas, asn1_binaries, asn1_hidden = collect_all('asn1crypto')
datas += asn1_datas
binaries += asn1_binaries
hiddenimports += asn1_hidden

a = Analysis(
    ['run_app.py'],
    pathex=['.', 'app'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['pytest', 'unittest'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ScannerApp',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='ScannerApp',
)
