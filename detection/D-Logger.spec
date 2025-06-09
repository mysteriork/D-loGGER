# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['advancedGUI.py'],
    pathex=[],
    binaries=[],
    datas=[('C:\\stufffff\\pythonProject\\LOGGERDETECTION\\scanner1.gif', '.'), ('C:\\stufffff\\pythonProject\\LOGGERDETECTION\\grn.png', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='D-Logger',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['C:\\stufffff\\pythonProject\\LOGGERDETECTION\\cyber3.ico'],
)
