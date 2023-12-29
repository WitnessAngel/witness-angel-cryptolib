# -*- mode: python ; coding: utf-8 -*-

import re, sys, os
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules, collect_data_files

import PyInstaller.config
PyInstaller.config.CONF['distpath'] = "bin"  # Make it same as buildozer output path

pyproject_data = Path("pyproject.toml").read_text()
version = re.search(r'''version = ['"](.*)['"]''', pyproject_data).group(1)
assert version, version

root_dir = os.path.abspath(os.getcwd())
src_dir = os.path.join(root_dir, "src")
assert os.path.isdir(src_dir)
sys.path.append(src_dir)

app_name = "flightbox_%s" % version.replace(".","-")

program_icon = "assets/flightbox_512x512.png"
extra_exe_params= []

is_macos = sys.platform.startswith("darwin")

codesign_identity = os.environ.get("MACOS_CODESIGN_IDENTITY", None)
print(">>> macosx codesign identity is", codesign_identity)

if sys.platform.startswith("win32"):
    program_icon = "assets/flightbox_favicon.ico"
elif is_macos:
    program_icon = "assets/flightbox_512x512.icns"

USE_CONSOLE = True  # Change this if needed, to debug

main_script = os.path.join(root_dir, 'main.py')

extra_exe_params = ()

a = Analysis([main_script],
             pathex=['.'],
             binaries=[],
             datas=None,
             hiddenimports=None,
             hookspath=[],
             runtime_hooks=[],
             excludes=['_tkinter', 'Tkinter', "enchant", "twisted", "cv2", "numpy", "pygame"],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=None,
             noarchive=True)

pyz = PYZ(a.pure, a.zipped_data,
             cipher=None)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          *extra_exe_params,
          #exclude_binaries=True,
          name=app_name,
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=USE_CONSOLE,
          icon=program_icon,
          codesign_identity=codesign_identity,
          entitlements_file="assets/entitlements.plist", # For MacOS only
)

if sys.platform.startswith("darwin"):
    app = BUNDLE(exe,
             name=app_name+".app",
             icon=program_icon,
             bundle_identifier="org.witnessangel.flightbox",
             codesign_identity=codesign_identity,
             entitlements_file="assets/entitlements.plist", # For MacOS only
    )
