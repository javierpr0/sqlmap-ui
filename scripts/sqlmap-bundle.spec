# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for building sqlmap as a standalone sidecar binary.
# SQLMAP_ROOT env var must point to the cloned sqlmap directory.

import os
import platform

sqlmap_root = os.environ.get('SQLMAP_ROOT')
if not sqlmap_root:
    raise RuntimeError("SQLMAP_ROOT environment variable is required. Set it to the path of the cloned sqlmap repo.")

script_dir = os.path.dirname(os.path.abspath(SPEC))

# Collect all data directories sqlmap needs
datas = [
    (os.path.join(sqlmap_root, 'data'), 'data'),
    (os.path.join(sqlmap_root, 'plugins'), 'plugins'),
    (os.path.join(sqlmap_root, 'tamper'), 'tamper'),
    (os.path.join(sqlmap_root, 'thirdparty'), 'thirdparty'),
    (os.path.join(sqlmap_root, 'extra'), 'extra'),
    (os.path.join(sqlmap_root, 'sqlmap.py'), '.'),
]

# Collect all lib/ Python files
for root, dirs, files in os.walk(os.path.join(sqlmap_root, 'lib')):
    for f in files:
        if f.endswith(('.py', '.txt', '.xml', '.json')):
            src = os.path.join(root, f)
            dst = os.path.relpath(root, sqlmap_root)
            datas.append((src, dst))

a = Analysis(
    [os.path.join(script_dir, 'sqlmap-bundle.py')],
    pathex=[sqlmap_root],
    binaries=[],
    datas=datas,
    hiddenimports=[
        'lib.controller.controller',
        'lib.core.common',
        'lib.core.data',
        'lib.core.option',
        'lib.core.settings',
        'lib.core.target',
        'lib.core.agent',
        'lib.core.testing',
        'lib.core.enums',
        'lib.core.exception',
        'lib.core.log',
        'lib.core.convert',
        'lib.core.unescaper',
        'lib.core.threads',
        'lib.core.dump',
        'lib.core.revision',
        'lib.core.update',
        'lib.core.wordlist',
        'lib.core.decorators',
        'lib.core.defaults',
        'lib.core.dicts',
        'lib.core.patch',
        'lib.core.profiling',
        'lib.core.replication',
        'lib.core.shell',
        'lib.core.subprocessng',
        'lib.parse.banner',
        'lib.parse.cmdline',
        'lib.parse.configfile',
        'lib.parse.handler',
        'lib.parse.headers',
        'lib.parse.html',
        'lib.parse.payloads',
        'lib.parse.sitemap',
        'lib.request.basic',
        'lib.request.comparison',
        'lib.request.connect',
        'lib.request.direct',
        'lib.request.dns',
        'lib.request.httpshandler',
        'lib.request.inject',
        'lib.request.methodrequest',
        'lib.request.pkihandler',
        'lib.request.rangehandler',
        'lib.request.redirecthandler',
        'lib.request.templates',
        'lib.techniques',
        'lib.takeover',
        'lib.utils.api',
        'lib.utils.brute',
        'lib.utils.crawler',
        'lib.utils.hash',
        'lib.utils.hashdb',
        'lib.utils.pivotdumptable',
        'lib.utils.progress',
        'lib.utils.purge',
        'lib.utils.search',
        'lib.utils.sqlalchemy',
        'lib.utils.timeout',
        'lib.utils.xrange',
        'sqlite3',
        'json',
        'xml.etree.ElementTree',
        'html.parser',
        'http.client',
        'http.cookiejar',
        'urllib.request',
        'urllib.parse',
        'urllib.error',
        'email',
        'email.mime',
        'email.mime.text',
        'email.mime.multipart',
        'email.mime.base',
        'difflib',
        'codecs',
        'unicodedata',
        'struct',
        'binascii',
        'hashlib',
        'socket',
        'ssl',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['MySQLdb', 'tkinter', 'matplotlib', 'numpy', 'PIL', 'scipy'],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe_kwargs = dict(
    name='sqlmap-sidecar',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)

# Only set target_arch on macOS (other platforms don't support it)
if platform.system() == 'Darwin':
    machine = platform.machine().lower()
    if machine in ('arm64', 'aarch64'):
        exe_kwargs['target_arch'] = 'arm64'
    elif machine in ('x86_64', 'amd64'):
        exe_kwargs['target_arch'] = 'x86_64'

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    **exe_kwargs,
)
