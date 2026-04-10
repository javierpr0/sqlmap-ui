"""
Entry point for PyInstaller bundle.
Patches broken MySQLdb, overrides modulePath for frozen builds, then runs sqlmap.
"""
import sys
import os
import types

# Block broken MySQLdb import
fake_mysqldb = types.ModuleType("MySQLdb")
fake_mysqldb.version_info = (0, 0, 0)
fake_mysqldb._mysql = types.ModuleType("MySQLdb._mysql")
fake_mysqldb._mysql.version_info = (0, 0, 0)
fake_mysqldb._mysql.__file__ = ""
sys.modules["MySQLdb"] = fake_mysqldb
sys.modules["MySQLdb._mysql"] = fake_mysqldb._mysql

# When running as a PyInstaller bundle, _MEIPASS points to the extracted dir
if getattr(sys, 'frozen', False):
    bundle_dir = sys._MEIPASS
else:
    bundle_dir = os.path.dirname(os.path.abspath(__file__))

os.chdir(bundle_dir)
sys.path.insert(0, bundle_dir)

# Patch sqlmap's modulePath to return _MEIPASS instead of exe directory
import sqlmap as sqlmap_module
sqlmap_module.modulePath = lambda: bundle_dir

# Also patch weAreFrozen so setPaths reads from _MEIPASS
from lib.core import common as common_module
_original_modulePath = common_module.getUnicode if hasattr(common_module, 'getUnicode') else str

# Override modulePath at the common level too if it exists
if hasattr(common_module, 'modulePath'):
    common_module.modulePath = lambda: bundle_dir

sqlmap_module.main()
