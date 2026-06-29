# SoftwareSecurityAuditor.spec
# One-folder PyInstaller build (avoids antivirus false positives from one-file mode).
# Build with:  pyinstaller SoftwareSecurityAuditor.spec --clean

from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files

block_cipher = None
ROOT = Path(SPECPATH)

datas = [
    (str(ROOT / "templates"), "templates"),
    (str(ROOT / "assets"),    "assets"),
    *collect_data_files("reportlab"),   # includes reportlab/fonts/ needed for PDF generation
]

hiddenimports = [
    "flask", "flask.json.provider",
    "jinja2", "jinja2.ext",
    "markupsafe", "markupsafe._speedups",
    "werkzeug.security", "werkzeug.serving", "werkzeug.routing",
    "click", "itsdangerous", "blinker",
    "reportlab.pdfbase", "reportlab.pdfbase.pdfmetrics",
    "reportlab.pdfbase.ttfonts", "reportlab.pdfbase._fontdata",
    "reportlab.lib.utils", "reportlab.platypus",
    "reportlab.graphics.renderPDF", "reportlab.rl_config",
    "pypdf", "pypdf.generic", "pypdf._codecs",
    "pypdf._crypt_providers", "pypdf._crypt_providers._fallback",
    "PIL", "PIL.Image", "PIL.PngImagePlugin", "PIL.JpegImagePlugin",
    "sqlite3", "_sqlite3",
]

a = Analysis(
    [str(ROOT / "app.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["pytest", "unittest", "tkinter", "matplotlib", "numpy"],
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="SoftwareSecurityAuditor",
    debug=False,
    strip=False,
    upx=False,       # UPX triggers Windows Defender — leave off
    console=False,   # no black terminal window; set True temporarily to debug startup errors
    icon=None,       # optional: str(ROOT / "assets" / "app.ico")
)

coll = COLLECT(
    exe, a.binaries, a.zipfiles, a.datas,
    strip=False, upx=False,
    name="SoftwareSecurityAuditor",   # output: dist\SoftwareSecurityAuditor\
)
