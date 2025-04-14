from .scanners.base_scanner import BaseScanner
from .scanners.batch_scanner import BatchScanner
from .scanners.powershell_scanner import PowerShellScanner
from .scanners.python_scanner import PythonScanner
from .scanners.pe_scanner import PEScanner
from .scanners.archive_scanner import ArchiveScanner
from .scanners.virustotal_scanner import VirusTotalScanner
from .scanners.pocketbase_scanner import PocketBaseScanner
from .scanners.c_scanner import CScanner
from .scanners.javascript_scanner import JavaScriptScanner
from .scanners.java_scanner import JavaScanner

_AVAILABLE_SCANNERS = {
    'batch': BatchScanner,
    'powershell': PowerShellScanner,
    'python': PythonScanner,
    'pe': PEScanner,
    'archive': ArchiveScanner,
    'virustotal': VirusTotalScanner,
    'pocketbase': PocketBaseScanner,
    'c_scanner': CScanner,
    'javascript': JavaScriptScanner,
    'java': JavaScanner,
}

def get_scanner(scanner_type: str):
    if scanner_type == "batch":
        from .scanners.batch_scanner import BatchScanner
        return BatchScanner()
    elif scanner_type == "powershell":
        from .scanners.powershell_scanner import PowerShellScanner
        return PowerShellScanner()
    elif scanner_type == "python":
        from .scanners.python_scanner import PythonScanner
        return PythonScanner()
    elif scanner_type == "pe":
        from .scanners.pe_scanner import PEScanner
        return PEScanner()
    elif scanner_type == "archive":
        from .scanners.archive_scanner import ArchiveScanner
        return ArchiveScanner()
    elif scanner_type == "virustotal":
        from .scanners.virustotal_scanner import VirusTotalScanner
        return VirusTotalScanner()
    elif scanner_type == "pocketbase":
        from .scanners.pocketbase_scanner import PocketBaseScanner
        return PocketBaseScanner()
    elif scanner_type == "c_scanner":
        from .scanners.c_scanner import CScanner
        return CScanner()
    elif scanner_type == "javascript":
        from .scanners.javascript_scanner import JavaScriptScanner
        return JavaScriptScanner()
    elif scanner_type == "java":
        from .scanners.java_scanner import JavaScanner
        return JavaScanner()
    elif scanner_type == "virus":
        from .virus_scanner import VirusScanner
        return VirusScanner()
    else:
        raise ValueError(f"Type de scanner inconnu: {scanner_type}")


def list_available_scanners():
    return ['virus', 'batch', 'powershell', 'python', 'pe', 'archive', 'virustotal', 
            'pocketbase', 'c_scanner', 'javascript', 'java']

__all__ = [
    'BaseScanner', 'BatchScanner', 'PowerShellScanner', 
    'PythonScanner', 'PEScanner', 'ArchiveScanner', 'VirusTotalScanner', 'PocketBaseScanner',
    'CScanner', 'JavaScriptScanner', 'JavaScanner', 'get_scanner', 'list_available_scanners'
]