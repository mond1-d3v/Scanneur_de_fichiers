import logging
from typing import List, Type, Dict
from .base_scanner import BaseScanner, ScannerException
from .batch_scanner import BatchScanner
from .pe_scanner import PEScanner
from .powershell_scanner import PowerShellScanner
from .archive_scanner import ArchiveScanner
from .python_scanner import PythonScanner
from .c_scanner import CScanner

logger = logging.getLogger(__name__)

def get_available_scanners() -> Dict[str, Type[BaseScanner]]:
    scanners = {
        "batch": BatchScanner,
        "pe": PEScanner,
        "powershell": PowerShellScanner,
        "archive": ArchiveScanner,
        "python": PythonScanner,
        "c_scanner": CScanner,
    }
    return scanners

def get_scanner_for_file(file_path: str) -> BaseScanner:
    scanners = get_available_scanners()
    for scanner_name, scanner_class in scanners.items():
        scanner = scanner_class()
        if scanner.can_scan(file_path):
            logger.debug(f"Scanner trouvé: {scanner_name}")
            return scanner
    raise ScannerException(f"Aucun scanner disponible pour {file_path}")

__all__ = [
    'BaseScanner',
    'ScannerException',
    'BatchScanner',
    'PEScanner',
    'PowerShellScanner',
    'ArchiveScanner',
    'PythonScanner',
    'CScanner',
    'get_available_scanners',
    'get_scanner_for_file'
]
