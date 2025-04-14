__version__ = '0.1.0'

from api.server import create_app
from api.routes import setup_routes
from db.database import Database
from db.pocketbase import PocketBase
from db import get_database
from scanner.virus_scanner import VirusScanner
from scanner.scanners.base_scanner import BaseScanner
from scanner.scanners.batch_scanner import BatchScanner
from scanner.scanners.powershell_scanner import PowerShellScanner
from scanner.scanners.python_scanner import PythonScanner
from scanner.scanners.pe_scanner import PEScanner
from scanner.scanners.archive_scanner import ArchiveScanner


try:
    from utils.file_utils import (
        safe_delete, 
        calculate_hash, 
        get_file_metadata, 
        create_safe_temp_file, 
        clean_temp_directory
    )
    from utils.hash_utils import (
        validate_hash_format,
        normalize_hash,
        hash_to_filename,
        hash_id_to_path_segments,
        calculate_file_hashes,
        generate_hmac_signature,
        verify_hmac_signature
    )
    from utils.logger import setup_logger, get_logger, LogContext, VERBOSE, NOTICE
except ImportError:
    pass

import config

__all__ = [
    'create_app',
    'setup_routes',
    'Database', 
    'PocketBase',
    'get_database',
    'VirusScanner',
    'BaseScanner',
    'BatchScanner',
    'PowerShellScanner',
    'PythonScanner',
    'PEScanner',
    'ArchiveScanner',
    'safe_delete',
    'calculate_hash',
    'get_file_metadata',
    'create_safe_temp_file',
    'clean_temp_directory',
    'validate_hash_format',
    'normalize_hash',
    'hash_to_filename',
    'hash_id_to_path_segments',
    'calculate_file_hashes',
    'generate_hmac_signature',
    'verify_hmac_signature',
    'setup_logger',
    'get_logger',
    'LogContext',
    'VERBOSE',
    'NOTICE',
    'config'
]
