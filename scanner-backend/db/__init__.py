import os
import logging
from typing import Optional
from db.database import Database, DatabaseError

try:
    from db.pocketbase import PocketBase
    POCKETBASE_AVAILABLE = True
except ImportError:
    POCKETBASE_AVAILABLE = False

logger = logging.getLogger(__name__)

_db_instance = None

def get_database() -> Optional[Database]:
    global _db_instance
    if _db_instance is not None:
        if _db_instance.check_connection():
            return _db_instance
        else:
            if not _db_instance.connect():
                _db_instance = None
    try:
        try:
            from config import active_config
            pocketbase_url = active_config.POCKETBASE_URL
            pocketbase_email = active_config.POCKETBASE_EMAIL
            pocketbase_password = active_config.POCKETBASE_PASSWORD
        except ImportError:
            pocketbase_url = os.environ.get('POCKETBASE_URL', 'http://localhost:8080')
            pocketbase_email = os.environ.get('POCKETBASE_EMAIL', '')
            pocketbase_password = os.environ.get('POCKETBASE_PASSWORD', '')
        if not pocketbase_url:
            return None
        if POCKETBASE_AVAILABLE:
            _db_instance = PocketBase(
                url=pocketbase_url,
                email=pocketbase_email,
                password=pocketbase_password
            )
            if not _db_instance.connect():
                _db_instance = None
        else:
            _db_instance = None
        return _db_instance
    except Exception:
        return None

def close_database():
    global _db_instance
    if _db_instance is not None:
        try:
            _db_instance.close()
        except Exception:
            pass
        _db_instance = None

__all__ = [
    'Database',
    'PocketBase',
    'DatabaseError',
    'get_database',
    'close_database'
]
