import os
import secrets
from dotenv import load_dotenv

load_dotenv()

MAX_UPLOAD_SIZE_MB = int(os.environ.get('MAX_UPLOAD_SIZE_MB', 50)) 

class Config:
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 5000))
    DEBUG = os.environ.get('DEBUG', 'False').lower() in ('true', '1', 't')
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads'))
    TEMP_FOLDER = os.environ.get('TEMP_FOLDER', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'temp'))
    LOG_FOLDER = os.environ.get('LOG_FOLDER', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs'))
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', 'VOTRE_CLE_API_VIRUSTOTAL')
    ANALYSIS_TIMEOUT = int(os.environ.get('ANALYSIS_TIMEOUT', 60)) 
    MALWARE_SCORE_THRESHOLD = int(os.environ.get('MALWARE_SCORE_THRESHOLD', 7)) 
    MAX_CONTENT_LENGTH = MAX_UPLOAD_SIZE_MB * 1024 * 1024 
    POCKETBASE_URL = os.environ.get('POCKETBASE_URL', 'http://ADRESSE_IP_POCKETBASE:8080')
    POCKETBASE_EMAIL = os.environ.get('POCKETBASE_EMAIL', 'Identifiant')
    POCKETBASE_PASSWORD = os.environ.get('POCKETBASE_PASSWORD', 'Mot_de_passe')
    PB_COLLECTION_MALWARE_PATTERNS = 'malware_patterns'
    PB_COLLECTION_FILE_HASHES = 'file_hashes'
    PB_COLLECTION_SCAN_HISTORY = 'scan_history'
    MALWARE_SEVERITY_THRESHOLD = int(os.environ.get('MALWARE_SEVERITY_THRESHOLD', 3)) 
    SIGNATURE_MATCH_THRESHOLD = float(os.environ.get('SIGNATURE_MATCH_THRESHOLD', 0.75))  
    TEMP_FILES_MAX_AGE = int(os.environ.get('TEMP_FILES_MAX_AGE', 3600))


class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False
    MAX_CONTENT_LENGTH = int(os.environ.get('DEV_MAX_UPLOAD_SIZE_MB', 100)) * 1024 * 1024


class TestingConfig(Config):
    DEBUG = True
    TESTING = True
    POCKETBASE_URL = os.environ.get('TEST_POCKETBASE_URL', 'http://localhost:8080')
    TEMP_FOLDER = os.environ.get('TEST_TEMP_FOLDER', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_temp'))
    MAX_CONTENT_LENGTH = int(os.environ.get('TEST_MAX_UPLOAD_SIZE_MB', 20)) * 1024 * 1024


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    MAX_CONTENT_LENGTH = int(os.environ.get('PROD_MAX_UPLOAD_SIZE_MB', 50)) * 1024 * 1024
    def __init__(self):
        super().__init__()
        if not os.environ.get('SECRET_KEY'):
            raise ValueError("SECRET_KEY doit être défini en production")
        if not os.environ.get('POCKETBASE_URL'):
            raise ValueError("POCKETBASE_URL doit être défini en production")
        if not os.environ.get('POCKETBASE_EMAIL'):
            raise ValueError("POCKETBASE_EMAIL doit être défini en production")
        if not os.environ.get('POCKETBASE_PASSWORD'):
            raise ValueError("POCKETBASE_PASSWORD doit être défini en production")


config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

active_config = config_by_name[os.environ.get('FLASK_ENV', 'default')]() 
