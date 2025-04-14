import os
import sys
import logging
from utils.logger import setup_logger
from datetime import datetime
import hashlib

logger = setup_logger("debug_script", log_level=logging.DEBUG)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db import get_database
from scanner.virus_scanner import VirusScanner
from config import active_config

def test_database_connection():
    try:
        db = get_database()
        if db.check_connection():
            logger.info("✅ Connexion à PocketBase réussie!")
            collections = db.list_collections()
            if collections:
                logger.info(f"Collections disponibles: {[c.get('name') for c in collections]}")
            else:
                logger.warning("Aucune collection disponible")
        else:
            logger.error("❌ Échec de la connexion à PocketBase")
    except Exception as e:
        logger.error(f"❌ Erreur lors de la connexion à PocketBase: {str(e)}")

def test_virus_scanner(file_path):
    if not os.path.isfile(file_path):
        logger.error(f"Le fichier {file_path} n'existe pas")
        return
    
    logger.info(f"Test du scanner sur le fichier: {file_path}")
    
    try:
        scanner = VirusScanner()
        result = scanner.scan(file_path)
        logger.info(f"Résultat du scan: is_malicious={result.get('is_malicious')}, score={result.get('score')}")
        logger.info(f"Menaces détectées: {len(result.get('threats', []))}")
        file_hash = scanner._compute_file_hash(file_path)
        logger.info(f"Hash du fichier: {file_hash}")
        
        db = get_database()
        if db:
            hash_record = db.find_one('file_hashes', {'sha256': file_hash})
            if hash_record:
                logger.info("✅ Enregistrement trouvé dans la collection file_hashes")
            else:
                logger.warning("❌ Aucun enregistrement trouvé dans file_hashes")
            scan_records = db.find('scan_history', {}, limit=5)
            if scan_records:
                logger.info(f"✅ {len(scan_records)} enregistrements trouvés dans scan_history")
            else:
                logger.warning("❌ Aucun enregistrement trouvé dans scan_history")
            if result.get('is_malicious'):
                patterns = db.find('malware_patterns', {}, limit=5)
                if patterns:
                    logger.info(f"✅ {len(patterns)} patterns de malware enregistrés")
                else:
                    logger.warning("❌ Aucun pattern de malware enregistré")
        
    except Exception as e:
        logger.error(f"❌ Erreur lors du test du scanner: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())

def insert_test_data():
    try:
        db = get_database()
        if not db or not db.check_connection():
            logger.error("❌ Impossible de se connecter à la base de données")
            return
        hash_data = {
            "md5": hashlib.md5(b"test").hexdigest(),
            "sha1": hashlib.sha1(b"test").hexdigest(),
            "sha256": hashlib.sha256(b"test").hexdigest(),
            "is_malicious": True,
            "malware_type": "test_malware",
            "last_analysis": datetime.now().isoformat(),
            "analysis_result": {
                "is_malicious": True,
                "score": 8,
                "threats": [
                    {"type": "test_threat", "name": "Test Threat", "severity": "high"}
                ]
            }
        }
        
        result = db.insert('file_hashes', hash_data)
        logger.info(f"✅ Données insérées dans file_hashes: {result.get('id')}")
        pattern_data = {
            "pattern_text": "test_pattern",
            "malware_type": "test_malware",
            "severity": 4,
            "file_type": "text/plain",
            "description": "Pattern de test",
            "detection_count": 1,
            "first_detected": datetime.now().isoformat(),
            "last_detected": datetime.now().isoformat()
        }
        
        result = db.insert('malware_patterns', pattern_data)
        logger.info(f"✅ Données insérées dans malware_patterns: {result.get('id')}")
        scan_data = {
            "file_name": "test.txt",
            "file_size": 1024,
            "file_type": "text/plain",
            "scan_date": datetime.now().isoformat(),
            "hash_reference": result.get('id'),
            "is_malicious": True,
            "scan_source": "test",
            "detection_details": {
                "threats_count": 1,
                "threat_types": ["test_threat"],
                "scanners_used": ["test_scanner"],
                "score": 8
            },
            "user_ip": "127.0.0.1"
        }
        result = db.insert('scan_history', scan_data)
        logger.info(f"✅ Données insérées dans scan_history: {result.get('id')}")
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'insertion des données de test: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    logger.info("=== Démarrage du script de débogage ===")
    logger.info("\n--- Test de connexion à la base de données ---")
    test_database_connection()
    logger.info("\n--- Test d'insertion de données ---")
    insert_test_data()
    logger.info("=== Fin du script de débogage ===")
