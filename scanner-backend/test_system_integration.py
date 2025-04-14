import sys
import os
import tempfile
import logging
import time
import hashlib
import traceback
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import setup_logger
from config import active_config

SUCCESS_MARK = "[OK]" 
FAIL_MARK = "[FAIL]"

logger = setup_logger("system_integration_test", log_level=logging.INFO)

def create_test_file(content="Test content", suffix=".txt"):
    try:
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        temp_file.write(content.encode('utf-8'))
        temp_file.close()
        logger.debug(f"Fichier de test créé: {temp_file.name}")
        return temp_file.name
    except Exception as e:
        logger.error(f"{FAIL_MARK} Erreur lors de la création du fichier de test: {str(e)}")
        return None

def test_file_processing():
    logger.info("Démarrage des tests d'intégration du système")
    
    try:
        test_file_path = create_test_file("@echo off\necho Test batch file\npause", suffix=".bat")
        
        if not test_file_path:
            logger.error(f"{FAIL_MARK} Échec de la création du fichier de test")
            return False
        
        logger.info(f"{SUCCESS_MARK} Fichier de test créé: {test_file_path}")
        file_hash = None
        with open(test_file_path, "rb") as f:
            file_bytes = f.read()
            file_hash = hashlib.sha256(file_bytes).hexdigest()
        
        logger.info(f"{SUCCESS_MARK} Hash SHA-256 calculé: {file_hash}")
        from scanner import get_scanner
        
        logger.info(f"{SUCCESS_MARK} Module scanner importé avec succès")
        
        try:
            virus_scanner = get_scanner("virus")
            logger.info(f"{SUCCESS_MARK} Scanner créé avec succès: {virus_scanner.name}")
        except Exception as e:
            logger.error(f"{FAIL_MARK} Échec de la création du scanner: {str(e)}")
            logger.error(traceback.format_exc())
            return False
        try:
            start_time = time.time()
            scan_result = virus_scanner.scan(test_file_path)
            end_time = time.time()
            
            logger.info(f"{SUCCESS_MARK} Analyse terminée en {end_time - start_time:.2f} secondes")
            logger.info(f"{SUCCESS_MARK} Résultat du scan: {scan_result.get('message', 'Inconnu')}")
        except Exception as e:
            logger.error(f"{FAIL_MARK} Échec de l'analyse du fichier: {str(e)}")
            logger.error(traceback.format_exc())
            return False
        for scanner_type in ['batch', 'powershell', 'python', 'pe', 'archive']:
            try:
                scanner = get_scanner(scanner_type)
                if scanner.can_scan(test_file_path):
                    scanner_result = scanner.scan(test_file_path)
                    logger.info(f"{SUCCESS_MARK} Scanner {scanner_type} testé avec succès")
                else:
                    logger.info(f"{SUCCESS_MARK} Scanner {scanner_type} ne peut pas analyser ce type de fichier (normal)")
            except Exception as e:
                logger.warning(f"Attention: Scanner {scanner_type} a échoué: {str(e)}")
        try:
            os.unlink(test_file_path)
            logger.info(f"{SUCCESS_MARK} Nettoyage du fichier temporaire réussi")
        except Exception as e:
            logger.warning(f"Attention lors du nettoyage du fichier temporaire: {str(e)}")
        
        return True
        
    except Exception as e:
        logger.error(f"{FAIL_MARK} Erreur lors des tests d'intégration: {str(e)}")
        logger.error(traceback.format_exc())
        return False

if __name__ == "__main__":
    success = test_file_processing()
    if success:
        logger.info(f"{SUCCESS_MARK} Tous les tests d'intégration ont réussi!")
        sys.exit(0)
    else:
        logger.error(f"{FAIL_MARK} Les tests d'intégration ont échoué")
        sys.exit(1)
