import os
import sys
import logging
import tempfile
from datetime import datetime
import random
import string

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger('test_integration')

def create_test_file(content=None):
    """Crée un fichier de test temporaire avec le contenu spécifié"""
    if content is None:
        content = ''.join(random.choice(string.ascii_letters) for _ in range(100))
    fd, temp_path = tempfile.mkstemp(suffix='.txt')
    with os.fdopen(fd, 'w') as f:
        f.write(content)
    return temp_path

def test_imports():
    try:
        logger.info("Test d'importation des modules principaux...")
        from scanner.virus_scanner import VirusScanner
        logger.info("✓ Module VirusScanner importé avec succès")
        from scanner.scanners.base_scanner import BaseScanner
        from scanner.scanners.batch_scanner import BatchScanner
        from scanner.scanners.powershell_scanner import PowerShellScanner
        from scanner.scanners.python_scanner import PythonScanner
        from scanner.scanners.pe_scanner import PEScanner
        from scanner.scanners.archive_scanner import ArchiveScanner
        logger.info("✓ Modules de scanners spécifiques importés avec succès")
        from utils.file_utils import process_uploaded_file
        from utils.hash_utils import calculate_hash
        logger.info("✓ Modules utilitaires importés avec succès")
        from api.server import app
        logger.info("✓ Module API importé avec succès")
        from db.pocketbase import authenticate
        logger.info("✓ Module PocketBase importé avec succès")
        return True
    except ImportError as e:
        logger.error(f"× Certains modules ne peuvent pas être importés: {e}")
        return False

def test_virus_scanner():
    try:
        from scanner.virus_scanner import VirusScanner
        scanner = VirusScanner()
        logger.info("✓ Scanner instantié avec succès")
        test_file = create_test_file("Ceci est un fichier de test inoffensif")
        logger.info(f"✓ Fichier de test créé: {test_file}")
        try:
            result = scanner.scan(test_file)
            logger.info(f"✓ Analyse terminée avec succès: {result}")
            assert isinstance(result, dict), "Le résultat n'est pas un dictionnaire"
            assert "is_malicious" in result, "Le résultat ne contient pas is_malicious"
            os.remove(test_file)
            logger.info("✓ Fichier de test supprimé")
            
            return True
            
        except Exception as e:
            logger.error(f"× Échec de l'analyse: {e}")
            if os.path.exists(test_file):
                os.remove(test_file)
            return False
    except Exception as e:
        logger.error(f"× Erreur lors du test du scanner: {e}")
        return False

def test_scanners():
    try:
        from scanner.scanners.batch_scanner import BatchScanner
        batch_scanner = BatchScanner()
        from scanner.scanners.powershell_scanner import PowerShellScanner
        powershell_scanner = PowerShellScanner()
        from scanner.scanners.python_scanner import PythonScanner
        python_scanner = PythonScanner()
        logger.info("✓ Tous les scanners spécifiques initialisés avec succès")
        return True
    except Exception as e:
        logger.error(f"× Erreur lors du test des scanners spécifiques: {e}")
        return False

def main():
    logger.info("=== DÉBUT DU TEST D'INTÉGRATION ===")
    if not test_imports():
        logger.error("× Test d'importation échoué")
        return 1
    logger.info("✓ Test d'importation réussi")
    if not test_virus_scanner():
        logger.error("× Test du scanner principal échoué")
        return 1
    logger.info("✓ Test du scanner principal réussi")
    if not test_scanners():
        logger.error("× Test des scanners spécifiques échoué")
        return 1
    logger.info("✓ Test des scanners spécifiques réussi")
    logger.info("=== TEST D'INTÉGRATION RÉUSSI ===")
    return 0

if __name__ == "__main__":
    sys.exit(main())
