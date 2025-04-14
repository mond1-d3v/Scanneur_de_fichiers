import sys
import os
from time import time
import logging
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import setup_logger
from db.pocketbase import PocketBase
from config import active_config

logger = setup_logger("pb_connection_test", log_level=logging.INFO)
SUCCESS_MARK = "[OK]" 
FAIL_MARK = "[FAIL]"

def test_pocketbase_connection():
    logger.info(f"Test de connexion à PocketBase - URL: {active_config.POCKETBASE_URL}")
    try:
        start_time = time()
        pb = PocketBase(
            base_url=active_config.POCKETBASE_URL,
            email=active_config.POCKETBASE_EMAIL,
            password=active_config.POCKETBASE_PASSWORD
        )
        auth_result = pb.authenticate()
        if auth_result and hasattr(pb, 'token') and pb.token:
            logger.info(f"{SUCCESS_MARK} Authentification réussie auprès de PocketBase")
        else:
            logger.error(f"{FAIL_MARK} Échec de l'authentification - Token non reçu")
            return False
        collections_info = pb.list_collections()
        if not collections_info:
            logger.warning(f"{FAIL_MARK} Aucune collection trouvée ou échec de récupération des collections")
            return False
        logger.info(f"{SUCCESS_MARK} {len(collections_info)} collections trouvées:")
        for collection in collections_info:
            logger.info(f"  - {collection.get('name', 'Nom inconnu')} (ID: {collection.get('id', 'ID inconnu')})")
        required_collections = [
            active_config.PB_COLLECTION_MALWARE_PATTERNS,
            active_config.PB_COLLECTION_FILE_HASHES,
            active_config.PB_COLLECTION_SCAN_HISTORY
        ]
        collection_names = [c.get('name') for c in collections_info]
        for required in required_collections:
            if required in collection_names:
                logger.info(f"{SUCCESS_MARK} Collection requise trouvée: {required}")
            else:
                logger.warning(f"{FAIL_MARK} Collection requise non trouvée: {required}")
        response_time = time() - start_time
        logger.info(f"{SUCCESS_MARK} Test terminé en {response_time:.3f} secondes")
        return True
    except Exception as e:
        logger.error(f"{FAIL_MARK} Erreur lors de la connexion à PocketBase: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_pocketbase_connection()
    if success:
        logger.info(f"{SUCCESS_MARK} Le test de connexion à PocketBase a été complété avec succès!")
        sys.exit(0)
    else:
        logger.error(f"{FAIL_MARK} Le test de connexion à PocketBase a échoué")
        sys.exit(1)
