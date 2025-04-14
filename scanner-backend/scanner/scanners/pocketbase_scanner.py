import hashlib
import logging
from datetime import datetime
from typing import Dict, Any, Optional

from .base_scanner import BaseScanner
from db import get_database, DatabaseError

logger = logging.getLogger(__name__)

class PocketBaseScanner(BaseScanner):    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__()
        self.name = "PocketBaseScanner"
        try:
            self.db = get_database()
            logger.info("Scanner PocketBase initialisé avec succès")
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation du scanner PocketBase: {str(e)}")
            self.db = None
    
    def can_scan(self, file_path):
        return True

    def scan(self, file_path: str) -> Dict[str, Any]:
        file_hash = self._calculate_hash(file_path)
        
        if not self.db:
            return {
                "scanner": self.name,
                "is_malicious": False,
                "score": 0,
                "message": "Scanner PocketBase non disponible",
                "threats": [],
                "error": "Base de données non disponible",
                "file_path": file_path,
                "file_hash": file_hash
            }
            
        try:
            query = {"sha256": file_hash}
            hash_record = self.db.find_one("file_hashes", query)
            
            if hash_record:
                is_malicious = hash_record.get("is_malicious", False)
                malware_type = hash_record.get("malware_type", "Unknown")
                score = hash_record.get("score", 0)
                try:
                    update_data = {
                        "last_analysis": datetime.now().isoformat()
                    }
                    self.db.update("file_hashes", hash_record["id"], update_data)
                except Exception as e:
                    logger.error(f"Erreur lors de la mise à jour du timestamp : {str(e)}")
                if is_malicious:
                    threat = {
                        "type": "hash_match",
                        "name": malware_type,
                        "category": "malicious"
                    }
                    message = f"Fichier connu comme malveillant dans la base de données"
                    return {
                        "scanner": self.name,
                        "is_malicious": True,
                        "score": score,
                        "message": message,
                        "threats": [threat],
                        "error": None,
                        "file_path": file_path,
                        "file_hash": file_hash
                    }
                else:
                    return {
                        "scanner": self.name,
                        "is_malicious": False,
                        "score": 0,
                        "message": "Fichier connu comme sûr dans la base de données",
                        "threats": [],
                        "error": None,
                        "file_path": file_path,
                        "file_hash": file_hash
                    }
            return {
                "scanner": self.name,
                "is_malicious": False,
                "score": 0,
                "message": "Fichier non trouvé dans la base de données",
                "threats": [],
                "error": None,
                "file_path": file_path,
                "file_hash": file_hash,
                "is_new_file": True
            }
                
        except DatabaseError as e:
            logger.error(f"Erreur lors de la vérification dans la base de données: {str(e)}")
            return {
                "scanner": self.name,
                "is_malicious": False,
                "score": 0,
                "message": "Erreur lors de la vérification du hash dans la base de données",
                "threats": [],
                "error": str(e),
                "file_path": file_path,
                "file_hash": file_hash
            }
    
    def _calculate_hash(self, file_path: str) -> str:
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256()
                for chunk in iter(lambda: f.read(4096), b""):
                    file_hash.update(chunk)
            return file_hash.hexdigest()
        except Exception as e:
            logger.error(f"Erreur lors du calcul du hash: {str(e)}")
            return ""
