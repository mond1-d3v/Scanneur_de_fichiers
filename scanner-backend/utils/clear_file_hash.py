import os
import sys
import hashlib
import argparse
import logging
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import get_database


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def calculate_hash(file_path, hash_type="sha256"):
    try:
        hash_func = getattr(hashlib, hash_type)()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
                
        return hash_func.hexdigest()
    except Exception as e:
        logger.error(f"Erreur lors du calcul du hash {hash_type} pour {file_path}: {str(e)}")
        return None

def clear_hash_from_db(hash_value=None, file_path=None):
    try:
        db = get_database()
        if not db:
            logger.error("Impossible de se connecter à la base de données")
            return False
        
        if file_path and not hash_value:
            hash_value = calculate_hash(file_path)
            if not hash_value:
                logger.error(f"Impossible de calculer le hash pour {file_path}")
                return False
        if not hash_value:
            logger.error("Aucun hash fourni et aucun fichier à partir duquel calculer un hash")
            return False
        logger.info(f"Recherche du hash {hash_value} dans la base de données")
        record = db.find_one('file_hashes', {'sha256': hash_value})
        if not record:
            logger.info(f"Hash {hash_value} non trouvé dans la base de données")
            return False
        logger.info(f"Suppression du hash {hash_value} (ID: {record.get('id')})")
        db.delete('file_hashes', record.get('id'))
        logger.info(f"Hash {hash_value} supprimé avec succès")
        time.sleep(1)
        check_record = db.find_one('file_hashes', {'sha256': hash_value})
        if check_record:
            logger.warning(f"Le hash {hash_value} existe toujours dans la base de données")
            return False
        return True
    except Exception as e:
        logger.error(f"Erreur lors de la suppression du hash: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return False

def main():
    parser = argparse.ArgumentParser(description="Supprimer des entrées de hashes spécifiques de la base de données")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Chemin vers le fichier dont le hash doit être supprimé")
    group.add_argument("-s", "--hash", help="Valeur du hash SHA256 à supprimer")
    args = parser.parse_args()
    if args.file:
        if not os.path.isfile(args.file):
            logger.error(f"Le fichier {args.file} n'existe pas")
            sys.exit(1)
        file_hash = calculate_hash(args.file)
        if not file_hash:
            logger.error(f"Impossible de calculer le hash pour {args.file}")
            sys.exit(1)
        logger.info(f"Hash calculé pour {args.file}: {file_hash}")
        if clear_hash_from_db(hash_value=file_hash):
            logger.info(f"Hash {file_hash} supprimé avec succès de la base de données")
            print(f"Hash {file_hash} supprimé avec succès")
        else:
            logger.error(f"Échec de la suppression du hash {file_hash}")
            print(f"Échec de la suppression du hash {file_hash}")
            sys.exit(1)
    else:
        if clear_hash_from_db(hash_value=args.hash):
            logger.info(f"Hash {args.hash} supprimé avec succès de la base de données")
            print(f"Hash {args.hash} supprimé avec succès")
        else:
            logger.error(f"Échec de la suppression du hash {args.hash}")
            print(f"Échec de la suppression du hash {args.hash}")
            sys.exit(1)

if __name__ == "__main__":
    main()
