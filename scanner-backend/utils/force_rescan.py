import sys
import os
import argparse
import hashlib
import logging
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db import get_database
from scanner.virus_scanner import VirusScanner
from utils.logger import setup_logger

logger = setup_logger(
    app_name="force_rescan",
    log_dir="logs",
    log_level=logging.INFO
)

def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def clear_file_from_cache(file_path):
    try:
        file_hash = calculate_hash(file_path)
        db = get_database()
        if not db:
            logger.error("Impossible de se connecter à la base de données")
            return False
        record = db.find_one('file_hashes', {'sha256': file_hash})
        if not record:
            logger.info(f"Aucune entrée trouvée pour le fichier {file_path} avec le hash {file_hash}")
            return False
        db.delete('file_hashes', record.get('id'))
        logger.info(f"Entrée supprimée pour le hash {file_hash}")
        time.sleep(1)
        check_record = db.find_one('file_hashes', {'sha256': file_hash})
        if check_record:
            logger.warning(f"L'entrée pour le hash {file_hash} existe toujours dans la base de données")
            return False
        return True
    except Exception as e:
        logger.error(f"Erreur lors de la suppression du fichier du cache: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return False

def force_rescan_file(file_path):
    if not os.path.exists(file_path):
        logger.error(f"Le fichier {file_path} n'existe pas")
        return None
    logger.info(f"Préparation pour la réanalyse forcée de {file_path}")
    cleared = clear_file_from_cache(file_path)
    if cleared:
        logger.info(f"Entrée du cache supprimée pour {file_path}")
    else:
        logger.warning(f"Impossible de supprimer l'entrée du cache pour {file_path} ou aucune entrée trouvée")
    scanner = VirusScanner()
    result = scanner.scan(file_path)
    return result

def main():
    parser = argparse.ArgumentParser(description="Force la réanalyse d'un fichier en ignorant le cache")
    parser.add_argument("file_path", help="Chemin vers le fichier à réanalyser")
    parser.add_argument("--show-details", "-d", action="store_true", help="Afficher les détails complets de l'analyse")
    args = parser.parse_args()
    result = force_rescan_file(args.file_path)
    if result:
        print(f"\nRésultat de l'analyse de {os.path.basename(args.file_path)}:")
        print(f"Malveillant: {'OUI' if result.get('is_malicious') else 'NON'}")
        print(f"Score: {result.get('score')}/10")
        print(f"Message: {result.get('message')}")
        threats = result.get('threats', [])
        if threats:
            print(f"\nMenaces détectées ({len(threats)}):")
            for i, threat in enumerate(threats, 1):
                print(f"  {i}. {threat.get('name')} (Sévérité: {threat.get('severity', 'inconnue')})")
                print(f"     {threat.get('description')}")
        else:
            print("\nAucune menace détectée")
        if args.show_details and 'scan_details' in result:
            import json
            print("\nDétails complets de l'analyse:")
            print(json.dumps(result.get('scan_details', {}), indent=2))
    else:
        print(f"Échec de l'analyse de {args.file_path}")
        
if __name__ == "__main__":
    main()
