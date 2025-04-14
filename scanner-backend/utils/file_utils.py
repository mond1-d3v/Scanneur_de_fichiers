import os
import hashlib
import shutil
import tempfile
import logging
import magic
from werkzeug.utils import secure_filename
from datetime import datetime

logger = logging.getLogger(__name__)

def safe_delete(filepath):
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
            logger.debug(f"Fichier supprimé: {filepath}")
    except Exception as e:
        logger.error(f"Erreur lors de la suppression du fichier {filepath}: {str(e)}")

def calculate_hash(filepath, hash_type="sha256"):
    try:
        hash_obj = hashlib.new(hash_type)
        
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
                
        return hash_obj.hexdigest()
    except Exception as e:
        logger.error(f"Erreur lors du calcul du hash {hash_type} pour {filepath}: {str(e)}")
        return None

def get_file_metadata(filepath):
    try:
        stat_info = os.stat(filepath)
        file_size = stat_info.st_size
        creation_time = datetime.fromtimestamp(stat_info.st_ctime).isoformat()
        modification_time = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
        mime_type = magic.Magic(mime=True).from_file(filepath)
        md5_hash = calculate_hash(filepath, "md5")
        sha1_hash = calculate_hash(filepath, "sha1")
        sha256_hash = calculate_hash(filepath, "sha256")
        
        return {
            "filename": os.path.basename(filepath),
            "size_bytes": file_size,
            "size_human": format_file_size(file_size),
            "mime_type": mime_type,
            "creation_time": creation_time,
            "modification_time": modification_time,
            "md5": md5_hash,
            "sha1": sha1_hash,
            "sha256": sha256_hash
        }
    except Exception as e:
        logger.error(f"Erreur lors de l'extraction des métadonnées pour {filepath}: {str(e)}")
        return {}

def format_file_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024**2:
        return f"{size_bytes/1024:.2f} KB"
    elif size_bytes < 1024**3:
        return f"{size_bytes/(1024**2):.2f} MB"
    else:
        return f"{size_bytes/(1024**3):.2f} GB"

def create_safe_temp_file(original_filename, data=None):
    try:
        safe_filename = secure_filename(original_filename)
        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, f"malware_analyzer_{safe_filename}")
        if data:
            with open(temp_path, "wb") as temp_file:
                temp_file.write(data)
        logger.debug(f"Fichier temporaire créé: {temp_path}")
        return temp_path
    except Exception as e:
        logger.error(f"Erreur lors de la création du fichier temporaire: {str(e)}")
        return None

def clean_temp_directory(temp_dir=None, older_than_days=1):
    if not temp_dir:
        temp_dir = tempfile.gettempdir()
    
    count = 0
    try:
        now = datetime.now()
        for filename in os.listdir(temp_dir):
            if filename.startswith("malware_analyzer_"):
                filepath = os.path.join(temp_dir, filename)
                file_modified = datetime.fromtimestamp(os.path.getmtime(filepath))
                if (now - file_modified).days >= older_than_days:
                    os.remove(filepath)
                    count += 1
                    logger.debug(f"Fichier temporaire supprimé: {filepath}")
        
        logger.info(f"{count} fichiers temporaires supprimés du répertoire {temp_dir}")
        return count
    
    except Exception as e:
        logger.error(f"Erreur lors du nettoyage du répertoire temporaire {temp_dir}: {str(e)}")
        return count
