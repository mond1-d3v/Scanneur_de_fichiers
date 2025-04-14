from datetime import datetime
import hashlib
import os
import logging
import mimetypes
from typing import Dict, Any, Optional
from db import get_database
from scanner.scanners.base_scanner import BaseScanner
import socket
import re

logger = logging.getLogger(__name__)

class VirusScanner(BaseScanner):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__()
        self.name = "Virus Scanner"
        self.description = "Scanner de virus générique multi-moteurs"
        self.logger = logging.getLogger(__name__)
        self.config = {
            "threshold": 1,
            "fast_mode": False,
            "max_workers": 3,
        }
        if config:
            self.config.update(config)
        try:
            self.db = get_database()
            self.logger.info("Connexion à la base de données établie")
        except Exception as e:
            self.logger.error(f"Erreur de connexion à la base de données: {str(e)}")
            self.db = None

    def can_scan(self, file_path: str) -> bool:
        return os.path.isfile(file_path)

    def _get_file_type(self, file_path: str) -> str:
        mime_type, _ = mimetypes.guess_type(file_path)
        return mime_type or 'application/octet-stream'

    def scan(self, file_path: str) -> Dict[str, Any]:
        self.logger.info(f"Démarrage de l'analyse pour le fichier: {file_path}")
        if not os.path.isfile(file_path):
            self.logger.error(f"Le fichier {file_path} n'existe pas")
            return {
                "error": f"Le fichier {file_path} n'existe pas",
                "is_malicious": False,
                "score": 0,
                "threats": []
            }
        file_hash = self._compute_file_hash(file_path)
        is_js_file = file_path.lower().endswith(('.js', '.mjs', '.jsx', '.ts', '.cjs')) or self._get_file_type(file_path) in ['application/javascript', 'text/javascript']
        is_c_file = file_path.lower().endswith(('.c', '.cpp', '.h', '.hpp'))
        is_dll_file = file_path.lower().endswith('.dll')
        force_rescan = is_js_file or is_c_file or is_dll_file
        if self.db and not force_rescan:
            try:
                existing_record = self.db.find_one('file_hashes', {'sha256': file_hash})
                if existing_record:
                    self.logger.info(f"Fichier déjà analysé: {file_hash}")
                    result = existing_record.get('analysis_result', {})
                    result['scan_date'] = datetime.now().isoformat()
                    return result
            except Exception as e:
                self.logger.error(f"Erreur lors de la vérification du hash: {str(e)}")

        if force_rescan:
            if is_js_file:
                self.logger.info(f"Fichier JavaScript détecté, réalisation d'une nouvelle analyse complète.")
            elif is_c_file:
                self.logger.info(f"Fichier C/C++ détecté, réalisation d'une nouvelle analyse complète.")
            elif is_dll_file:
                self.logger.info(f"Fichier DLL détecté, réalisation d'une nouvelle analyse complète.")

        result = self._redirect_to_scanner(file_path)
        if self.db and result:
            try:
                self._save_scan_results(result, file_path, file_hash)
                self.logger.info(f"Résultats d'analyse sauvegardés pour {file_hash}")
            except Exception as e:
                self.logger.error(f"Erreur lors de la sauvegarde des résultats: {str(e)}")

        return result

    def _redirect_to_scanner(self, file_path: str) -> Dict[str, Any]:
        file_type = self._get_file_type(file_path)
        self.logger.info(f"Redirection du fichier {file_path} (type: {file_type}) vers les scanners spécifiques")
        from scanner import get_scanner
        scanners_to_use = []
        force_full_analysis = True
        is_js_file = file_path.lower().endswith(('.js', '.mjs', '.jsx', '.ts', '.cjs')) or file_type in ['application/javascript', 'text/javascript']
        if is_js_file:
            self.logger.info(f"Fichier JavaScript détecté: {file_path}")
            scanners_to_use.append('javascript')
            scanners_to_use.append('virustotal')
            self.js_file = True
        elif file_type == 'text/x-python' or file_path.endswith('.py'):
            scanners_to_use.append('python')
        elif file_type == 'text/plain' and file_path.endswith('.ps1'):
            scanners_to_use.append('powershell')
        elif file_type == 'text/plain' and (file_path.endswith('.bat') or file_path.endswith('.cmd')):
            scanners_to_use.append('batch')
        elif file_path.endswith(('.java', '.jsp', '.jar', '.class')):
            scanners_to_use.append('java')
            scanners_to_use.append('virustotal')
        elif file_type == 'application/x-msdownload' or file_path.endswith(('.exe', '.dll', '.sys', '.ocx')):
            scanners_to_use.append('pe')
            if file_path.endswith('.dll'):
                scanners_to_use.append('virustotal')
                self.dll_file = True
        elif file_path.endswith(('.c', '.cpp', '.h', '.hpp')):
            scanners_to_use.append('c_scanner')
            scanners_to_use.append('virustotal')
            self.c_file = True
        elif file_type in ['application/zip', 'application/x-rar-compressed'] or \
             file_path.endswith(('.zip', '.rar', '.7z')):
            scanners_to_use.append('archive')
        if not scanners_to_use:
            scanners_to_use = ['batch', 'python', 'powershell', 'pe', 'c_scanner', 'javascript', 'java']
        if 'virustotal' not in scanners_to_use:
            scanners_to_use.append('virustotal')
        self.dll_file = file_path.endswith('.dll')
        self.c_file = file_path.endswith(('.c', '.cpp', '.h', '.hpp'))
        self.js_file = file_path.endswith(('.js', '.mjs', '.jsx'))
        self.java_file = file_path.endswith(('.java', '.jsp', '.jar', '.class'))
        combined_result = {
            "file_path": file_path,
            "file_type": file_type,
            "is_malicious": False,
            "score": 0,
            "threats": [],
            "scan_date": datetime.now().isoformat(),
            "scanner_results": {}
        }
        total_score = 0
        scanner_count = 0
        for scanner_type in scanners_to_use:
            try:
                scanner = get_scanner(scanner_type)
                if scanner and scanner.can_scan(file_path):
                    self.logger.info(f"Analyse avec le scanner {scanner_type}")
                    result = scanner.scan(file_path)
                    combined_result["scanner_results"][scanner_type] = result
                    if result.get('is_malicious', False):
                        combined_result['is_malicious'] = True
                    current_score = result.get('score', 0)
                    if current_score > 0:
                        total_score += current_score
                        scanner_count += 1
                    if 'threats' in result and result['threats']:
                        for threat in result['threats']:
                            if threat not in combined_result['threats']:
                                combined_result['threats'].append(threat)
                    self.logger.info(f"Résultat du scanner {scanner_type}: is_malicious={result.get('is_malicious')}, score={current_score}")
                else:
                    self.logger.info(f"Le scanner {scanner_type} ne peut pas analyser ce fichier")
            except Exception as e:
                self.logger.error(f"Erreur lors de l'analyse avec {scanner_type}: {str(e)}")
        if scanner_count > 0:
            avg_score = total_score / scanner_count
            if combined_result["is_malicious"] and avg_score < 7:
                avg_score = 7
            if self.dll_file and avg_score >= 3:
                combined_result["is_malicious"] = True
                avg_score = max(avg_score, 7)
            if self.c_file and avg_score >= 3:
                combined_result["is_malicious"] = True
                avg_score = max(avg_score, 7)
            combined_result['score'] = round(avg_score, 1)
        else:
            combined_result['score'] = 0
        if combined_result["is_malicious"]:
            threat_count = len(combined_result['threats'])
            if (threat_count > 0):
                combined_result['message'] = f"Fichier malveillant! {threat_count} menaces détectées."
            else:
                combined_result['message'] = "Le fichier est considéré comme malveillant!"
        else:
            combined_result['message'] = "Analyse complétée avec succès. Aucune menace détectée."
        return combined_result

    def list_available_scanners(self):
        from scanner import list_available_scanners
        return list_available_scanners()

    def _compute_file_hash(self, file_path: str) -> str:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _save_scan_results(self, result: Dict[str, Any], file_path: str, file_hash: str):
        if not self.db:
            self.logger.warning("Base de données non disponible, impossible d'enregistrer les résultats")
            return
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        file_type = result.get("file_type", "unknown")
        is_malicious = result.get("is_malicious", False)
        md5_hash = self._compute_file_hash_md5(file_path)
        sha1_hash = self._compute_file_hash_sha1(file_path)
        malware_type = "unknown"
        if is_malicious and result.get("threats"):
            for threat in result.get("threats", []):
                threat_type = threat.get("type", "")
                if threat_type and threat_type != "malicious_code":
                    malware_type = threat_type
                    break
        now_isoformat = datetime.now().isoformat()
        hash_data = {
            "md5": md5_hash,
            "sha1": sha1_hash,
            "sha256": file_hash,
            "is_malicious": is_malicious,
            "malware_type": malware_type if is_malicious else "",
            "last_analysis": now_isoformat,
            "analysis_result": result
        }
        existing_hash = self.db.find_one('file_hashes', {'sha256': file_hash})
        hash_id = None
        if existing_hash:
            self.db.update('file_hashes', existing_hash['id'], hash_data)
            hash_id = existing_hash['id']
            self.logger.info(f"Hash mis à jour: {file_hash}")
        else:
            insert_result = self.db.insert('file_hashes', hash_data)
            hash_id = insert_result.get('id')
            self.logger.info(f"Nouveau hash enregistré: {file_hash}")

    def _compute_file_hash_md5(self, file_path: str) -> str:
        md5_hash = hashlib.md5()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                md5_hash.update(byte_block)
        return md5_hash.hexdigest()

    def _compute_file_hash_sha1(self, file_path: str) -> str:
        sha1_hash = hashlib.sha1()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha1_hash.update(byte_block)
        return sha1_hash.hexdigest()
