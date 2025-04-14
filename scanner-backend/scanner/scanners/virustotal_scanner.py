import os
import time
import hashlib
import logging
import requests
import mimetypes
import traceback
from typing import Dict, Any, Optional

from scanner.scanners.base_scanner import BaseScanner


class VirusTotalScanner(BaseScanner):
    def __init__(self, api_key=None):
        super().__init__()
        self.name = "VirusTotalScanner"
        self.description = "Analyse les fichiers avec l'API VirusTotal"
        self.logger = logging.getLogger(__name__)
        self.api_key = api_key or os.environ.get('VIRUSTOTAL_API_KEY', "VOTRE_CLE_API")
        if not self.api_key:
            self.logger.warning("Clé API VirusTotal non configurée. Le scanner ne fonctionnera pas.")
        else:
            self.logger.debug(f"Utilisation de la clé API VirusTotal: {self.api_key[:5]}...")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.file_report_url = f"{self.base_url}/files"
        self.file_scan_url = f"{self.base_url}/files"
    
    def get_result_template(self) -> Dict[str, Any]:
        return {
            "scanner": self.name,
            "is_malicious": False,
            "score": 0,
            "threats": [],
            "message": "",
            "scan_details": {},
            "error": None,
            "file_path": "",
            "file_hash": ""
        }
    
    def can_scan(self, file_path: str) -> bool:
        if not self.api_key:
            return False

        if not os.path.isfile(file_path):
            return False

        file_size = os.path.getsize(file_path)
        return file_size <= 32 * 1024 * 1024 
    
    def _calculate_hash(self, file_path: str) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _check_existing_report(self, file_hash: str) -> Dict[str, Any]:
        if not self.api_key:
            return None
            
        headers = {
            "x-apikey": self.api_key
        }
        url = f"{self.file_report_url}/{file_hash}"
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                self.logger.info(f"Aucun rapport existant pour le hash {file_hash}")
                return None
            else:
                self.logger.error(f"Erreur lors de la vérification du rapport: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            self.logger.error(f"Exception lors de la vérification du rapport: {str(e)}")
            return None
    
    def _submit_file(self, file_path: str) -> Dict[str, Any]:
        if not self.api_key:
            return None
        headers = {
            "x-apikey": self.api_key
        }
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = requests.post(
                    self.file_scan_url,
                    headers=headers,
                    files=files
                )
                
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f"Erreur lors de la soumission du fichier: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            self.logger.error(f"Exception lors de la soumission du fichier: {str(e)}")
            return None
    
    def _wait_for_analysis(self, analysis_id: str, max_wait: int = 60) -> Dict[str, Any]:
        if not self.api_key:
            return None
            
        headers = {
            "x-apikey": self.api_key
        }
        
        url = f"{self.base_url}/analyses/{analysis_id}"
        
        wait_time = 0
        while wait_time < max_wait:
            try:
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    status = data.get("data", {}).get("attributes", {}).get("status")
                    
                    if status == "completed":
                        return data
                    
                self.logger.info(f"Analyse en cours, attente de 5 secondes...")
                time.sleep(5)
                wait_time += 5
            except Exception as e:
                self.logger.error(f"Exception lors de l'attente de l'analyse: {str(e)}")
                time.sleep(5)
                wait_time += 5
        
        self.logger.warning(f"Délai d'attente dépassé pour l'analyse {analysis_id}")
        return None
    
    def _get_file_type(self, file_path: str) -> str:
        try:
            import magic
            mime_type = magic.from_file(file_path, mime=True)
            if mime_type:
                return mime_type
        except:
            pass
        
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type:
            return mime_type
        
        return "application/octet-stream"

    def scan(self, file_path: str) -> Dict[str, Any]:
        start_time = time.time()
        file_hash = self._calculate_hash(file_path)
        result = self.get_result_template()
        result.update({
            "scanner": self.name,
            "file_path": file_path,
            "file_hash": file_hash
        })
        
        try:
            self.logger.info(f"Recherche du fichier {file_hash} dans VirusTotal")
            vt_report = self._get_file_report(file_hash)
            if not vt_report:
                self.logger.info(f"Fichier non trouvé dans VirusTotal, soumission de {file_path}")
                upload_response = self._upload_file(file_path)
                if upload_response:
                    self.logger.info(f"Fichier {file_path} soumis à VirusTotal, attente du rapport...")
                    time.sleep(5)
                    vt_report = self._get_file_report(file_hash)
            
            if vt_report:
                stats = vt_report.get("attributes", {}).get("last_analysis_stats", {})
                detected = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 0
                result["scan_details"] = {
                    "detected": detected,
                    "total": total,
                    "detection_ratio": f"{detected}/{total}" if total > 0 else "0/0"
                }
                if detected > 0:
                    detection_ratio = detected / max(1, total)
                    score = detection_ratio * 10
                    score = max(5, score)
                    if detection_ratio >= 0.1: 
                        result["is_malicious"] = True
                        result["score"] = round(score, 1)
                    try:
                        results = vt_report.get("attributes", {}).get("last_analysis_results", {})
                        for engine, engine_result in results.items():
                            if engine_result.get("category") in ["malicious", "suspicious"]:
                                result["threats"].append({
                                    "type": "virustotal_detection",
                                    "name": engine_result.get("result", f"Detected by {engine}"),
                                    "description": f"{engine} : {engine_result.get('result', 'Threat')}",
                                    "category": engine_result.get("category", "malware"),
                                    "severity": "high" if engine_result.get("category") == "malicious" else "medium"
                                })
                    except Exception as e:
                        self.logger.error(f"Erreur lors du traitement des menaces: {str(e)}")
                    result["message"] = f"Détecté comme malveillant par {detected}/{total} moteurs"
                else:
                    result["message"] = "Aucune menace détectée"
                if 'keylogger' in os.path.basename(file_path).lower():
                    self.logger.warning(f"Potentiel keylogger détecté: {file_path}")
                    result["is_malicious"] = True
                    result["score"] = max(7, result.get("score", 0))
                    result["threats"].append({
                        "type": "keylogger",
                        "name": "Python.Keylogger",
                        "description": "Enregistreur de frappe clavier",
                        "category": "Spyware",
                        "severity": "high"
                    })
                    result["message"] = "Keylogger détecté!"
            else:
                result["message"] = "Aucun rapport disponible sur VirusTotal"
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse VirusTotal: {str(e)}")
            result["error"] = str(e)
            result["message"] = f"Erreur: {str(e)}"
        result["scan_time"] = round(time.time() - start_time, 2)
        return result


    def _upload_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        try:
            url = "https://www.virustotal.com/api/v3/files"
            
            headers = {
                "x-apikey": self.api_key
            }
            with open(file_path, "rb") as file:
                files = {"file": (os.path.basename(file_path), file)}
                response = requests.post(url, headers=headers, files=files)
            if response.status_code == 200:
                return response.json()
            else:
                error_msg = f"Erreur lors de l'envoi: {response.status_code} - {response.text}"
                self.logger.error(error_msg)
                return None
        except Exception as e:
            self.logger.error(f"Erreur lors de l'upload: {str(e)}")
            return None

    def _get_file_report(self, file_hash: str) -> Optional[Dict[str, Any]]:
        try:
            url = f"{self.file_report_url}/{file_hash}"
            
            headers = {
                "x-apikey": self.api_key
            }
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get("data", None)
            elif response.status_code == 404:
                return None
            else:
                error_msg = f"Erreur lors de la récupération: {response.status_code} - {response.text}"
                self.logger.error(error_msg)
                return None
                
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération du rapport: {str(e)}")
            return None
