import os
import re
import time
import logging
import zipfile
import tarfile
from typing import Dict, Any, List, Optional, Set, Tuple
from .base_scanner import BaseScanner, ScannerException

logger = logging.getLogger(__name__)

class ArchiveScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.name = "Archive Scanner"
        self.description = "Scanner pour archives compressées"
        self.supported_extensions = ["zip", "tar", "gz", "tgz", "bz2", "tbz2", "xz", "txz", "7z", "rar"]
        self.suspicious_extensions = [
            "exe", "dll", "vbs", "js", "ps1", "bat", "cmd", "hta", "scr", 
            "pif", "msi", "vbe", "jse", "wsf", "wsh", "msh", "reg", "jar", 
            "py", "pl", "php", "asp", "aspx", "jsp"
        ]
        self.archive_extensions = [
            "zip", "tar", "gz", "tgz", "bz2", "tbz2", "xz", "txz", "7z", "rar"
        ]
        self.suspicious_filename_patterns = [
            r"password.*\.(txt|doc|xls)",
            r"(bank|credit|account).*\.(doc|xls|pdf|txt)",
            r"(pass|passwd|credentials)\.",
            r"(confidential|private|secret)\.",
            r"double_extension\..+\..+",
            r"invoice.*\.(doc|xls|pdf)",
            r"received_file\d*\.",
            r"attachment\d*\.",
            r"document\d*\.doc[x]?\.(exe|js|vbs|bat)"
        ]
        self.max_archive_size = 50 * 1024 * 1024
        self.max_nested_level = 3

    def can_scan(self, file_path):
        if not os.path.isfile(file_path):
            return False
        extension = os.path.splitext(file_path)[1].lower().lstrip('.')
        return extension in self.supported_extensions

    def scan(self, file_path):
        start_time = time.time()
        if not self.can_scan(file_path):
            raise ScannerException(f"Format non supporté: {file_path}")
        try:
            result = self.get_result_template()
            result["target"] = file_path
            file_size = os.path.getsize(file_path)
            extension = os.path.splitext(file_path)[1].lower().lstrip('.')
            result["metadata"] = {
                "file_size": file_size,
                "format": extension,
                "size_bytes": file_size,
                "size_human": self._format_bytes(file_size)
            }
            archive_content = self._analyze_archive_content(file_path)
            result["archive_analysis"] = archive_content
            encoding_issues = self._check_filename_encoding(file_path)
            result["encoding_issues"] = encoding_issues
            risk_score, reasons = self._calculate_risk_score(result)
            result["risk_score"] = risk_score
            result["risk_reasons"] = reasons
            result["scan_duration"] = time.time() - start_time
            return result
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de l'archive {file_path}: {str(e)}")
            raise ScannerException(f"Erreur d'analyse: {str(e)}")

    def _analyze_archive_content(self, file_path):
        result = {
            "total_files": 0,
            "suspicious_files": [],
            "executable_files": [],
            "archive_files": [],
            "encrypted": False,
            "nested_level": 0,
            "largest_file": {"name": "", "size": 0},
            "file_extensions": {},
            "suspicious_patterns": []
        }
        extension = os.path.splitext(file_path)[1].lower().lstrip('.')
        if extension in ["zip"]:
            self._analyze_zip_archive(file_path, result)
        elif extension in ["tar", "tgz", "tbz2", "txz"]:
            self._analyze_tar_archive(file_path, result)
        return result

    def _analyze_zip_archive(self, file_path, result):
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                for zip_info in zip_file.infolist():
                    if zip_info.flag_bits & 0x1:
                        result["encrypted"] = True
                        break
                result["total_files"] = len(zip_file.infolist())
                for zip_info in zip_file.infolist():
                    file_name = zip_info.filename
                    file_size = zip_info.file_size
                    if file_size > result["largest_file"]["size"]:
                        result["largest_file"] = {"name": file_name, "size": file_size}
                    extension = os.path.splitext(file_name)[1].lower().lstrip('.')
                    if extension:
                        if extension in result["file_extensions"]:
                            result["file_extensions"][extension] += 1
                        else:
                            result["file_extensions"][extension] = 1
                    if extension in self.suspicious_extensions:
                        result["executable_files"].append({
                            "name": file_name,
                            "size": file_size,
                            "extension": extension
                        })
                    if extension in self.archive_extensions:
                        result["archive_files"].append({
                            "name": file_name,
                            "size": file_size,
                            "extension": extension
                        })
                    for pattern in self.suspicious_filename_patterns:
                        if re.search(pattern, file_name, re.IGNORECASE):
                            result["suspicious_patterns"].append({
                                "file": file_name,
                                "pattern": pattern,
                                "description": "Nom de fichier suspect"
                            })
                            break
        except Exception as e:
            result["error"] = str(e)

    def _analyze_tar_archive(self, file_path, result):
        try:
            with tarfile.open(file_path, 'r:*') as tar_file:
                members = tar_file.getmembers()
                result["total_files"] = len(members)
                for member in members:
                    file_name = member.name
                    file_size = member.size
                    if file_size > result["largest_file"]["size"]:
                        result["largest_file"] = {"name": file_name, "size": file_size}
                    extension = os.path.splitext(file_name)[1].lower().lstrip('.')
                    if extension:
                        if extension in result["file_extensions"]:
                            result["file_extensions"][extension] += 1
                        else:
                            result["file_extensions"][extension] = 1
                    if extension in self.suspicious_extensions:
                        result["executable_files"].append({
                            "name": file_name,
                            "size": file_size,
                            "extension": extension
                        })
                    if extension in self.archive_extensions:
                        result["archive_files"].append({
                            "name": file_name,
                            "size": file_size,
                            "extension": extension
                        })
                    for pattern in self.suspicious_filename_patterns:
                        if re.search(pattern, file_name, re.IGNORECASE):
                            result["suspicious_patterns"].append({
                                "file": file_name,
                                "pattern": pattern,
                                "description": "Nom de fichier suspect"
                            })
                            break
        except Exception as e:
            result["error"] = str(e)

    def _check_filename_encoding(self, file_path):
        result = {
            "has_issues": False,
            "non_ascii_filenames": [],
            "suspicious_characters": []
        }
        extension = os.path.splitext(file_path)[1].lower().lstrip('.')
        if extension == "zip":
            try:
                with zipfile.ZipFile(file_path, 'r') as zip_file:
                    for zip_info in zip_file.infolist():
                        file_name = zip_info.filename
                        if not all(ord(c) < 128 for c in file_name):
                            result["has_issues"] = True
                            result["non_ascii_filenames"].append(file_name)
                        if any(ord(c) < 32 for c in file_name):
                            result["has_issues"] = True
                            result["suspicious_characters"].append(file_name)
            except Exception as e:
                logger.debug(f"Erreur lors de la vérification d'encodage: {str(e)}")
        return result

    def _calculate_risk_score(self, scan_result):
        score = 0
        reasons = []
        archive_analysis = scan_result.get("archive_analysis", {})
        metadata = scan_result.get("metadata", {})
        executable_files = archive_analysis.get("executable_files", [])
        if executable_files:
            exec_score = min(30, len(executable_files) * 10)
            score += exec_score
            reasons.append(f"Fichiers exécutables ({len(executable_files)}): +{exec_score}")
        archive_files = archive_analysis.get("archive_files", [])
        if archive_files:
            archive_score = min(15, len(archive_files) * 5)
            score += archive_score
            reasons.append(f"Archives imbriquées ({len(archive_files)}): +{archive_score}")
        if archive_analysis.get("encrypted", False):
            encrypt_score = 20
            score += encrypt_score
            reasons.append(f"Archive chiffrée: +{encrypt_score}")
        suspicious_patterns = archive_analysis.get("suspicious_patterns", [])
        if suspicious_patterns:
            pattern_score = min(25, len(suspicious_patterns) * 5)
            score += pattern_score
            reasons.append(f"Noms de fichiers suspects ({len(suspicious_patterns)}): +{pattern_score}")
        encoding_issues = scan_result.get("encoding_issues", {})
        if encoding_issues.get("has_issues", False):
            encoding_score = 15
            score += encoding_score
            reasons.append(f"Problèmes d'encodage des noms de fichiers: +{encoding_score}")
        file_size = metadata.get("size_bytes", 0)
        if file_size > self.max_archive_size:
            size_score = 10
            score += size_score
            reasons.append(f"Archive de grande taille ({self._format_bytes(file_size)}): +{size_score}")
        score = min(100, score)
        return score, reasons

    def _format_bytes(self, size):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
