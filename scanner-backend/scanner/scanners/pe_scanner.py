import os
import re
import time
import hashlib
import logging
import struct
import math
from typing import Dict, Any
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
from .base_scanner import BaseScanner, ScannerException

logger = logging.getLogger(__name__)

class PEScanner(BaseScanner):    
    def __init__(self):
        super().__init__()
        self.name = "PE Scanner"
        self.description = "Scanner pour fichiers exécutables Windows"
        self.supported_extensions = ["exe", "dll", "sys", "scr", "ocx", "cpl", "drv"]
    
    def can_scan(self, file_path):
        if self.get_file_extension(file_path) not in self.supported_extensions:
            return False
        try:
            with open(file_path, 'rb') as f:
                header = f.read(2)
                return header == b'MZ'
        except:
            pass
            
        return False
    
    def scan(self, file_path):
        is_dll = file_path.lower().endswith('.dll')
        if not self.can_scan(file_path):
            logger.warning(f"Le fichier {file_path} n'est pas un fichier PE valide")
            return {
                "file_name": os.path.basename(file_path),
                "status": "skipped",
                "message": "Ce n'est pas un fichier PE valide",
                "risk_score": 0,
                "findings": []
            }
        
        logger.info(f"Analyse du fichier PE: {file_path}")
        if not PEFILE_AVAILABLE:
            result = self._scan_basic(file_path)
        else:
            if is_dll:
                logger.warning(f"Analyse approfondie pour DLL: {file_path}")
                result = self._scan_with_pefile(file_path)
                result["is_dll"] = True
                result["dll_special_scan"] = True
            else:
                result = self._scan_with_pefile(file_path)
        if is_dll:
            if result.get('risk_score', 0) >= 40: 
                result['status'] = 'malicious'
                result['message'] = "Plusieurs indicateurs de malveillance potentielle détectés dans cette DLL"
            if PEFILE_AVAILABLE:
                try:
                    pe = pefile.PE(file_path)
                    dll_analysis = self._analyze_dll(pe)
                    if not result.get('findings'):
                        result['findings'] = []
                    
                    result['findings'].append({
                        "type": "dll_analysis",
                        "description": "Analyse spécifique aux DLLs",
                        "details": dll_analysis
                    })
                    if dll_analysis.get('indicators'):
                        additional_points = min(20, len(dll_analysis['indicators']) * 5)
                        result['risk_score'] = min(100, result['risk_score'] + additional_points)
                        
                        if result['risk_score'] >= 50:
                            result['status'] = 'malicious'
                            result['message'] = "Caractéristiques suspectes détectées dans cette DLL"
                except Exception as e:
                    logger.error(f"Erreur lors de l'analyse spécifique DLL: {str(e)}")
        return result
    
    def _scan_basic(self, file_path):
        findings = []
        file_size = os.path.getsize(file_path)
        sha256_hash = self._calculate_file_hash(file_path)
        characteristics = []
        if file_size < 10000:
            characteristics.append("Fichier PE anormalement petit")
        is_packed = self._check_basic_packing(file_path)
        if is_packed:
            characteristics.append("Potentiellement emballé (basé sur l'entropie)")
        suspicious_strings = self._extract_suspicious_strings(file_path)
        if len(characteristics) > 0:
            findings.append({
                "type": "basic_characteristics",
                "description": "Caractéristiques suspectes basiques",
                "details": characteristics
            })
        
        for string_type, strings in suspicious_strings.items():
            if strings:
                findings.append({
                    "type": "suspicious_strings",
                    "description": f"Chaînes suspectes ({string_type})",
                    "details": strings[:10]
                })
    
        risk_score = self._calculate_basic_risk_score(findings, is_packed, file_size, suspicious_strings)
        status = "clean"
        message = "Analyse basique: Aucune caractéristique suspecte majeure"
        
        if risk_score > 30:
            status = "suspicious"
            message = "Analyse basique: Quelques caractéristiques suspectes détectées"
        
        if risk_score > 60:
            status = "malicious" 
            message = "Analyse basique: Plusieurs indicateurs de malveillance potentielle"
            
        return {
            "file_name": os.path.basename(file_path),
            "file_size": file_size,
            "status": status,
            "message": message,
            "risk_score": risk_score,
            "findings": findings,
            "sha256": sha256_hash,
            "analysis_type": "basic"
        }
    

    def _extract_metadata(self, pe) -> Dict[str, Any]:
        metadata = {}
        try:
            metadata["machine_type"] = pe.FILE_HEADER.Machine
            metadata["timestamp"] = pe.FILE_HEADER.TimeDateStamp
            metadata["subsystem"] = pe.OPTIONAL_HEADER.Subsystem
            metadata["sections"] = []
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                metadata["sections"].append({
                    "name": section_name,
                    "entropy": section.get_entropy(),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData
                })
            metadata["imports"] = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore') if entry.dll else "unknown"
                    imports = []
                    for imp in entry.imports:
                        func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else "ordinal_" + str(imp.ordinal)
                        imports.append(func_name)
                    metadata["imports"].append({
                        "dll": dll_name,
                        "functions": imports
                    })
            metadata["exports"] = []
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exp_name = exp.name.decode('utf-8', errors='ignore') if exp.name else "ordinal_" + str(exp.ordinal)
                    metadata["exports"].append(exp_name)
            metadata["resources"] = []
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    resource_id = resource_type.id
                    if resource_type.directory:
                        for resource_id in resource_type.directory.entries:
                            if resource_id.directory:
                                for resource_lang in resource_id.directory.entries:
                                    metadata["resources"].append({
                                        "type": resource_type.id,
                                        "id": resource_id.id,
                                        "lang": resource_lang.id
                                    })
        except Exception as e:
            self.logger.error(f"Erreur lors de l'extraction des métadonnées: {str(e)}")
        return metadata

    
    def _scan_with_pefile(self, file_path):
        findings = []
        file_size = os.path.getsize(file_path)
        sha256_hash = self._calculate_file_hash(file_path)
        
        try:
            pe = pefile.PE(file_path)
            metadata = self._extract_metadata(pe)
            section_analysis = self._analyze_sections(pe)
            import_analysis = self._analyze_imports(pe)
            header_analysis = self._analyze_headers(pe)
            suspicious_strings = self._extract_suspicious_strings(file_path)
            findings.append({
                "type": "metadata",
                "description": "Métadonnées du fichier PE",
                "details": metadata
            })
            if section_analysis['suspicious_sections']:
                findings.append({
                    "type": "suspicious_sections",
                    "description": "Sections suspectes détectées",
                    "details": section_analysis['suspicious_sections']
                })
            if import_analysis['suspicious_imports']:
                findings.append({
                    "type": "suspicious_imports",
                    "description": "Imports suspects détectés",
                    "details": import_analysis['suspicious_imports']
                })
            header_issues = []
            header_issues.extend(header_analysis.get('header_issues', []))
            header_issues.extend(header_analysis.get('timestamp_issues', []))
            header_issues.extend(header_analysis.get('checksum_issues', []))
            
            if header_issues:
                findings.append({
                    "type": "header_issues",
                    "description": "Problèmes détectés dans les en-têtes",
                    "details": header_issues
                })
            for string_type, strings in suspicious_strings.items():
                if strings:
                    findings.append({
                        "type": f"suspicious_{string_type}",
                        "description": f"Chaînes suspectes de type {string_type}",
                        "details": strings[:10]
                    })
            risk_score = self._calculate_advanced_risk_score(
                section_analysis, 
                import_analysis, 
                header_analysis, 
                suspicious_strings
            )
            status = "clean"
            message = "Aucune caractéristique suspecte majeure"
            
            if risk_score > 30:
                status = "suspicious"
                message = "Quelques caractéristiques suspectes détectées"
            
            if risk_score > 60:
                status = "malicious"
                message = "Plusieurs indicateurs de malveillance potentielle"
                
            return {
                "file_name": os.path.basename(file_path),
                "file_size": file_size,
                "status": status,
                "message": message,
                "risk_score": risk_score,
                "findings": findings,
                "sha256": sha256_hash,
                "analysis_type": "advanced"
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse avec pefile: {str(e)}")
            return self._scan_basic(file_path)
    
    def _analyze_headers(self, pe):
        results = {
            "header_issues": [],
            "timestamp_issues": [],
            "checksum_issues": []
        }
        if pe.OPTIONAL_HEADER.CheckSum != 0:
            calculated_checksum = pe.generate_checksum()
            if pe.OPTIONAL_HEADER.CheckSum != calculated_checksum:
                results["checksum_issues"].append(
                    f"Somme de contrôle incorrecte: déclarée {pe.OPTIONAL_HEADER.CheckSum}, calculée {calculated_checksum}"
                )
        if hasattr(pe, 'FILE_HEADER') and hasattr(pe.FILE_HEADER, 'TimeDateStamp'):
            timestamp = pe.FILE_HEADER.TimeDateStamp
            current_time = int(time.time())
            if timestamp > current_time:
                future_date = time.strftime('%Y-%m-%d', time.gmtime(timestamp))
                results["timestamp_issues"].append(f"Date de compilation dans le futur: {future_date}")
            if timestamp < 946684800:
                if timestamp != 0:
                    old_date = time.strftime('%Y-%m-%d', time.gmtime(timestamp))
                    results["timestamp_issues"].append(f"Date de compilation très ancienne: {old_date}")
        if pe.OPTIONAL_HEADER.SizeOfHeaders > 0x1000:
            results["header_issues"].append(f"Taille d'en-tête anormalement grande: {pe.OPTIONAL_HEADER.SizeOfHeaders}")
        if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint'):
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            entry_in_section = False
            for section in pe.sections:
                if (section.VirtualAddress <= entry_point < 
                    section.VirtualAddress + section.Misc_VirtualSize):
                    entry_in_section = True
                    break
            if not entry_in_section and entry_point != 0:
                results["header_issues"].append(f"Point d'entrée {hex(entry_point)} n'est pas dans une section valide")
        return results
    
    def _extract_suspicious_strings(self, file_path):
        results = {
            "url": [],
            "ip": [],
            "registry": [],
            "suspicious_paths": [],
            "commands": []
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                text_content = str(content)
                for url in re.findall(r'https?://[^\s\'"\)\>]{5,}', text_content):
                    if url not in results["url"]:
                        results["url"].append(url)
                for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text_content):
                    if ip not in results["ip"] and not ip.startswith('0.'):
                        results["ip"].append(ip)
                for reg in re.findall(r'HKEY_[A-Z_]+\\[^\s\'"\)\>]{5,}', text_content):
                    if reg not in results["registry"]:
                        results["registry"].append(reg)
                suspicious_paths = [r'%temp%', r'%appdata%', r'\\Windows\\Temp', r'\\Temp\\', r'\\AppData\\']
                for path in suspicious_paths:
                    if path in text_content and path not in results["suspicious_paths"]:
                        results["suspicious_paths"].append(path)
                suspicious_commands = [r'cmd.exe', r'powershell', r'rundll32', r'regsvr32', 
                                      r'schtasks', r'wscript', r'cscript']
                for cmd in suspicious_commands:
                    if cmd in text_content and cmd not in results["commands"]:
                        results["commands"].append(cmd)
                
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des chaînes: {str(e)}")
            
        return results
    
    def _calculate_entropy(self, data):
        if not data:
            return 0
            
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
                
        return entropy
    
    def _calculate_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _check_basic_packing(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                entropy = self._calculate_entropy(data)
                return entropy > 7.0
        except:
            return False

    def _calculate_basic_risk_score(self, findings, is_packed, file_size, suspicious_strings):
        score = 0
        if is_packed:
            score += 30
        if file_size < 10000:
            score += 15 
        if suspicious_strings.get("url", []):
            score += min(20, len(suspicious_strings["url"]) * 5)
        if suspicious_strings.get("ip", []):
            score += min(15, len(suspicious_strings["ip"]) * 5) 
        if suspicious_strings.get("registry", []):
            score += min(20, len(suspicious_strings["registry"]) * 5) 
        if suspicious_strings.get("commands", []):
            score += min(20, len(suspicious_strings["commands"]) * 5) 
        return min(100, score)
    
    def _calculate_advanced_risk_score(self, section_analysis, import_analysis, header_analysis, suspicious_strings):
        score = 0
        suspicious_sections_count = len(section_analysis.get('suspicious_sections', []))
        score += min(25, suspicious_sections_count * 7)
        rwx_sections_count = len(section_analysis.get('rwx_sections', []))
        score += min(30, rwx_sections_count * 20)
        high_entropy_sections_count = len(section_analysis.get('high_entropy_sections', []))
        score += min(25, high_entropy_sections_count * 12) 
        suspicious_imports_count = len(import_analysis.get('suspicious_imports', []))
        score += min(35, suspicious_imports_count * 5)
        if import_analysis.get('has_minimal_imports', False):
            score += 20  
        dll_file = os.path.splitext(section_analysis.get('file_path', ''))[1].lower() == '.dll'
        if dll_file:
            exports_count = len(import_analysis.get('exports', []))
            if exports_count == 0:
                score += 15
            
            suspicious_exports = import_analysis.get('suspicious_exports', 0)
            score += min(20, suspicious_exports * 5)
            if any("hook" in export.lower() for export in import_analysis.get('exports', [])):
                score += 20
        header_issues_count = (
            len(header_analysis.get('header_issues', [])) +
            len(header_analysis.get('timestamp_issues', [])) +
            len(header_analysis.get('checksum_issues', []))
        )
        score += min(25, header_issues_count * 9) 
        url_count = len(suspicious_strings.get('url', []))
        score += min(15, url_count * 3) 
        ip_count = len(suspicious_strings.get('ip', []))
        score += min(15, ip_count * 3)
        registry_count = len(suspicious_strings.get('registry', []))
        score += min(15, registry_count * 3)
        command_count = len(suspicious_strings.get('commands', []))
        score += min(15, command_count * 3)
        highly_suspicious = [
            "inject", "shellcode", "rootkit", "hooking", "patch", "exploit", 
            "keylog", "spy", "backdoor", "trojan", "ransom"
        ]
        
        for category, strings in suspicious_strings.items():
            for item in strings:
                if any(keyword in item.lower() for keyword in highly_suspicious):
                    score += 20
                    break
        return min(100, score)

    def _analyze_sections(self, pe):
        suspicious_sections = []
        sections_info = []
        
        try:
            for section in pe.sections:
                section_name = section.Name.strip(b'\x00').decode('utf-8', errors='ignore')
                entropy = section.get_entropy()
                section_info = {
                    'name': section_name,
                    'entropy': entropy,
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'characteristics': hex(section.Characteristics)
                }
                sections_info.append(section_info)
                if (entropy > 7.0):
                    suspicious_sections.append({
                        'name': section_name,
                        'reason': f"Entropie élevée ({entropy:.2f})",
                        'severity': 'medium'
                    })
                standard_sections = ['.text', '.data', '.rdata', '.pdata', '.rsrc', '.reloc', '.idata']
                if section_name not in standard_sections and len(section_name) > 0:
                    suspicious_sections.append({
                        'name': section_name,
                        'reason': "Nom de section non standard",
                        'severity': 'low'
                    })
                if section.Characteristics & 0x20000000 and section.Characteristics & 0x80000000:
                    suspicious_sections.append({
                        'name': section_name,
                        'reason': "Section à la fois exécutable et inscriptible",
                        'severity': 'high'
                    })
            
            return {
                'suspicious_sections': suspicious_sections,
                'sections_info': sections_info
            }
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse des sections: {e}")
            return {
                'error': str(e),
                'suspicious_sections': [],
                'sections_info': []
            }
    
    def _analyze_dll(self, pe):
        results = {
            "is_dll": True,
            "exports": [],
            "suspicious_exports": 0,
            "dll_characteristics": {},
            "indicators": []
        }
        if not hasattr(pe, 'FILE_HEADER') or not pe.FILE_HEADER.IMAGE_FILE_DLL:
            results["is_dll"] = False
            return results
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            suspicious_export_patterns = [
                "inject", "hook", "patch", "detour", "spy", "monitor", "log", 
                "crypt", "password", "record", "keylog", "admin", "screen", 
                "capture", "remote", "backdoor"
            ]
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exp_name = exp.name.decode('utf-8', errors='ignore') if exp.name else f"ordinal_{exp.ordinal}"
                results["exports"].append(exp_name)
                for pattern in suspicious_export_patterns:
                    if pattern.lower() in exp_name.lower():
                        results["suspicious_exports"] += 1
                        results["indicators"].append(f"Export suspect: {exp_name}")
                        break
        else:
            results["indicators"].append("DLL sans table d'export")
        if hasattr(pe, 'OPTIONAL_HEADER'):
            dllcharacteristics = pe.OPTIONAL_HEADER.DllCharacteristics
            if not dllcharacteristics & 0x0040:
                results["dll_characteristics"]["no_aslr"] = True
                results["indicators"].append("DLL sans support ASLR (peut indiquer un code malveillant)")
            if not dllcharacteristics & 0x0100:
                results["dll_characteristics"]["no_dep"] = True
                results["indicators"].append("DLL sans support DEP (protection d'exécution désactivée)")
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            if ".text" in section_name and section.Characteristics & 0x20000000:
                if section.SizeOfRawData < 1000:
                    results["indicators"].append("DLL avec petite section .text exécutable (possible shellcode)")
                entropy = section.get_entropy()
                if entropy > 7.0:
                    results["indicators"].append(f"DLL avec section .text de haute entropie ({entropy:.2f})")
        
        return results
