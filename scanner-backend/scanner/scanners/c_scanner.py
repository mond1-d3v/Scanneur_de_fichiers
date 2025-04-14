import os
import re
import time
import logging
from typing import Dict, Any, List, Optional

from .base_scanner import BaseScanner, ScannerException

logger = logging.getLogger(__name__)

class CScanner(BaseScanner):   
    def __init__(self):
        super().__init__()
        self.name = "C/C++ Scanner"
        self.description = "Scanner pour fichiers source C/C++"
        self.supported_extensions = ["c", "cpp", "h", "hpp", "cc", "cxx"]
        self.logger = logging.getLogger(__name__)
        self.dangerous_functions = {
            "exec": [
                r"system\s*\(",
                r"exec(?:l|le|lp|v|ve|vp)?\s*\(",
                r"popen\s*\(",
                r"CreateProcess\s*\(",
                r"ShellExecute\s*\(",
                r"WinExec\s*\(",
                r"LoadLibrary\s*\(",
                r"GetProcAddress\s*\("
            ],
            "memory": [
                r"memcpy\s*\(",
                r"strcpy\s*\(",
                r"strcat\s*\(",
                r"sprintf\s*\(",
                r"gets\s*\(",
                r"strncpy\s*\(",
                r"strncat\s*\(",
                r"snprintf\s*\("
            ],
            "network": [
                r"socket\s*\(",
                r"connect\s*\(",
                r"bind\s*\(",
                r"listen\s*\(",
                r"accept\s*\(",
                r"recv\s*\(",
                r"send\s*\(",
                r"WSAStartup\s*\("
            ],
            "file": [
                r"fopen\s*\(",
                r"open\s*\(",
                r"remove\s*\(",
                r"unlink\s*\(",
                r"rename\s*\(",
                r"mkdir\s*\(",
                r"rmdir\s*\(",
                r"CreateFile\s*\("
            ],
            "registry": [
                r"RegOpenKey(?:Ex)?\s*\(",
                r"RegCreateKey(?:Ex)?\s*\(",
                r"RegSetValue(?:Ex)?\s*\(",
                r"RegGetValue\s*\(",
                r"RegDeleteKey\s*\(",
                r"RegEnumKey\s*\("
            ],
            "privilege": [
                r"SetPrivilege\s*\(",
                r"AdjustTokenPrivileges\s*\(",
                r"LookupPrivilegeValue\s*\(",
                r"OpenProcessToken\s*\(",
                r"CreateToken\s*\(",
                r"ImpersonateLoggedOnUser\s*\("
            ],
            "injection": [
                r"VirtualAlloc(?:Ex)?\s*\(",
                r"VirtualProtect(?:Ex)?\s*\(",
                r"WriteProcessMemory\s*\(",
                r"CreateRemoteThread\s*\(",
                r"MapViewOfFile\s*\(",
                r"HeapCreate\s*\(",
                r"NtMapViewOfSection\s*\("
            ],
            "hook": [
                r"SetWindowsHookEx\s*\(",
                r"SetWinEventHook\s*\(",
                r"DetourAttach\s*\(",
                r"DetourDetach\s*\(",
                r"GetMessageProc\s*\(",
                r"CallNextHookEx\s*\("
            ],
            "keylog": [
                r"GetAsyncKeyState\s*\(",
                r"GetKeyState\s*\(",
                r"GetKeyboardState\s*\(",
                r"RegisterHotKey\s*\(",
                r"SetWindowsHookEx\s*\(\s*(?:WH_KEYBOARD|WH_KEYBOARD_LL)",
                r"INPUT_KEYBOARD"
            ],
            "persistence": [
                r"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                r"Startup",
                r"SHGetSpecialFolderPath\s*\(",
                r"StartupFolder",
                r"ScheduleTask",
                r"CreateService\s*\(",
                r"OpenSCManager\s*\("
            ],
            "antidebug": [
                r"IsDebuggerPresent\s*\(",
                r"CheckRemoteDebuggerPresent\s*\(",
                r"NtQueryInformationProcess\s*\(",
                r"OutputDebugString\s*\(",
                r"FindWindow\s*\(\s*[\"\']OllyDbg[\"\']",
                r"GetTickCount\s*\(",
                r"QueryPerformanceCounter\s*\("
            ]
        }
        self.malicious_code_patterns = {
            "backdoor": [
                r"#define\s+PORT\s+\d{1,5}",
                r"bind\s*\(\s*sockfd\s*,\s*\(struct\s+sockaddr\s*\*\)\s*&",
                r"listen\s*\(\s*sockfd\s*,\s*\d+\s*\)",
                r"accept\s*\(\s*sockfd\s*,",
                r"struct\s+sockaddr_in\s+.*?;\s*.*?\.sin_port\s*=\s*htons\s*\(\s*\d{1,5}\s*\)",
            ],
            "dropper": [
                r"URLDownloadToFile",
                r"WinHttpReadData\s*\(",
                r"InternetReadFile\s*\(",
                r"fwrite\s*\(\s*buffer",
                r"CreateFile\s*\(\s*[\"\'][^\"\']+\.(?:exe|dll|sys)[\"\']",
            ],
            "keylogger": [
                r"GetAsyncKeyState\s*\(\s*.*?\s*\)",
                r"SetWindowsHookEx\s*\(\s*WH_KEYBOARD",
                r"GetKeyboardState\s*\(",
                r"keylogger",
                r"key_log",
                r"fprintf\s*\(\s*(?:log|out).*?,\s*[\"\'](?:%c|%s|%d|char|key)[\"\']",
            ],
            "rootkit": [
                r"ZwQuerySystemInformation",
                r"NtQuerySystemInformation",
                r"ZwQueryDirectoryFile",
                r"NtQueryDirectoryFile",
                r"DetourAttach",
                r"HookEngine",
                r"SSDT",
                r"Service\s+Table",
                r"NtCreateFile",
                r"ZwCreateFile",
                r"SeDebugPrivilege",
                r"NtQueryInformationProcess",
            ],
            "spyware": [
                r"GetClipboardData\s*\(",
                r"EmptyClipboard\s*\(",
                r"SetClipboardData\s*\(",
                r"GetDC\s*\(",
                r"CreateCompatibleDC\s*\(",
                r"BitBlt\s*\(",
                r"SendInput\s*\(",
                r"GetForegroundWindow\s*\(",
                r"GetWindowText\s*\(",
                r"CreateToolhelp32Snapshot\s*\(",
                r"Process32First\s*\(",
                r"Process32Next\s*\(",
                r"EnableWindow\s*\(",
                r"EnumWindows\s*\(",
            ],
            "ransomware": [
                r"#include\s+[<\"](?:openssl|crypto|aes|rsa|sha)\.h[>\"]",
                r"crypt",
                r"AES_",
                r"RSA_",
                r"CryptEncrypt",
                r"CryptDecrypt",
                r"CryptGenKey",
                r"CryptGenRandom",
                r"GetSystemDirectory\s*\(",
                r"FindFirstFile\s*\(",
                r"FindNextFile\s*\(",
                r"\.(?:doc|docx|xls|xlsx|ppt|pptx|pdf|txt|jpg|png|mp3|mp4|avi|zip|rar|7z)\"\s*\)",
                r"ransom",
                r"bitcoin",
                r"payment",
            ]
        }
        self.known_exploit_signatures = {
            r"strcpy\s*\(\s*\w+,\s*argv\[\d+\]\s*\)": {
                "name": "Stack Buffer Overflow via Command Line",
                "description": "Copie non sécurisée d'arguments de ligne de commande pouvant mener à un buffer overflow"
            },
            r"gets\s*\(\s*\w+\s*\)": {
                "name": "Dangerous gets() Function",
                "description": "Utilisation de gets() qui est vulnérable aux buffer overflows"
            },
            r"system\s*\(\s*\w+\s*\)": {
                "name": "Unsanitized System Command",
                "description": "Exécution de commandes système avec des données potentiellement non validées"
            },
            r"scanf\s*\(\s*[\"\']%s[\"\']": {
                "name": "Unsafe scanf() Usage",
                "description": "Utilisation non sécurisée de scanf() sans limite de taille"
            },
            r"select\s*\(\s*.*?NULL\s*,\s*NULL\s*,\s*NULL\s*,\s*(?:\w+)\s*\)": {
                "name": "Sleep via select()",
                "description": "Utilisation de select() comme méthode de temporisation (souvent utilisé dans les malwares)"
            }
        }

    def can_scan(self, file_path: str) -> bool:
        extension = self.get_file_extension(file_path)
        if extension in self.supported_extensions:
            return True
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(8192)
                c_signatures = [
                    r'#include\s+[<"]',
                    r'int\s+main\s*\(',
                    r'void\s+\w+\s*\(',
                    r'struct\s+\w+\s*{',
                    r'class\s+\w+\s*{',
                    r'namespace\s+\w+\s*{',
                    r'#define\s+\w+',
                    r'#ifdef\s+\w+',
                    r'#ifndef\s+\w+',
                    r'#pragma\s+once',
                    r'typedef\s+struct',
                    r'extern\s+"C"'
                ]
                for signature in c_signatures:
                    if re.search(signature, content, re.IGNORECASE):
                        return True
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification du fichier C/C++: {str(e)}")
        return False

    def scan(self, file_path: str) -> Dict[str, Any]:
        start_time = time.time()
        result = self.get_result_template()
        result["file_path"] = file_path
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                for signature, info in self.known_exploit_signatures.items():
                    if re.search(signature, content, re.IGNORECASE | re.MULTILINE):
                        result["is_malicious"] = True
                        result["score"] = 10.0
                        result["threats"] = [{
                            "type": "known_exploit",
                            "name": info["name"],
                            "description": info["description"],
                            "severity": "critical"
                        }]
                        result["message"] = f"Exploit C/C++ détecté: {info['name']}"
                        result["scan_time"] = time.time() - start_time
                        return result
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification préliminaire du fichier C/C++: {str(e)}")
        self.content = content
        try:
            analysis_result = self._analyze_c_code(content)
            result["scan_details"] = {
                "file_size": os.path.getsize(file_path),
                "dangerous_functions": analysis_result["dangerous_functions"],
                "malicious_patterns": analysis_result["malicious_patterns"],
                "risk_score": analysis_result["risk_score"],
                "risk_factors": analysis_result["risk_factors"]
            }
            if analysis_result["risk_score"] >= 7.0:
                result["is_malicious"] = True
                result["score"] = analysis_result["risk_score"]
                for threat in analysis_result["threats"]:
                    result["threats"].append(threat)
                result["message"] = f"Code C/C++ potentiellement malveillant (score: {analysis_result['risk_score']}/10)"
            else:
                result["is_malicious"] = False
                result["score"] = analysis_result["risk_score"]
                result["message"] = "Aucun comportement malveillant détecté dans le code C/C++"
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse du fichier C/C++ {file_path}: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
            result["error"] = str(e)
            result["is_malicious"] = False
            result["score"] = 0
        result["scan_time"] = time.time() - start_time
        return result

    def _analyze_c_code(self, content: str) -> Dict[str, Any]:
        result = {
            "dangerous_functions": {"total_count": 0, "categories": {}},
            "malicious_patterns": {"total_count": 0, "categories": {}},
            "risk_score": 0,
            "risk_factors": [],
            "threats": []
        }
        for category, patterns in self.dangerous_functions.items():
            category_matches = []
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if matches:
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        match_str = str(match).strip()
                        if match_str and match_str not in category_matches:
                            category_matches.append(match_str)
            if category_matches:
                result["dangerous_functions"]["categories"][category] = {
                    "count": len(category_matches),
                    "examples": category_matches[:5]
                }
                result["dangerous_functions"]["total_count"] += len(category_matches)
                severity = "high" if category in ["exec", "injection", "keylog", "rootkit"] else "medium"
                risk_factor = f"Fonctions {category} dangereuses: {len(category_matches)}"
                if risk_factor not in result["risk_factors"]:
                    result["risk_factors"].append(risk_factor)
                result["threats"].append({
                    "type": f"dangerous_function_{category}",
                    "name": f"Fonctions dangereuses - {category}",
                    "description": f"Utilisation de fonctions {category} potentiellement dangereuses",
                    "severity": severity
                })
        for category, patterns in self.malicious_code_patterns.items():
            category_matches = []
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if matches:
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        match_str = str(match).strip()
                        if match_str and match_str not in category_matches:
                            category_matches.append(match_str)
            if category_matches:
                result["malicious_patterns"]["categories"][category] = {
                    "count": len(category_matches),
                    "examples": category_matches[:5]
                }
                result["malicious_patterns"]["total_count"] += len(category_matches)
                severity = "critical" if category in ["rootkit", "ransomware"] else "high"
                risk_factor = f"Patterns de code {category}: {len(category_matches)}"
                if risk_factor not in result["risk_factors"]:
                    result["risk_factors"].append(risk_factor)
                result["threats"].append({
                    "type": f"malicious_code_{category}",
                    "name": f"Code malveillant - {category}",
                    "description": f"Détection de code typique de {category}",
                    "severity": severity
                })
        suspicious_strings = self._detect_suspicious_strings(content)
        if suspicious_strings["total_count"] > 0:
            risk_factor = f"Chaînes suspectes: {suspicious_strings['total_count']}"
            if risk_factor not in result["risk_factors"]:
                result["risk_factors"].append(risk_factor)
            if suspicious_strings["total_count"] >= 3:
                result["threats"].append({
                    "type": "suspicious_strings",
                    "name": "Multiples chaînes suspectes",
                    "description": f"Présence de {suspicious_strings['total_count']} chaînes suspectes",
                    "severity": "medium"
                })
        risk_score = self._calculate_risk_score(
            result["dangerous_functions"], 
            result["malicious_patterns"],
            suspicious_strings
        )
        result["risk_score"] = risk_score
        return result

    def _detect_suspicious_strings(self, content: str) -> Dict[str, Any]:
        result = {
            "total_count": 0,
            "strings": []
        }
        suspicious_patterns = [
            r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
            r"\b(?:user|admin|root|administrator)\b",
            r"\b(?:password|passwd|pwd|pass)\b",
            r"\b(?:0x)(?:[0-9a-fA-F]{2}){2,}\b", 
            r"\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", 
            r"\b(?:backdoor|rootkit|keylog|trojan|worm|virus|malware|ransom)\b", 
            r"(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
            r"exploit", 
            r"(?:Windows\\System32\\cmd\.exe)", 
            r"(?:nc|ncat|netcat) -[lL] \d{1,5}", 
            r"(?:meterpreter|metasploit|shellcode|payload)", 
        ]
        for pattern in suspicious_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match not in result["strings"]:
                    result["strings"].append(match)
                    result["total_count"] += 1
        result["strings"] = result["strings"][:10]
        return result

    def _calculate_risk_score(self, dangerous_functions: Dict[str, Any], 
                             malicious_patterns: Dict[str, Any],
                             suspicious_strings: Dict[str, Any]) -> float:
        score = 0
        if dangerous_functions["total_count"] > 0:
            category_weights = {
                "exec": 2.0,
                "memory": 1.0,
                "network": 1.5,
                "file": 1.0,
                "registry": 1.5,
                "privilege": 2.0,
                "injection": 2.5,
                "hook": 2.0,
                "keylog": 3.0,
                "persistence": 2.0,
                "antidebug": 2.5
            }
            df_score = 0
            for category, findings in dangerous_functions["categories"].items():
                weight = category_weights.get(category, 1.0)
                df_score += min(2.5, findings["count"] * weight / 2)
            score += min(5, df_score)
        if malicious_patterns["total_count"] > 0:
            category_weights = {
                "backdoor": 3.0,
                "dropper": 3.0,
                "keylogger": 3.0,
                "rootkit": 3.5,
                "spyware": 2.5,
                "ransomware": 3.5
            }
            mp_score = 0
            for category, findings in malicious_patterns["categories"].items():
                weight = category_weights.get(category, 2.0)
                mp_score += min(4.0, findings["count"] * weight / 2)
            score += min(6, mp_score)
        if suspicious_strings["total_count"] > 0:
            ss_score = min(2.0, suspicious_strings["total_count"] * 0.5)
            score += ss_score
        if "network" in dangerous_functions["categories"] and "exec" in dangerous_functions["categories"]:
            score += 1.5
        if "keylog" in dangerous_functions["categories"] and "network" in dangerous_functions["categories"]:
            score += 2.0
        if "persistence" in dangerous_functions["categories"] and "injection" in dangerous_functions["categories"]:
            score += 2.0
        return min(10.0, score)

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
            "file_name": "",
            "scan_time": 0
        }
