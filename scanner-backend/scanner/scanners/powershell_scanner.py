import os
import re
import time
import base64
import logging
import binascii
from typing import Dict, Any, List, Optional
from .base_scanner import BaseScanner, ScannerException
logger = logging.getLogger(__name__)

class PowerShellScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.name = "PowerShell Scanner"
        self.description = "Scanner pour scripts PowerShell"
        self.supported_extensions = ["ps1", "psm1", "psd1"]
        self.dangerous_commands = {
            "execution": [
                r"Invoke-Expression",
                r"iex\s",
                r"Invoke-Command",
                r"eval\s",
                r"Invoke-Item",
                r"Start-Process",
                r"\&\s+[\"\']?[^\"\']+[\"\']?",
            ],
            "download": [
                r"(Invoke-)?WebRequest",
                r"(Invoke-)?RestMethod",
                r"Net\.WebClient",
                r"DownloadFile",
                r"DownloadString",
                r"DownloadData",
                r"WebClient\.",
                r"Start-BitsTransfer",
            ],
            "network": [
                r"New-Object\s+Net\.Socket",
                r"New-Object\s+Net\.WebClient",
                r"GetResponseStream$",
                r"System\.Net\.",
                r"Sockets\.",
                r"Test-NetConnection",
            ],
            "registry": [
                r"Registry::",
                r"HKLM:",
                r"HKCU:",
                r"Get-ItemProperty\s+-Path\s+(?:HKLM|HKCU|HKEY)",
                r"Set-ItemProperty\s+-Path\s+(?:HKLM|HKCU|HKEY)",
                r"Remove-ItemProperty\s+-Path\s+(?:HKLM|HKCU|HKEY)",
                r"New-Item\s+-Path\s+(?:HKLM|HKCU|HKEY)",
            ],
            "system_info": [
                r"Get-WmiObject\s+Win32_(?:OperatingSystem|ComputerSystem|Process)",
                r"Get-CimInstance\s+Win32_(?:OperatingSystem|ComputerSystem|Process)",
                r"Get-Process",
                r"Get-Service",
                r"Get-Date",
                r"hostname",
                r"ipconfig",
                r"whoami",
                r"net\s+user",
                r"net\s+localgroup",
                r"netstat",
                r"Get-MpPreference",
            ],
            "uac_bypass": [
                r"ConsentPromptBehaviorAdmin",
                r"EnableLUA",
                r"elevate",
                r"Bypass",
                r"CurrentUser to LocalSystem",
            ],
            "privilege_escalation": [
                r"Start-Process.*-Verb\s+RunAs",
                r"Microsoft\.Win32\.UnsafeNativeMethods",
                r"IEX.*New-Object\s+Net\.WebClient",
                r"Net\.ServicePointManager.*SecurityProtocol",
                r"Administrator",
                r"privilege",
                r"escalat",
                r"sudo",
            ],
            "credential_access": [
                r"Get-Credential",
                r"SecureString",
                r"ConvertFrom-SecureString",
                r"ConvertTo-SecureString",
                r"PSCredential",
                r"Password",
                r"SecureKey",
                r"token",
                r"pass.*hash",
                r"mimikatz",
                r"credentials",
                r"credential",
            ],
            "code_injection": [
                r"reflection\.assembly",
                r"System\.Reflection",
                r"LoadLibrary",
                r"VirtualAlloc",
                r"memcpy",
                r"DllImport",
                r"Marshal",
                r"runtime",
                r"kernel32",
                r"ntdll",
                r"kernel",
                r"WriteProcessMemory",
                r"CreateRemoteThread",
                r"AddScript",
                r"runspace",
            ],
            "persistence": [
                r"New-Service",
                r"Create-ScheduledTask",
                r"Set-ScheduledTask",
                r"Register-ScheduledJob",
                r"Register-WmiEvent",
                r"Startup",
                r"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                r"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            ],
            "defense_evasion": [
                r"Set-MpPreference",
                r"DisableRealTimeMonitoring",
                r"Add-MpPreference\s+-ExclusionPath",
                r"Add-MpPreference\s+-ExclusionProcess",
                r"DisableScriptScanning",
                r"DisableBehaviorMonitoring",
                r"Delete.*EventLog",
                r"Stop-Service\s+WinDefend",
                r"Clear-EventLog",
                r"remove.*log",
                r"Base64",
                r"hidden",
                r"undetect",
                r"bypass",
                r"Stealth",
                r"-W\s+Hidden",
            ],
            "data_exfiltration": [
                r"Compress-Archive",
                r"Send-MailMessage",
                r"FtpWebRequest",
                r"FtpClient",
            ],
        }
        self.obfuscation_patterns = [
            r"(\$\w+)\s*=\s*\[\s*char\s*\]\s*(\d+)", 
            r"(\$\w+)\s*=\s*\[\s*string\s*\]\s*\[char\[\]\]\s*\(.*?\)",
            r"(\$\w+)\s*=\s*(\$\w+)\s*-replace\s+['\"](.*?)['\"],\s*['\"](.*?)['\"]",  
            r"(\$\w+)\s*=\s*(\$\w+)\s*-join\s*['\"](.*?)['\"]", 
            r"(\$\w+)\s*=\s*['\"](.*?)['\"]\s*\-f\s*(.*)",  
            r"(\$\w+)\s*=\s*(\$\w+)\s*\+\s*(\$\w+)",  
            r"(\$\w+)\s*=\s*'.*?'\s*\+\s*'.*?'",  
            r"(\$\w+)\s*=\s*\$\w+\[(\d+|\$\w+)\]", 
            r"(\$\w+)\s*=\s*\$\w+\s*\.\s*\{\s*\$_\s*\}", 
            r"(\$\w+)\s*=\s*\$\w+\s*\|\s*\.+\s*\{\s*\$_\s*\}\s*\|\s*\.+\s*\{\s*\$_\s*\}"
        ]
        self.encoding_patterns = [
            (r"(?:\[\s*Convert\s*\]::FromBase64String\s*\(['\"](.*?)['\"]\))", "base64"),
            (r"(?:\[\s*Text\.Encoding\s*\]::(?:ASCII|Unicode|UTF8)\.GetString\s*\((.*?)\))", "text_encoding"),
            (r"(?:New-Object\s+IO\.Compression\.GzipStream)", "gzip"),
            (r"(?:Invoke-Expression\s+\$[^)]*FromBase64String)", "iex_base64"),
            (r"(?:Invoke-Expression\s+\$\w+)", "iex_variable"),
            (r"(?:\[\s*System\.Convert\s*\]::ToBase64String\s*\((.*?)\))", "to_base64"),
            (r"(?:Convert\s+Content\s+From\s+(.*?))", "encoding_conversion"),
        ]
        self.suspicious_string_patterns = [
            r"(?:https?|ftp)://[\w\-\.]+\.\w+/[\w\-\./?=%&]+",  
            r"\b(?:powershell\.exe|cmd\.exe|bash\.exe|command\.com)\b",  
            r"\b(?:cacls|icacls|xcacls)\b", 
            r"\b(?:schtasks|at)\b",  
            r"\b(?:Admin|administrator|administrateur|system)\b",  
            r"\b(?:Pass|password|mot\s+de\s+passe|cred|credential)\b",  
            r"\b(?:hidden|silent|quiet|stealth)\b",
        ]
        
    def can_scan(self, file_path):
        extension = self.get_file_extension(file_path)
        if extension in self.supported_extensions:
            return True
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(4096)
                ps_signatures = [
                    r'param\s*$',
                    r'function\s+\w+\s*\{',
                    r'Write-Host',
                    r'Get-\w+',
                    r'Set-\w+',
                    r'New-\w+',
                    r'Invoke-\w+',
                    r'\$\w+\s*=',
                    r'\[CmdletBinding\('
                ]
                
                for signature in ps_signatures:
                    if re.search(signature, content, re.IGNORECASE):
                        return True
        except:
            pass
            
        return False
    
    def scan(self, file_path):
        start_time = time.time()
        result = self.get_result_template()
        result["file_path"] = file_path
        result["file_name"] = os.path.basename(file_path)
        logger.info(f"Analyse du script PowerShell: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            file_size = os.path.getsize(file_path)
            result["scan_details"]["file_size"] = file_size
            obfuscation = self._detect_obfuscation(content)
            result["scan_details"]["obfuscation"] = obfuscation
            dangerous_commands = self._detect_dangerous_commands(content)
            result["scan_details"]["dangerous_commands"] = dangerous_commands
            encodings = self._detect_encodings(content)
            result["scan_details"]["encodings"] = encodings
            encoded_content = self._extract_encoded_content(content)
            if encoded_content:
                result["scan_details"]["encoded_content"] = {
                    "original_type": encoded_content["type"],
                    "decoded_size": len(encoded_content["content"]),
                    "analysis": self._analyze_decoded_content(encoded_content["content"])
                }
            suspicious_strings = self._detect_suspicious_strings(content)
            result["scan_details"]["suspicious_strings"] = suspicious_strings
            risk_score, reasons = self._calculate_risk_score(
                obfuscation,
                dangerous_commands,
                encodings,
                encoded_content,
                suspicious_strings,
                file_size
            )
            
            result["risk_score"] = risk_score
            result["scan_details"]["risk_factors"] = reasons
            if risk_score >= 70:
                result["is_malicious"] = True
                result["threats"].append({
                    "name": "Suspicious PowerShell Script",
                    "type": "malicious_script",
                    "severity": "high" if risk_score >= 85 else "medium",
                    "details": f"Score de risque {risk_score}/100"
                })
            elif risk_score >= 40:
                result["is_malicious"] = False
                result["threats"].append({
                    "name": "Potentially Unwanted PowerShell Script",
                    "type": "suspicious_script",
                    "severity": "medium" if risk_score >= 55 else "low",
                    "details": f"Score de risque {risk_score}/100"
                })
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse du script PowerShell {file_path}: {str(e)}")
            result["error"] = str(e)
        result["scan_time"] = time.time() - start_time
        
        return result
    
    def _detect_obfuscation(self, content):
        result = {
            "techniques_count": 0,
            "techniques": []
        }
        for pattern in self.obfuscation_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                result["techniques_count"] += len(matches)
                pattern_name = pattern[:50] + "..." if len(pattern) > 50 else pattern
                result["techniques"].append({
                    "pattern": pattern_name,
                    "count": len(matches),
                    "examples": matches[:3]
                })
        backtick_count = content.count('`')
        if backtick_count > 5:
            result["techniques_count"] += 1
            result["techniques"].append({
                "pattern": "PowerShell backtick escaping",
                "count": backtick_count,
                "examples": ["Character escaping with backticks"]
            })
        strange_vars = re.findall(r'\$([a-zA-Z0-9]{1,2}|\w{30,})', content)
        if strange_vars:
            result["techniques_count"] += 1
            result["techniques"].append({
                "pattern": "Unusual variable names",
                "count": len(strange_vars),
                "examples": list(set(strange_vars))[:3]
            })
        string_splitting = re.findall(r'(\'[^\']{1,3}\'|\"[^\"]{1,3}\")\s*\+\s*(\'[^\']{1,3}\'|\"[^\"]{1,3}\")', content)
        if string_splitting:
            result["techniques_count"] += 1
            result["techniques"].append({
                "pattern": "String splitting",
                "count": len(string_splitting),
                "examples": [f"{m[0]}+{m[1]}" for m in string_splitting[:3]]
            })
        char_encodings = re.findall(r'\[char\]\s*(\d+)', content)
        if char_encodings:
            result["techniques_count"] += 1
            result["techniques"].append({
                "pattern": "Character encoding using [char]",
                "count": len(char_encodings),
                "examples": char_encodings[:3]
            })
        return result
    
    def _detect_dangerous_commands(self, content):
        result = {
            "total_count": 0,
            "categories": {}
        }
        for category, patterns in self.dangerous_commands.items():
            category_findings = []
            
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    for match in matches:
                        match_str = match if isinstance(match, str) else match[0]
                        match_str = match_str.strip()
                        if match_str and match_str not in category_findings:
                            category_findings.append(match_str)
            
            if category_findings:
                result["categories"][category] = {
                    "count": len(category_findings),
                    "examples": category_findings[:5]
                }
                result["total_count"] += len(category_findings)
        return result
    
    def _detect_encodings(self, content):
        result = {
            "total_count": 0,
            "types": {}
        }
        for pattern, encoding_type in self.encoding_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            if matches:
                if encoding_type not in result["types"]:
                    result["types"][encoding_type] = {
                        "count": 0,
                        "examples": []
                    }
                
                result["types"][encoding_type]["count"] += len(matches)
                result["total_count"] += len(matches)
                
                # Ajouter des exemples limités
                for match in matches[:3]:
                    match_str = match if isinstance(match, str) else match[0]
                    if len(match_str) > 50:
                        match_str = match_str[:47] + "..."
                    result["types"][encoding_type]["examples"].append(match_str)
        return result
    
    def _extract_encoded_content(self, content):
        base64_pattern = r'(?:FromBase64String|Base64Decode)\s*$ \s*[\'"](.*?)[\'"]\s* $ '
        matches = re.findall(base64_pattern, content, re.IGNORECASE | re.DOTALL)
        
        if not matches:
            return None
        longest_match = max(matches, key=len) if matches else None
        
        if not longest_match or len(longest_match) < 20:
            return None
            
        try:
            cleaned_base64 = re.sub(r'[^A-Za-z0-9+/=]', '', longest_match)
            padding_needed = 4 - (len(cleaned_base64) % 4) if len(cleaned_base64) % 4 != 0 else 0
            cleaned_base64 += "=" * padding_needed
            decoded = base64.b64decode(cleaned_base64)
            try:
                decoded_text = decoded.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    decoded_text = decoded.decode('utf-16-le')
                except UnicodeDecodeError:
                    decoded_text = binascii.hexlify(decoded).decode('ascii')
            
            return {
                "type": "base64",
                "original_length": len(longest_match),
                "content": decoded_text
            }
            
        except Exception as e:
            logger.debug(f"Impossible de décoder le contenu Base64: {str(e)}")
            return None
    
    def _analyze_decoded_content(self, decoded_content):
        result = {
            "is_powershell": False,
            "is_executable": False,
            "has_dangerous_commands": False,
            "suspicious_patterns": []
        }
        ps_signatures = [
            r'function\s+\w+\s*\{',
            r'Write-Host',
            r'Get-\w+',
            r'Set-\w+',
            r'Invoke-\w+',
            r'\$\w+\s*=',
            r'param\s*$',
            r'\[CmdletBinding\('
        ]
        
        for signature in ps_signatures:
            if re.search(signature, decoded_content, re.IGNORECASE):
                result["is_powershell"] = True
                break
        if decoded_content.startswith("MZ") or "TVqQAAMAAAAEAAAA" in decoded_content:
            result["is_executable"] = True
            result["suspicious_patterns"].append("Contains executable code (PE file header detected)")
        for category, patterns in self.dangerous_commands.items():
            for pattern in patterns:
                if re.search(pattern, decoded_content, re.IGNORECASE):
                    result["has_dangerous_commands"] = True
                    result["suspicious_patterns"].append(f"Dangerous command pattern: {pattern}")
                    break
        urls = re.findall(r'https?://[\w\-\.]+\.\w+/[\w\-\./?=%&]+', decoded_content)
        if urls:
            result["suspicious_patterns"].append(f"Contains URLs: {', '.join(urls[:3])}")
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', decoded_content)
        if ips:
            result["suspicious_patterns"].append(f"Contains IP addresses: {', '.join(ips[:3])}")
        
        return result
    
    def _detect_suspicious_strings(self, content):
        result = {
            "total_count": 0,
            "strings": []
        }
        for pattern in self.suspicious_string_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match not in result["strings"]:
                    result["strings"].append(match)
                    result["total_count"] += 1
        result["strings"] = result["strings"][:10]
        return result
    
    def _calculate_risk_score(self, obfuscation, dangerous_commands, encodings, 
                             encoded_content, suspicious_strings, file_size):
        score = 0
        reasons = []
        if obfuscation["techniques_count"] > 0:
            obfuscation_score = min(30, obfuscation["techniques_count"] * 5)
            score += obfuscation_score
            reasons.append(f"Script obfusqué ({obfuscation['techniques_count']} techniques): +{obfuscation_score}")
        if dangerous_commands["total_count"] > 0:
            category_weights = {
                "execution": 10,
                "download": 8,
                "network": 6,
                "registry": 7,
                "system_info": 3,
                "uac_bypass": 15,
                "privilege_escalation": 15,
                "credential_access": 8,
                "code_injection": 15,
                "persistence": 12,
                "defense_evasion": 15,
                "data_exfiltration": 8
            }
            dangerous_commands_score = 0
            for category, findings in dangerous_commands["categories"].items():
                category_score = findings["count"] * category_weights.get(category, 5)
                dangerous_commands_score += category_score
                reasons.append(f"Commandes {category} ({findings['count']}): +{category_score}")
            dangerous_commands_score = min(40, dangerous_commands_score)
            score += dangerous_commands_score
            if "download" in dangerous_commands["categories"] and "execution" in dangerous_commands["categories"]:
                bonus = 10
                score += bonus
                reasons.append(f"Combinaison téléchargement + exécution: +{bonus}")
                
            if "defense_evasion" in dangerous_commands["categories"]:
                bonus = 5
                score += bonus
                reasons.append(f"Tentatives d'évasion de défense: +{bonus}")
        if encodings["total_count"] > 0:
            encoding_score = min(15, encodings["total_count"] * 3)
            score += encoding_score
            reasons.append(f"Encodages suspects ({encodings['total_count']}): +{encoding_score}")
        if encoded_content and encoded_content.get("content"):
            analysis = encoded_content.get("analysis", {})
            
            if analysis.get("is_executable", False):
                exec_score = 20
                score += exec_score
                reasons.append(f"Contenu encodé contient un exécutable: +{exec_score}")
            
            if analysis.get("is_powershell", False):
                ps_score = 15
                score += ps_score
                reasons.append(f"Contenu encodé contient du PowerShell: +{ps_score}")
            
            if analysis.get("has_dangerous_commands", False):
                cmd_score = 10
                score += cmd_score
                reasons.append(f"Contenu encodé contient des commandes dangereuses: +{cmd_score}")
        if suspicious_strings["total_count"] > 0:
            suspicious_score = min(10, suspicious_strings["total_count"] * 2)
            score += suspicious_score
            reasons.append(f"Chaînes suspectes ({suspicious_strings['total_count']}): +{suspicious_score}")
        if file_size < 5000 and score > 30:
            size_score = 10
            score += size_score
            reasons.append(f"Petit script avec score élevé: +{size_score}")
        score = min(100, score)
        
        return score, reasons
