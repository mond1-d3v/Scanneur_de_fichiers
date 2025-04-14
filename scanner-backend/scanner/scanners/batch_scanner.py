import os
import re
import time
import logging
from typing import Dict, Any

from .base_scanner import BaseScanner, ScannerException

logger = logging.getLogger(__name__)

class BatchScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.name = "Batch Scanner"
        self.description = "Scanner pour scripts batch Windows"
        self.supported_extensions = ["bat", "cmd"]
        self.dangerous_commands = {
            "network": [
                r"(powershell|curl|wget|certutil)\s+-.*https?://",
                r"bitsadmin\s+/transfer",
                r"nc\s+.+\s+\d{1,5}",
                r"netsh\s+firewall\s+add",
            ],
            "exec": [
                r"start\s+/\w+",
                r"cmd\.exe\s+/c",
                r"wscript\.exe",
                r"cscript\.exe",
                r"powershell\s+-[eEwWnNoO]",
                r"rundll32\.exe",
                r"regsvr32\.exe",
            ],
            "registry": [
                r"reg\s+(add|delete|query|import|export)",
                r"regedit\s+/[sif]",
            ],
            "system": [
                r"cacls\s+\S+\s+/[gpetu]",
                r"icacls\s+\S+\s+/grant",
                r"schtasks\s+/create",
                r"at\s+\d{1,2}:",
                r"attrib\s+[\+\-][rashepicdo]",
            ],
            "deletion": [
                r"del\s+/[fqsa]",
                r"rmdir\s+/[sq]",
                r"erase\s+/[fqsa]",
            ],
            "obfuscation": [
                r"set\s+\w+=%\w+:~(\d+),(\d+)%",
                r"call\s+set\s+",
                r"set\s+[a-zA-Z0-9]=[^\s]",
            ]
        }
    
    def can_scan(self, file_path):
        return self.get_file_extension(file_path) in self.supported_extensions
    
    def scan(self, file_path: str) -> Dict[str, Any]:
        result = self.get_result_template()
        result["file_path"] = file_path
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().lower()
            score = 0
            threat_details = []
            dangerous_commands = {
                r"rd /s /q %systemroot%": 10,
                r"del /[fqs].* %systemroot%": 9,
                r"del /[fqs].* system32": 9,
                r"format [a-z]:": 10,
                r"net user.* /add": 6,
                r"net localgroup administrators.* /add": 7,
                r"reg.* delete": 6,
                r"taskkill /f": 3,
                r"attrib \+[rhs]": 4,
                r"shutdown /[rs]": 5,
                r"netsh firewall.* disable": 7,
                r"copy.*\.exe %appdata%": 6,
                r"copy.*\.vbs %startup%": 6,
                r"schtasks.* /create": 5,
                r"wmic.*process call create": 6,
                r"powershell -e": 7,
                r"curl.exe.*\.exe|wget.exe.*\.exe": 5,
                r"echo.*\|.*assoc": 6
            }
            
            import re
            for pattern, risk_score in dangerous_commands.items():
                if re.search(pattern, content, re.IGNORECASE):
                    score += risk_score
                    threat_details.append(f"Commande dangereuse: {pattern}")
            if "copy %0" in content:
                score += 5
                threat_details.append("Auto-réplication détectée")
            startup_paths = ["startup", "winlogon", "run /reg", "hkcu\\software\\microsoft\\windows\\currentversion\\run"]
            for path in startup_paths:
                if path in content:
                    score += 4
                    threat_details.append(f"Mécanisme de persistance: {path}")
            final_score = min(10, score / 5)
            result["score"] = round(final_score, 1)
            result["is_malicious"] = final_score >= 5
            if result["is_malicious"]:
                result["message"] = f"Script batch potentiellement malveillant (score: {result['score']})"
                for detail in threat_details:
                    result["threats"].append({
                        "type": "batch_suspicious_code",
                        "name": detail,
                        "category": "suspicious"
                    })
            else:
                result["message"] = "Aucun comportement malveillant détecté dans le script batch"
            result["scan_details"] = {
                "suspicious_patterns_found": len(threat_details),
                "details": threat_details
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse du fichier batch: {str(e)}")
            result["error"] = str(e)
        
        return result


    
    def _analyze_content(self, content):
        findings = {}
        for category, patterns in self.dangerous_commands.items():
            findings[category] = []
            
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    command = match.group(0).strip()
                    if command not in findings[category]:
                        findings[category].append(command)
        
        return findings
    
    def _calculate_risk_score(self, findings, content):
        base_score = 0
        for category, commands in findings.items():
            count = len(commands)
            if count == 0:
                continue
            if category == "network":
                base_score += min(25, count * 5)
            elif category == "exec":
                base_score += min(30, count * 6)
            elif category == "registry":
                base_score += min(20, count * 5)
            elif category == "system":
                base_score += min(20, count * 4)
            elif category == "deletion":
                base_score += min(15, count * 5)
            elif category == "obfuscation":
                base_score += min(25, count * 8)

        critical_bonus = 0

        if findings.get("network") and findings.get("exec"):
            critical_bonus += 15

        if findings.get("registry") and findings.get("exec"):
            critical_bonus += 10

        additional_factors = 0

        if len(content) < 500 and base_score > 20:
            additional_factors += 10

        if re.search(r'powershell.*-e(nc|ncodedCommand)', content, re.IGNORECASE):
            additional_factors += 15

        risk_score = min(100, base_score + critical_bonus + additional_factors)
        return risk_score
