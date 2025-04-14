import os
import re
import time
import logging
import base64
from typing import Dict, Any, List, Optional
from .base_scanner import BaseScanner, ScannerException

logger = logging.getLogger(__name__)

class JavaScriptScanner(BaseScanner):    
    def __init__(self):
        super().__init__()
        self.name = "JavaScript Scanner"
        self.description = "Scanner pour scripts JavaScript"
        self.supported_extensions = ["js", "mjs", "jsx", "cjs", "ts", "html", "htm"]
        self.dangerous_functions = {
            "execution": [
                r"eval\s*\(",
                r"Function\s*\(\s*['\"]",
                r"new\s+Function\s*\(",
                r"setTimeout\s*\(\s*(?:['\"](.*?)['\"]\s*,|([^,]*),)",
                r"setInterval\s*\(\s*(?:['\"](.*?)['\"]\s*,|([^,]*),)",
                r"document\.write\s*\(",
                r"window\.execScript\s*\(",
                r"document\.createElement\s*\(\s*['\"]script['\"]\s*\)",
            ],
            "command_execution": [
                r"process\.exec\s*\(",
                r"child_process",
                r"spawn\s*\(",
                r"execSync\s*\(",
                r"shelljs",
                r"require\s*\(\s*['\"]child_process['\"]",
                r"require\s*\(\s*['\"]shelljs['\"]",
                r"Runtime\.exec\s*\(",
            ],
            "data_exfiltration": [
                r"\.ajax\s*\(",
                r"fetch\s*\(",
                r"XMLHttpRequest",
                r"navigator\.sendBeacon",
                r"WebSocket",
                r"\.post\s*\(",
                r"\.get\s*\(",
                r"\.send\s*\(",
                r"localStorage\.(get|set)Item",
                r"document\.cookie",
            ],
            "dom_manipulation": [
                r"document\.getElementById\s*\(\s*['\"](.*?)['\"]\s*\)\.innerHTML\s*=",
                r"\.innerHTML\s*=",
                r"\.outerHTML\s*=",
                r"document\.body\.appendChild",
                r"document\.write\s*\(",
                r"document\.writeln\s*\(",
                r"document\.domain\s*=",
                r"location\.href\s*=",
                r"window\.location\s*=",
                r"document\.location\s*=",
                r"location\.replace\s*\(",
            ],
            "browser_exploitation": [
                r"window\.parent",
                r"window\.opener",
                r"window\.top",
                r"document\.referrer",
                r"window\.name\s*=",
                r"iframe\.contentDocument",
                r"\.postMessage\s*\(",
                r"navigator\.userAgent",
                r"history\.pushState\s*\(",
                r"onpageshow",
            ],
            "credentials": [
                r"password",
                r"credential",
                r"auth_token",
                r"apikey",
                r"secret",
                r"authorization",
                r"Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*",
            ],
            "storage_access": [
                r"localStorage",
                r"sessionStorage",
                r"indexedDB",
                r"document\.cookie",
                r"navigator\.clipboard",
                r"FileReader",
                r"CacheStorage",
            ],
            "crypto_mining": [
                r"CoinHive",
                r"mining",
                r"miner",
                r"hashrate",
                r"cryptonight",
                r"coinhive",
                r"minero",
                r"monero",
                r"jsecoin",
                r"webmining",
            ],
        }
        
        self.obfuscation_patterns = [
            r"\beval\s*\(\s*([^)]+)\s*\)",  
            r"\bunescape\s*\(\s*([^)]+)\s*\)",  
            r"\bdecodeURIComponent\s*\(\s*([^)]+)\s*\)",  
            r"\batob\s*\(\s*([^)]+)\s*\)",  
            r"\bString\.fromCharCode\s*\(([^)]+)\)",  
            r"\b(\w+)\s*=\s*\[.*?\];\s*\1\.join\s*\(\s*['\"]{2}\s*\)",  
            r"\b(\w+)\s*=\s*['\"]{1}([^'\"]+)['\"]{1};\s*\1=\s*\1\.split\s*\(\s*['\"]{1}([^'\"]+)['\"]{1}\s*\)", 
            r"(\w+)\s*=\s*['\"](.*?)['\"]\.replace\s*\(\s*/.*?/g,\s*['\"].*?['\"]\s*\)",  
            r"((?:var|let|const)\s+\w+\s*=\s*(['\"]).{0,10}(?:\\\w{1,3}|\\\x[\da-fA-F]{2}|\\\u[\da-fA-F]{4}).{0,40}\2)",  
            r"/\*(?:[\s\S]*?)\*/\[\s*['\"](.*?)['\"]\s*\]\s*\(\s*\)",  
            r"\\u00[a-fA-F0-9]{2}\\u00[a-fA-F0-9]{2}",  
            r"\\x[a-fA-F0-9]{2}\\x[a-fA-F0-9]{2}",  
            r"^\s*(?:var|let|const|,)\s+\w{1,2}\s*,\s*\w{1,2}\s*,\s*\w{1,2}.*;$",  
            r"function\s*\(\s*\w{1,2}\s*,\s*\w{1,2}\s*,\s*\w{1,2}\s*\)",  
            r"(?:\d+)[+](?:\d+)\[(?:\d+)\]",  
            r"\([\"\']\+[\"\'].*?[\"\\']\+[\"\']\)\.split\(\[\"\'\]\)",  
        ]
        self.encoding_patterns = [
            (r'atob\s*\(\s*[\'\"](.*?)[\'\"]', "base64"),
            (r'btoa\s*\(\s*[\'\"](.*?)[\'\"]', "base64_encode"),
            (r'decodeURIComponent\s*\(\s*[\'\"](.*?)[\'\"]', "uri"),
            (r'escape\s*\(\s*[\'\"](.*?)[\'\"]', "uri_encode"),
            (r'unescape\s*\(\s*[\'\"](.*?)[\'\"]', "uri_decode"),
            (r'JSON\.parse\s*\(\s*[\'\"](.*?)[\'\"]', "json"),
            (r'String\.fromCharCode\s*\((.*?)\)', "char_code"),
        ]
        self.suspicious_string_patterns = [
            r"(?:https?|wss?|ftp)://[\w\-\.]+\.\w+/[\w\-\./?=%&]+",
            r"\b(?:admin|administrator|root|password|passwd|pwd|login|auth)\b", 
            r"\b(?:token|apikey|api_key|secret|key|credential)\b", 
            r"\b(?:hack|exploit|bypass|crack|bruteforce|backdoor)\b",  
            r"\b(?:payload|injection|xss|csrf|cookie|hijack|steal)\b",  
            r"\b(?:trojan|virus|malware|ransomware|spyware|adware|worm)\b", 
            r"\b(?:cryptominer|coinhive|monero|bitcoin|ethereum)\b", 
        ]
        self.malware_signatures = {
            "xss": [
                r"document\.cookie",
                r"<(?:script|img|iframe)[^>]*?>",
                r"onerror\s*=",
                r"onload\s*=",
                r"javascript:.*?alert\s*\(",
            ],
            "csrf": [
                r"\.(?:form|submit)\(",
                r"document\.createElement\s*\(\s*['\"]form['\"]\s*\)",
                r"\.(?:method|action)\s*=",
                r"\.(?:submit)\s*\(\s*\)",
            ],
            "malware_dropper": [
                r"document\.write\s*\(\s*[\'\"]<(?:script|iframe)[^>]*src=[\'\"](https?://[^\'\"]+)[\'\"]\s*>\s*<\/(?:script|iframe)>[\'\"]\s*\)",
                r"\.(?:href|src)\s*=\s*['\"](?:javascript|data):.*?\\x",
                r"\.(?:innerHTML|outerHTML)\s*=\s*[\'\"]<(?:script|iframe)[^>]*>",
                r"\.(?:createObjectURL|createBlobURL)\s*\(.*?new\s+Blob",
            ],
            "crypto_mining": [
                r"new\s+(?:CoinHive|WebMiner)",
                r"\.(?:mine|start|setThrottle|setNumThreads)",
                r"new\s+CryptoMiner",
                r"new\s+WebWorker\s*\(\s*['\"]min(?:e|er)\.js['\"]",
                r"new\s+Worker\s*\(\s*['\"]min(?:e|er)\.js['\"]",
            ],
            "information_stealer": [
                r"\.(?:getElementsByTagName|querySelector)\s*\(\s*['\"]form[\'\"]",
                r"\.(?:getElementsByTagName|querySelector)\s*\(\s*['\"]input[\'\"]",
                r"\.(?:value|innerHTML|innerText)\s*\+?=",
                r"\.(?:send|post|fetch)\s*\(\s*.*?(?:password|login|username|email)",
            ],
            "browser_hijacker": [
                r"window\.location\s*=\s*['\"]https?://",
                r"document\.location\s*=\s*['\"]https?://",
                r"location\.href\s*=\s*['\"]https?://",
                r"window\.open\s*\(\s*['\"]https?://",
                r"\.(?:replace|assign)\s*\(\s*['\"]https?://",
            ],
        }
    
    def can_scan(self, file_path):
        extension = self.get_file_extension(file_path)
        if extension in self.supported_extensions:
            return True
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(4096)
                js_signatures = [
                    r'function\s+\w+\s*\(',
                    r'var\s+\w+\s*=',
                    r'let\s+\w+\s*=',
                    r'const\s+\w+\s*=',
                    r'document\.getElementById',
                    r'window\.',
                    r'document\.',
                    r'console\.log',
                    r'export\s+default',
                    r'import\s+.*\s+from',
                    r'//\s*@ts-check'
                ]
                for signature in js_signatures:
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
        
        logger.info(f"Analyse du script JavaScript: {file_path}")
        
        try:
            has_eicar = False
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                if "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in content:
                    has_eicar = True
                    logger.warning(f"Signature EICAR détectée dans {file_path}")
                    result["is_malicious"] = True
                    result["score"] = 10.0
                    result["threats"] = [{
                        "type": "eicar_test_signature",
                        "name": "Signature de test antivirus EICAR",
                        "description": "Le fichier contient la signature de test antivirus standard EICAR",
                        "severity": "high"
                    }]
                    result["message"] = "Fichier contenant la signature EICAR (test antivirus) détecté!"
                    result["scan_time"] = time.time() - start_time
                    return result
            self.content = content
            file_size = os.path.getsize(file_path)
            result["scan_details"]["file_size"] = file_size
            obfuscation = self._detect_obfuscation(content)
            result["scan_details"]["obfuscation"] = obfuscation
            dangerous_functions = self._detect_dangerous_functions(content)
            result["scan_details"]["dangerous_functions"] = dangerous_functions
            encodings = self._detect_encodings(content)
            result["scan_details"]["encodings"] = encodings
            try:
                deobfuscated_content = self._simple_deobfuscation(content)
                if deobfuscated_content != content:
                    deobfuscated_analysis = {
                        "dangerous_functions": self._detect_dangerous_functions(deobfuscated_content),
                        "suspicious_strings": self._detect_suspicious_strings(deobfuscated_content)
                    }
                    result["scan_details"]["deobfuscated_analysis"] = deobfuscated_analysis
            except Exception as e:
                logger.debug(f"Erreur lors de la déobfuscation: {str(e)}")
            suspicious_strings = self._detect_suspicious_strings(content)
            result["scan_details"]["suspicious_strings"] = suspicious_strings
            malware_signatures = self._detect_malware_signatures(content)
            result["scan_details"]["malware_signatures"] = malware_signatures
            risk_score, reasons = self._calculate_risk_score(
                obfuscation,
                dangerous_functions,
                encodings,
                suspicious_strings,
                malware_signatures,
                file_size
            )
            result["risk_score"] = risk_score
            result["scan_details"]["risk_factors"] = reasons
            if file_size < 1000:
                logger.info(f"Script JS de petite taille ({file_size} octets), vérification approfondie...")
                eicar_pattern = r"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR"
                if re.search(eicar_pattern, content, re.IGNORECASE):
                    result["is_malicious"] = True
                    result["score"] = 10.0
                    result["threats"].append({
                        "type": "eicar_test",
                        "name": "Signature EICAR détectée",
                        "description": "Le fichier contient la signature de test antivirus EICAR",
                        "severity": "high"
                    })
                    result["message"] = "Fichier contenant la signature EICAR détecté!"
                    return result
                for pattern in ["keylogger", "eval", "exploit", "backdoor"]:
                    if re.search(r'\b' + pattern + r'\b', content, re.IGNORECASE):
                        risk_score = max(risk_score, 6.0)
                        break
            if risk_score >= 5.0:
                result["is_malicious"] = True
                result["score"] = risk_score
                result["threats"] = self._generate_threat_list(
                    obfuscation,
                    dangerous_functions,
                    suspicious_strings,
                    malware_signatures
                )
                result["message"] = f"Script JavaScript potentiellement malveillant (score: {risk_score:.1f}/10)"
            else:
                result["is_malicious"] = False
                result["score"] = risk_score
                result["message"] = "Aucun comportement malveillant détecté dans le script JavaScript"
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse du script JavaScript {file_path}: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            result["error"] = str(e)
            result["is_malicious"] = False
            result["score"] = 0
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
                    "examples": [str(m)[:50] for m in matches[:3]]
                })
        eval_pattern = r"eval\s*\(\s*['\"](.{50,})['\"]"
        eval_matches = re.findall(eval_pattern, content)
        if eval_matches:
            result["techniques_count"] += len(eval_matches)
            result["techniques"].append({
                "pattern": "eval_with_long_string",
                "count": len(eval_matches),
                "examples": [m[:50] + "..." for m in eval_matches[:3]]
            })
        base64_pattern = r"['\"]([A-Za-z0-9+/]{30,}={0,2})['\"]"
        base64_matches = re.findall(base64_pattern, content)
        if base64_matches:
            valid_base64 = []
            for match in base64_matches:
                try:
                    decoded = base64.b64decode(match)
                    if all(32 <= b <= 126 for b in decoded[:20]):
                        valid_base64.append(match)
                except:
                    pass
            
            if valid_base64:
                result["techniques_count"] += len(valid_base64)
                result["techniques"].append({
                    "pattern": "base64_encoded_data",
                    "count": len(valid_base64),
                    "examples": [b[:30] + "..." for b in valid_base64[:3]]
                })
        return result
    
    def _detect_dangerous_functions(self, content):
        result = {
            "total_count": 0,
            "categories": {}
        }
        for category, patterns in self.dangerous_functions.items():
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
                for match in matches[:3]:
                    match_str = match if isinstance(match, str) else match[0]
                    if len(match_str) > 50:
                        match_str = match_str[:47] + "..."
                    result["types"][encoding_type]["examples"].append(match_str)
        return result
    
    def _simple_deobfuscation(self, content):        
        deobfuscated = content
        def replace_unicode(match):
            try:
                return chr(int(match.group(1), 16))
            except:
                return match.group(0)
        
        deobfuscated = re.sub(r'\\u([0-9a-fA-F]{4})', replace_unicode, deobfuscated)
        def replace_hex(match):
            try:
                return chr(int(match.group(1), 16))
            except:
                return match.group(0)
        
        deobfuscated = re.sub(r'\\x([0-9a-fA-F]{2})', replace_hex, deobfuscated)
        def replace_octal(match):
            try:
                return chr(int(match.group(1), 8))
            except:
                return match.group(0)
        deobfuscated = re.sub(r'\\([0-7]{1,3})', replace_octal, deobfuscated)
        deobfuscated = re.sub(r'\/\*\*\/', '', deobfuscated)
        deobfuscated = re.sub(r'\/\*\s*\*\/', '', deobfuscated)
        def decode_base64(match):
            try:
                decoded = base64.b64decode(match.group(1)).decode('utf-8')
                return f'/* Decoded Base64: {decoded} */'
            except:
                return match.group(0)
        deobfuscated = re.sub(r'atob\s*\(\s*[\'"]([A-Za-z0-9+/=]+)[\'"]\s*\)', decode_base64, deobfuscated)
        return deobfuscated
    
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
        eicar_patterns = [
            r"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
            r"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        ]
        
        for pattern in eicar_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                result["strings"].append("EICAR Test Signature")
                result["total_count"] += 1
        result["strings"] = result["strings"][:10]
        
        return result

    def _calculate_risk_score(self, obfuscation, dangerous_functions, encodings, 
                             suspicious_strings, malware_signatures, file_size):
        score = 0
        reasons = []
        if obfuscation["techniques_count"] > 0:
            obfuscation_score = min(3.0, obfuscation["techniques_count"] * 0.5)
            score += obfuscation_score
            reasons.append(f"Obfuscation ({obfuscation['techniques_count']} techniques): +{obfuscation_score:.1f}")
        if dangerous_functions["total_count"] > 0:
            category_weights = {
                "execution": 1.5,
                "command_execution": 2.0,
                "data_exfiltration": 1.2,
                "dom_manipulation": 0.8,
                "browser_exploitation": 1.0,
                "credentials": 1.0,
                "storage_access": 0.5,
                "crypto_mining": 2.0
            }
            df_score = 0
            for category, findings in dangerous_functions["categories"].items():
                category_score = findings["count"] * category_weights.get(category, 0.5)
                df_score += category_score
                reasons.append(f"Fonctions {category} ({findings['count']}): +{category_score:.1f}")
            df_score = min(4.0, df_score)
            score += df_score
        if encodings["total_count"] > 0:
            encoding_score = min(1.0, encodings["total_count"] * 0.2)
            score += encoding_score
            reasons.append(f"Encodages ({encodings['total_count']}): +{encoding_score:.1f}")
        if suspicious_strings["total_count"] > 0:
            strings_score = min(2.0, suspicious_strings["total_count"] * 0.4)
            score += strings_score
            reasons.append(f"Chaînes suspectes ({suspicious_strings['total_count']}): +{strings_score:.1f}")
            if "EICAR Test Signature" in suspicious_strings.get("strings", []):
                eicar_bonus = 5.0
                score += eicar_bonus
                reasons.append(f"Signature de test EICAR détectée: +{eicar_bonus:.1f}")
        if malware_signatures["total_count"] > 0:
            signature_score = 0
            for category, findings in malware_signatures["categories"].items():
                category_weight = 2.0 if category in ["crypto_mining", "information_stealer", "malware_dropper"] else 1.5
                category_score = findings["count"] * category_weight
                signature_score += category_score
                reasons.append(f"Signature {category} ({findings['count']}): +{category_score:.1f}")
            signature_score = min(5.0, signature_score)
            score += signature_score
        if file_size < 5000 and obfuscation["techniques_count"] > 2:
            small_obfuscated_score = 1.0
            score += small_obfuscated_score
            reasons.append(f"Petit script fortement obfusqué: +{small_obfuscated_score:.1f}")
        has_xhr = re.search(r'(XMLHttpRequest|fetch|\.send\()', content, re.IGNORECASE)
        has_form = re.search(r'(getElementById|querySelector).*(?:password|login|username|email)', content, re.IGNORECASE)
        has_event_listener = re.search(r'addEventListener.*(?:keydown|keypress|submit)', content, re.IGNORECASE)
        
        if has_xhr and has_form:
            combo_score = 2.0
            score += combo_score
            reasons.append(f"Combinaison formulaire + communication réseau: +{combo_score:.1f}")
        if has_event_listener and (has_xhr or "keylog" in content.lower()):
            keylog_score = 3.0
            score += keylog_score
            reasons.append(f"Comportement potentiel de keylogger: +{keylog_score:.1f}")
        score = min(10.0, score)
        return score, reasons

    def _generate_threat_list(self, obfuscation, dangerous_functions, suspicious_strings, malware_signatures):
        threats = []
        content = getattr(self, 'content', '')
        if "EICAR Test Signature" in suspicious_strings.get("strings", []):
            threats.append({
                "type": "eicar_test_signature",
                "name": "Signature de test antivirus EICAR",
                "description": "Le fichier contient la signature de test antivirus standard EICAR",
                "severity": "high"
            })
        if obfuscation["techniques_count"] > 2:
            threats.append({
                "type": "obfuscation",
                "name": "JavaScript obfusqué",
                "description": f"Script utilisant {obfuscation['techniques_count']} techniques d'obfuscation",
                "severity": "medium" if obfuscation["techniques_count"] > 5 else "low"
            })
        if content and re.search(r'addEventListener.*(?:keydown|keypress)', content, re.IGNORECASE):
            threats.append({
                "type": "keylogger_behavior",
                "name": "Comportement de keylogger",
                "description": "Le script contient du code qui pourrait être utilisé pour enregistrer les frappes au clavier",
                "severity": "medium"
            })
        if content and re.search(r'(getElementById|querySelector).*(?:password|login|username|email)', content, re.IGNORECASE) and \
           re.search(r'(XMLHttpRequest|fetch|\.send\()', content, re.IGNORECASE):
            threats.append({
                "type": "data_exfiltration",
                "name": "Exfiltration potentielle de données",
                "description": "Le script contient du code qui pourrait être utilisé pour exfiltrer des données sensibles",
                "severity": "high"
            })
        for category, findings in dangerous_functions.get("categories", {}).items():
            if findings["count"] > 0:
                severity = "high" if category in ["execution", "command_execution", "crypto_mining"] else "medium"
                threats.append({
                    "type": f"dangerous_function_{category}",
                    "name": f"Fonctions dangereuses - {category}",
                    "description": f"Utilisation de fonctions de type {category}: {', '.join(findings['examples'][:3])}",
                    "severity": severity
                })
        for category, findings in malware_signatures.get("categories", {}).items():
            if findings["count"] > 0:
                severity = "high" if category in ["crypto_mining", "information_stealer", "malware_dropper"] else "medium"
                threats.append({
                    "type": f"malware_signature_{category}",
                    "name": f"Signature de malware - {category}",
                    "description": f"Détection de pattern {category}: {findings['examples'][0] if findings['examples'] else 'multiple patterns'}",
                    "severity": severity
                })
        if suspicious_strings.get("total_count", 0) > 3:
            threats.append({
                "type": "suspicious_strings",
                "name": "Chaînes suspectes multiples",
                "description": f"Présence de {suspicious_strings['total_count']} chaînes suspectes: {', '.join(suspicious_strings.get('strings', [])[:3])}",
                "severity": "low"
            })
        return threats

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
            "file_name": ""
        }
