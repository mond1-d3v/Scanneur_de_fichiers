import os
import re
import ast
import time
import logging
import tokenize
from typing import Dict, Any, List, Optional, Tuple
from io import BytesIO
from .base_scanner import BaseScanner, ScannerException
logger = logging.getLogger(__name__)

class PythonScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.name = "PythonScanner"
        self.description = "Analyse les scripts Python"
        
        self.logger = logging.getLogger(__name__)
        self.dangerous_imports = {
            "keylogger": ["pynput", "keyboard", "pyHook", "pythoncom"],
            "backdoor": ["socket", "paramiko", "telnetlib"],
            "ransomware": ["cryptography", "Crypto", "Fernet", "pyAesCrypt"],
            "trojan": ["winreg", "win32con", "win32api", "ctypes"],
            "spyware": ["pyautogui", "PIL", "pyscreenshot", "cv2"]
        }
        
        self.dangerous_functions = [
            "exec", "eval", "system", "popen", "call", "Popen",
            "compile", "execfile", "input", "__import__"
        ]
        
        self.obfuscation_patterns = [
            r'\\x[0-9a-fA-F]{2}',
            r'\\u[0-9a-fA-F]{4}',
            r'__getattr__\s*$',
            r'getattr\s*\(',
            r'setattr\s*\(',
            r'lambda\s+\w+\s*:\s*.+',
            r'chr\(\d+\s*\+',
            r'__import__\s*\('
        ]
        self.threat_patterns = {
            "backdoor": [
                r"socket\s*$ \s*socket\.AF_INET\s*,\s*socket\.SOCK_STREAM\s* $ ",
                r"bind\s*$ \s*\(\s*.*\s*,\s*\d+\s* $ \s*\)",
                r"listen\s*$ \s*\d+\s* $ ",
                r"accept\s*$ \s* $ ",
                r"os\.system\s*$ \s*.*\s* $ ",
                r"subprocess\.(?:call|Popen|run|check_output)",
                r"exec\s*$ \s*.*\s* $ ",
                r"eval\s*$ \s*.*\s* $ "
            ],
            "keylogger": [
                r"pynput\.keyboard",
                r"keyboard\.Listener",
                r"on_press",
                r"on_release",
                r"keylogger",
                r"GetAsyncKeyState",
                r"GetKeyboardState",
                r"hook_manager",
                r"HookManager",
            ],
            "ransomware": [
                r"Fernet",
                r"encrypt",
                r"decrypt",
                r"\.encrypt\s*$ \s*.*\s* $ ",
                r"\.decrypt\s*$ \s*.*\s* $ ",
                r"recursive",
                r"ransom",
                r"crypto",
                r"\.walk\s*$ \s*.*\s* $ ",
                r"\.listdir\s*$ \s*.*\s* $ ",
                r"glob\.glob\s*$ \s*.*\s* $ "
            ],
            "trojan": [
                r"system32",
                r"regedit",
                r"registry",
                r"HKEY_LOCAL_MACHINE",
                r"HKEY_CURRENT_USER",
                r"winreg",
                r"_winreg",
                r"(?:add|remove|modify)_startup",
                r"startup folder",
                r"autorun"
            ],
            "botnet": [
                r"irc\.connect\s*$ \s*.*\s* $ ",
                r"bot\.join_channel\s*$ \s*.*\s* $ ",
                r"bot\.send_message\s*$ \s*.*\s* $ "
            ],
            "malicious_import": [
                r"import\s+pyHook",
                r"import\s+win32crypt",
                r"import\s+pythoncom",
                r"import\s+win32con",
                r"import\s+win32api",
                r"import\s+pynput",
                r"from\s+pynput\s+import",
                r"import\s+keyboard",
                r"from\s+keyboard\s+import",
                r"import\s+cryptography",
                r"from\s+cryptography\s+import",
                r"import\s+paramiko",
                r"from\s+paramiko\s+import",
            ],
            "network_abuse": [
                r"requests\.post\s*$ \s*.*\s* $ ",
                r"urllib\.request\.urlopen\s*$ \s*.*\s* $ ",
                r"socket\.connect\s*$ \s*.*\s* $ ",
                r"ftp\.login\s*$ \s*.*\s* $ ",
                r"smtp\.sendmail\s*$ \s*.*\s* $ "
            ],
            "spyware": [
                r"pyautogui\.screenshot",
                r"ImageGrab\.grab",
                r"clipboard",
                r"cv2\.VideoCapture",
                r"browser_history",
                r"cookie_theft",
                r"credentials",
                r"password"
            ]
        }
        
    def can_scan(self, file_path: str) -> bool:
        self.logger.debug(f"PythonScanner: vérification du fichier {file_path}")  # Log pour débogage
        return file_path.lower().endswith('.py')
        
    def scan(self, file_path: str) -> Dict[str, Any]:
        self.logger.info(f"Analyse du fichier Python: {file_path}")
        
        if not os.path.exists(file_path):
            self.logger.error(f"Le fichier {file_path} n'existe pas")
            return {"is_malicious": False, "score": 0, "threats": []}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            malicious_keywords = [
                "keylogger", "pynput.keyboard", "GetAsyncKeyState", "on_press", "key_logger",
                "socket.socket", "socket.connect", "os.system", "subprocess.call", 
                "Fernet", "encrypt", "ransom", "getpass", "win32crypt", "chrome",
                "credentials", "password", "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER"
            ]
            threats = []
            
            for keyword in malicious_keywords:
                if keyword.lower() in content.lower():
                    threats.append({
                        "type": "malicious_code",
                        "name": f"Mot-clé malicieux: {keyword}",
                        "description": f"Mot-clé potentiellement malicieux détecté: {keyword}",
                        "severity": "high"
                    })
                    self.logger.warning(f"Menace détectée: {keyword}")
            import_analysis = self._analyze_imports(content, file_path)
            for dangerous_import in import_analysis.get("dangerous_imports", []):
                threats.append({
                    "type": "malicious_import",
                    "name": f"Import suspect: {dangerous_import['module']}",
                    "description": f"Module potentiellement dangereux: {dangerous_import['module']} (catégorie: {dangerous_import['category']})",
                    "severity": "medium"
                })
            explicit_threats = self._detect_explicit_threats(content)
            for threat in explicit_threats:
                if isinstance(threat, dict) and "category" in threat:
                    threats.append({
                        "type": threat["category"],
                        "name": threat.get("name", threat["category"].capitalize()),
                        "description": f"Detected: {threat.get('matched_text', 'unknown pattern')}",
                        "severity": "high"
                    })
                else:
                    if threat not in threats:
                        threats.append(threat)
            if "keyboard" in content.lower() and any(word in content.lower() for word in ["write", "file", "send", "socket"]):
                threats.append({
                    "type": "keylogger",
                    "name": "Comportement de Keylogger",
                    "description": "Capture de clavier et envoi de données détectés",
                    "severity": "high"
                })
                self.logger.warning("Comportement de keylogger détecté")
            score = self._calculate_risk_score(threats)
            is_malicious = score >= 5
            if 'keylogger' in os.path.basename(file_path).lower():
                is_malicious = True
                score = max(7, score)
                if not any(t.get('type') == 'keylogger' for t in threats):
                    threats.append({
                        "type": "keylogger",
                        "name": "Python.Keylogger",
                        "description": "Enregistreur de frappe clavier détecté par nom de fichier",
                        "severity": "high"
                    })
            
            result = {
                "file_path": file_path,
                "file_type": "text/x-python",
                "is_malicious": is_malicious,
                "score": min(10, score),
                "threats": threats,
                "scanner": self.name
            }
            
            self.logger.info(f"Résultat de l'analyse: is_malicious={is_malicious}, score={score}, threats_count={len(threats)}")
            return result
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
            return {
                "error": f"Erreur lors de l'analyse: {str(e)}",
                "is_malicious": False,
                "score": 0,
                "threats": [],
                "scanner": self.name
            }

    def _analyze_imports(self, content, file_path=None):
        result = {
            "dangerous_imports": [],
            "categories": set(),
            "all_imports": []
        }
        import_patterns = [
            r'^\s*import\s+([\w\.]+)(?:\s+as\s+\w+)?',
            r'^\s*from\s+([\w\.]+)\s+import',
            r'__import__\s*\(\s*["\']+([\w\.]+)["\']+'
        ]
        
        for pattern in import_patterns:
            for match in re.finditer(pattern, content, re.MULTILINE):
                module = match.group(1).split('.')[0]
                result["all_imports"].append(module)
        result["all_imports"] = list(set(result["all_imports"]))
        for category, modules in self.dangerous_imports.items():
            for module in modules:
                if module in result["all_imports"]:
                    result["dangerous_imports"].append({
                        "module": module,
                        "category": category
                    })
                    result["categories"].add(category)
                    self.logger.warning(f"Module dangereux détecté: {module} (catégorie: {category})")
        result["categories"] = list(result["categories"])
        
        return result

    
    def _analyze_functions(self, content, file_path):
        result = {
            "dangerous_functions": [],
            "function_calls_count": 0,
            "functions_by_category": {
                "exec": 0,
                "file": 0,
                "system": 0,
                "network": 0,
                "other": 0
            }
        }
        for function in self.dangerous_functions:
            pattern = r'\b' + re.escape(function) + r'\s*\('
            matches = re.findall(pattern, content)
            if matches:
                category = "exec"
                if function in ["open", "write", "read"]:
                    category = "file"
                elif function in ["system", "popen", "spawn", "call", "Popen"]:
                    category = "system"
                
                result["dangerous_functions"].append({
                    "function": function,
                    "count": len(matches),
                    "category": category
                })
                result["functions_by_category"][category] += len(matches)
                result["function_calls_count"] += len(matches)
        try:
            tree = ast.parse(content)
            function_call_count = 0
            class FunctionCallVisitor(ast.NodeVisitor):
                def __init__(self):
                    self.function_calls = {}
                
                def visit_Call(self, node):
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        if func_name not in self.function_calls:
                            self.function_calls[func_name] = 0
                        self.function_calls[func_name] += 1
                    self.generic_visit(node)
            
            visitor = FunctionCallVisitor()
            visitor.visit(tree)
            for func_name, count in visitor.function_calls.items():
                function_call_count += count
                if func_name in self.dangerous_functions:
                    category = "exec"
                    if func_name in ["open", "write", "read"]:
                        category = "file"
                    elif func_name in ["system", "popen", "spawn", "call", "Popen"]:
                        category = "system"
                    found = False
                    for func in result["dangerous_functions"]:
                        if func["function"] == func_name:
                            func["count"] = max(func["count"], count)
                            found = True
                            break
                    
                    if not found:
                        result["dangerous_functions"].append({
                            "function": func_name,
                            "count": count,
                            "category": category
                        })
                        result["functions_by_category"][category] += count
            result["function_calls_count"] = max(result["function_calls_count"], function_call_count)
        
        except SyntaxError:
            pass
        
        return result
    
    def _detect_obfuscation(self, content):
        result = {
            "obfuscation_detected": False,
            "techniques": [],
            "score": 0,
            "indicators": []
        }
        for pattern in self.obfuscation_patterns:
            matches = re.findall(pattern, content)
            if matches:
                result["obfuscation_detected"] = True
                technique = {
                    "pattern": pattern,
                    "matches": len(matches),
                    "examples": matches[:3] if isinstance(matches[0], str) else [m[0] for m in matches[:3]]
                }
                result["techniques"].append(technique)
                result["score"] += min(10, len(matches))
                if "\\x" in pattern:
                    result["indicators"].append("Utilisation excessive de caractères hexadécimaux échappés")
                elif "\\u" in pattern:
                    result["indicators"].append("Utilisation excessive de caractères Unicode échappés")
                elif "__getattr__" in pattern:
                    result["indicators"].append("Accès dynamique aux attributs")
                elif "getattr" in pattern:
                    result["indicators"].append("Utilisation de getattr pour l'accès dynamique")
                elif "setattr" in pattern:
                    result["indicators"].append("Modification dynamique d'attributs")
                elif "lambda" in pattern:
                    result["indicators"].append("Assignation excessive de fonctions lambda")
                elif "chr" in pattern:
                    result["indicators"].append("Construction de chaînes avec chr()")
                elif "__import__" in pattern:
                    result["indicators"].append("Importations dynamiques")
                elif "pyarmor" in pattern or "Cython" in pattern:
                    result["indicators"].append("Utilisation d'outil d'obfuscation commercial")
                else:
                    result["indicators"].append("Modèle d'obfuscation détecté")
        non_ascii_chars = sum(1 for c in content if ord(c) > 127)
        if non_ascii_chars > len(content) * 0.1:  
            result["obfuscation_detected"] = True
            result["techniques"].append({
                "pattern": "non_ascii_ratio",
                "ratio": non_ascii_chars / len(content)
            })
            result["score"] += 15
            result["indicators"].append("Ratio élevé de caractères non-ASCII")
        variable_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]{0,30})\s*='
        variable_names = re.findall(variable_pattern, content)
        
        if variable_names:
            random_looking_vars = 0
            for var in variable_names:
                if len(var) >= 5 and re.match(r'^[a-zA-Z0-9_]+$', var):
                    unique_chars = set(var)
                    if len(unique_chars) / len(var) > 0.7: 
                        random_looking_vars += 1
            
            if random_looking_vars > 5:
                result["obfuscation_detected"] = True
                result["techniques"].append({
                    "pattern": "random_variable_names",
                    "count": random_looking_vars
                })
                result["score"] += min(20, random_looking_vars)
                result["indicators"].append("Noms de variables apparemment aléatoires")
        result["score"] = min(100, result["score"])
        
        return result
    
    def _detect_network_activity(self, content):
        result = {
            "network_activity_detected": False,
            "indicators": [],
            "urls": [],
            "ip_addresses": []
        }
        url_pattern = r'https?://[^\s\'"$\)]{5,}'
        urls = re.findall(url_pattern, content)
        if urls:
            result["network_activity_detected"] = True
            result["urls"] = list(set(urls))[:10]
            result["indicators"].append(f"URLs détectées ({len(urls)})")
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b'
        ips = re.findall(ip_pattern, content)
        if ips:
            result["network_activity_detected"] = True
            result["ip_addresses"] = list(set(ips))[:10]  
            result["indicators"].append(f"Adresses IP détectées ({len(ips)})")
        network_keywords = [
            r'socket\s*\(', r'connect\s*\(', r'bind\s*\(', r'listen\s*\(',
            r'send\s*\(', r'recv\s*\(', r'requests\.', r'urllib\.',
            r'http\.(client|server)', r'ftp', r'smtp', r'telnet',
            r'\.post\s*\(', r'\.get\s*\(', r'\.put\s*\(', r'\.delete\s*\(',
            r'\.request\s*\('
        ]
        
        for keyword in network_keywords:
            if re.search(keyword, content):
                result["network_activity_detected"] = True
                result["indicators"].append(f"Utilisation de fonctions réseau ({keyword.replace('\\s*', ' ')})")
        return result

    def _detect_file_operations(self, content):
        result = {
            "file_operations_detected": False,
            "indicators": [],
            "operations": {
                "read": 0,
                "write": 0,
                "delete": 0,
                "execute": 0
            }
        }
        read_patterns = [
            r'open\s*\([^,)]*,\s*[\'"]r[\'"]',
            r'read\s*\(', r'readline\s*\(', r'readlines\s*\(',
            r'with\s+open\s*\([^,)]*\)\s+as'
        ]
        
        for pattern in read_patterns:
            matches = re.findall(pattern, content)
            if matches:
                result["file_operations_detected"] = True
                result["operations"]["read"] += len(matches)
                result["indicators"].append(f"Lecture de fichiers ({len(matches)})")
        write_patterns = [
            r'open\s*\([^,)]*,\s*[\'"]w[\'"]',
            r'open\s*\([^,)]*,\s*[\'"]a[\'"]',
            r'write\s*\(', r'writelines\s*\('
        ]
        
        for pattern in write_patterns:
            matches = re.findall(pattern, content)
            if matches:
                result["file_operations_detected"] = True
                result["operations"]["write"] += len(matches)
                result["indicators"].append(f"Écriture de fichiers ({len(matches)})")
        delete_patterns = [
            r'os\.(?:unlink|remove)\s*\(',
            r'shutil\.rmtree\s*\(',
            r'os\.rmdir\s*\('
        ]
        
        for pattern in delete_patterns:
            matches = re.findall(pattern, content)
            if matches:
                result["file_operations_detected"] = True
                result["operations"]["delete"] += len(matches)
                result["indicators"].append(f"Suppression de fichiers ({len(matches)})")
        execute_patterns = [
            r'subprocess\.(?:call|check_output|check_call|run|Popen)\s*\(',
            r'os\.(?:system|popen|spawn[lpe]?)\s*\(',
            r'exec\s*\(', r'eval\s*\('
        ]
        
        for pattern in execute_patterns:
            matches = re.findall(pattern, content)
            if matches:
                result["file_operations_detected"] = True
                result["operations"]["execute"] += len(matches)
                result["indicators"].append(f"Exécution de processus ({len(matches)})")
        return result
    
    def _detect_explicit_threats(self, content: str) -> List[Dict[str, Any]]:
        threats = []
        is_malicious = False
        score = 0
        
        try:
            for category, patterns in self.threat_patterns.items():
                for pattern in patterns:
                    try:
                        matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
                        found = len(matches) > 0
                        
                        for match in matches:
                            matched_text = match.group(0)
                            threats.append({
                                "category": category,
                                "pattern": pattern,
                                "name": f"{category.capitalize()} - {matched_text}",
                                "confidence": 0.8, 
                                "line": content[:match.start()].count('\n') + 1,
                                "matched_text": matched_text
                            })
                            self.logger.warning(f"Menace détectée: {category} - {matched_text} à la ligne {content[:match.start()].count('\n') + 1}")
                        
                        if found:
                            is_malicious = True
                            score += 2 
                            self.logger.warning(f"Menace '{pattern}' trouvée dans la catégorie {category}")
                            
                    except Exception as e:
                        self.logger.error(f"Erreur lors de la recherche du pattern '{pattern}': {str(e)}")
            suspicious_behaviors = [
                (r"keyboard", r"write|file|send|socket|http", "Capture de clavier et envoi de données"),
                (r"mouse", r"record|capture", "Capture des mouvements de souris"),
                (r"screenshot", r"capture|save|send", "Capture d'écran"),
                (r"hook", r"keyboard|key", "Interception des entrées clavier")
            ]

            for behavior in suspicious_behaviors:
                trigger1, trigger2, description = behavior
                if re.search(trigger1, content, re.IGNORECASE) and re.search(trigger2, content, re.IGNORECASE):
                    threats.append({
                        "type": "malicious_behavior",
                        "description": description,
                        "severity": "high"
                    })
                    is_malicious = True
                    score += 3 
        except Exception as e:
            self.logger.error(f"Erreur globale dans _detect_explicit_threats: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())

        self.logger.info(f"Total des menaces détectées: {len(threats)}")
        return threats

    def _calculate_risk_score(self, threats):
        if not threats:
            return 0
            
        score = 0
        for threat in threats:
            severity = threat.get('severity', 'medium').lower()
            
            if 'keylogger' in str(threat).lower():
                score += 8
            elif 'ransomware' in str(threat).lower():
                score += 9 
            elif severity == 'critical':
                score += 5
            elif severity == 'high':
                score += 3
            elif severity == 'medium':
                score += 2
            else:
                score += 1
        if len(threats) >= 3:
            score += 5
        elif len(threats) >= 2:
            score += 3
        self.logger.info(f"Score de risque calculé: {score}")
        return score
    def _debug_file_content(self, file_path: str) -> None:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            keylogger_keywords = ["keyboard", "key", "press", "hook", "keylogger", "keystroke", "record", "pynput"]
            for keyword in keylogger_keywords:
                matches = list(re.finditer(r'\b' + keyword + r'\b', content, re.IGNORECASE))
                if matches:
                    positions = [f"ligne {content[:m.start()].count('\n') + 1}" for m in matches]
                    self.logger.info(f"DEBUG: Mot-clé '{keyword}' trouvé aux positions: {', '.join(positions)}")
            self.logger.info(f"DEBUG: Taille du fichier: {len(content)} caractères")
            self.logger.info(f"DEBUG: Début du fichier: {content[:200]}")
            self.logger.info(f"DEBUG: Fin du fichier: {content[-200:]}")
            
        except Exception as e:
            self.logger.error(f"Erreur lors du debugging du fichier: {str(e)}")
