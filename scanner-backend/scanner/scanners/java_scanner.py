import os
import re
import time
import logging
from typing import Dict, Any, List, Optional
from .base_scanner import BaseScanner, ScannerException

logger = logging.getLogger(__name__)

class JavaScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.name = "Java Scanner"
        self.description = "Analyse les fichiers source Java"
        self.supported_extensions = ["java", "jsp", "jspx", "class"]
        self.dangerous_functions = {
            "exec": [
                "Runtime.getRuntime()", "exec(", "ProcessBuilder", 
                "Process", "start()", "getRuntime().exec"
            ],
            "reflection": [
                "Class.forName", "ClassLoader", "loadClass", "defineClass",
                "getMethod", "invoke", "getField", "getDeclaredMethod",
                "getDeclaredField", "setAccessible"
            ],
            "network": [
                "Socket", "ServerSocket", "HttpURLConnection", "URL",
                "InetAddress", "openConnection", "connect(", "accept(",
                "HttpClient", "send(", "openStream", "getInputStream"
            ],
            "file": [
                "File", "FileInputStream", "FileOutputStream", "RandomAccessFile",
                "createNewFile", "FileWriter", "FileReader", "getPath",
                "delete(", "mkdir(", "renameTo(", "exists(", "canWrite", 
                "canRead", "createTempFile", "Paths.get"
            ],
            "privilege": [
                "SecurityManager", "doPrivileged", "setSecurityManager",
                "getSecurityManager", "checkPermission", "AccessController",
                "privileged", "elevate", "sudo", "permissions", "grant"
            ],
            "serialization": [
                "Serializable", "readObject", "writeObject", "ObjectInputStream",
                "ObjectOutputStream", "externalizable", "readExternal", 
                "writeExternal", "serialVersionUID"
            ],
            "crypto": [
                "Cipher", "encrypt", "decrypt", "getInstance", "MessageDigest",
                "KeyGenerator", "SecretKey", "PrivateKey", "PublicKey", 
                "doFinal", "initSign", "initVerify", "KeyStore"
            ],
            "database": [
                "Connection", "Statement", "PreparedStatement", "DriverManager",
                "executeQuery", "executeUpdate", "execute(", "getConnection",
                "setString", "setInt", "ResultSet", "createStatement"
            ],
            "xml": [
                "DocumentBuilder", "SAXParser", "SAXReader", "XMLReader",
                "XPath", "XMLStreamReader", "XMLInputFactory", "JAXB",
                "Marshall", "Unmarshall", "setFeature", "setProperty"
            ],
            "jndi": [
                "InitialContext", "lookup", "bind", "rebind", "listBindings",
                "NamingEnumeration", "Context.", "DirContext", "JNDI", 
                "ReferenceWrapper", "Reference"
            ],
            "deserialization": [
                "readObject(", "readUnshared(", "ObjectInputStream", 
                "deserialize", "fromXML", "fromJSON", "parseObject"
            ],
            "classloading": [
                "URLClassLoader", "CustomClassLoader", "loadClass(", 
                "findClass(", "defineClass(", "resolveClass("
            ]
        }
        self.malicious_patterns = {
            "shellcode": [
                r"new\s+byte\s*\[\]\s*\{.*0x[0-9a-fA-F]{2}", 
                r"(\{\s*[0-9]{1,3}\s*,\s*){10,}",  
                r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}", 
            ],
            "backdoor": [
                r"ServerSocket\s*\(\s*\d+\s*\)",
                r"Socket\s*\(\s*\".*\"\s*,\s*\d+\s*\)",  
                r"accept\s*\(\s*\)",  
                r"Runtime\.getRuntime\(\)\.exec\s*\(\s*.*\s*\)",  
            ],
            "obfuscation": [
                r"Class\.forName\s*\(\s*\".*\"\s*\)",  
                r"invoke\s*\(\s*.*\s*,\s*.*\s*\)",  
                r"new\s+String\s*\(\s*new\s+byte\s*\[\]\s*\{.*\}\s*\)",  
                r"Base64\.(?:getDecoder|getMimeDecoder)\(\)\.decode\s*\(\s*\".*\"\s*\)",  
                r"(\\u[0-9a-fA-F]{4}){5,}",  
            ],
            "exploitation": [
                r"XPath\s*\(\s*.*\s*\+.*\s*\)", 
                r"executeQuery\s*\(\s*\".*\"\s*\+.*\s*\)",  
                r"new\s+URL\s*\(\s*.*\s*\+.*\s*\)",  
                r"InitialContext\(\)\.lookup\s*\(\s*.*\s*\)", 
                r"XMLDecoder\s*\(\s*.*\s*\)", 
            ],
            "webshell": [
                r"extends\s+HttpServlet", 
                r"doGet\s*\(\s*HttpServletRequest", 
                r"doPost\s*\(\s*HttpServletRequest",
                r"request\.getParameter\s*\(\s*\"(?:cmd|command|exec|shell|code)\"",
                r"response\.getWriter\(\)\.print\s*\(",
            ],
            "commandInjection": [
                r"exec\s*\(\s*.*getParameter\s*\(\s*\".*\"\s*\)\s*\)",
                r"bash\s*-c",
                r"/bin/sh\s*-c",
                r"cmd\s*/c",
                r"cmd\.exe\s*/c",
                r"powershell\s*-command",
            ],
            "dataExfiltration": [
                r"URLConnection\s*connection\s*=\s*new\s+URL\s*\(",
                r"HttpURLConnection\s*connection\s*=\s*\(HttpURLConnection\)\s*new\s+URL\s*\(",
                r"HttpClient\s*\.\s*send\s*\(",
                r"new\s+Socket\s*\(\s*\"[^\"]*\"\s*,\s*\d+\s*\)",
                r"OutputStream\s*output\s*=\s*socket\.getOutputStream\s*\(\s*\)",
            ],
            "bypassingSecurity": [
                r"System\.setSecurityManager\s*\(\s*null\s*\)",
                r"AccessController\.doPrivileged\s*\(",
                r"setAccessible\s*\(\s*true\s*\)",
                r"java\.security\.Security\.setProperty\s*\(",
                r"ClassLoader\.getSystemClassLoader\s*\(\s*\)",
            ]
        }
        self.malicious_terms = [
            "backdoor", "shell", "hack", "exploit", "root", "pwn", "injection",
            "vulnerability", "malware", "virus", "trojan", "botnet", "ransomware",
            "keylog", "steal", "password", "credential", "token", "payload"
        ]
        self.known_vulnerabilities = {
            "log4shell": [
                r"jndi\s*:\s*ldap",
                r"jndi\s*:\s*rmi",
                r"jndi\s*:\s*dns",
                r"jndi\s*:\s*iiop",
                r"${.*:.*}",
            ],
            "spring4shell": [
                r"class\.module\.classLoader",
                r"org\.springframework\.web\.servlet\.view\.AbstractView",
                r"org\.springframework\.web\.servlet\.view\.InternalResourceView",
            ],
            "deserialization": [
                r"readObject\s*\(\s*\)",
                r"SerializedLambda",
                r"InvokerTransformer",
                r"ChainedTransformer",
                r"commons-collections",
                r"InvokerTransformer",
                r"AnnotationInvocationHandler",
            ],
            "xxe": [
                r"SAXParserFactory\s*\.\s*newInstance\s*\(\s*\)",
                r"DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)",
                r"XMLStreamReader",
                r"setFeature\s*\(\s*\"http://apache.org/xml/features/disallow-doctype-decl\"\s*,\s*false\s*\)",
                r"setFeature\s*\(\s*\"http://xml.org/sax/features/external-general-entities\"\s*,\s*true\s*\)",
            ],
            "ssrf": [
                r"new\s+URL\s*\(\s*.*getParameter",
                r"new\s+URI\s*\(\s*.*getParameter",
                r"javax\.imageio\.ImageIO\.read\s*\(\s*new\s+URL\s*\(",
                r"openConnection\s*\(\s*\)\s*\.\s*setRequestMethod",
            ],
            "sqlInjection": [
                r"executeQuery\s*\(\s*[^\"]*\s*\+\s*.*getParameter",
                r"createStatement\s*\(\s*\)\s*\.\s*execute\s*\(\s*.*\s*\+",
                r"prepareStatement\s*\(\s*.*\s*\+",
                r"createNativeQuery\s*\(\s*.*\s*\+",
            ]
        }
    
    def can_scan(self, file_path: str) -> bool:
        extension = self.get_file_extension(file_path)
        return extension in self.supported_extensions
    
    def scan(self, file_path: str) -> Dict[str, Any]:
        self.logger.info(f"Analyse du fichier Java: {file_path}")
        result = self.get_result_template()
        result["file_path"] = file_path
        result["scanner"] = self.name
        start_time = time.time()
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            dangerous_calls = self._detect_dangerous_functions(content)
            malicious_code = self._detect_malicious_patterns(content)
            malicious_terms = self._search_malicious_terms(content)
            vulnerabilities = self._detect_vulnerabilities(content)
            malware_characteristics = self._check_malware_characteristics(content)
            risk_score, reasons = self._calculate_risk_score(
                dangerous_calls, 
                malicious_code,
                malicious_terms,
                vulnerabilities,
                malware_characteristics
            )
            threats = []
            for category, functions in dangerous_calls.items():
                if functions:
                    severity = "high" if category in ["exec", "jndi", "deserialization", "privilege"] else "medium"
                    threats.append({
                        "type": f"dangerous_function_{category}",
                        "name": f"Fonction(s) dangereuse(s) - {category}",
                        "description": f"Utilisation de fonctions dangereuses de catégorie {category}: {', '.join(functions[:5])}",
                        "severity": severity
                    })
            for category, patterns in malicious_code.items():
                if patterns:
                    severity = "high" if category in ["shellcode", "backdoor", "webshell", "commandInjection"] else "medium"
                    threats.append({
                        "type": f"malicious_pattern_{category}",
                        "name": f"Pattern malveillant - {category}",
                        "description": f"Détection de pattern {category}: {patterns[0]['match'][:50]}...",
                        "severity": severity
                    })
            for vuln_type, instances in vulnerabilities.items():
                if instances:
                    threats.append({
                        "type": f"vulnerability_{vuln_type}",
                        "name": f"Vulnérabilité - {vuln_type}",
                        "description": f"Détection de vulnérabilité {vuln_type}: {instances[0][:50]}...",
                        "severity": "high"
                    })
            for characteristic in malware_characteristics:
                threats.append({
                    "type": "malware_characteristic",
                    "name": characteristic["name"],
                    "description": characteristic["description"],
                    "severity": characteristic.get("severity", "medium")
                })
            normalized_score = min(10, risk_score / 10)
            result["score"] = normalized_score
            malicious_threshold = 30
            result["is_malicious"] = risk_score >= malicious_threshold or len(threats) >= 3
            file_name = os.path.basename(file_path).lower()
            suspicious_name_patterns = ["hack", "exploit", "shell", "backdoor", "rootkit", "trojan", "malware", "virus"]
            if any(pattern in file_name for pattern in suspicious_name_patterns):
                result["is_malicious"] = True
                result["score"] = max(result["score"], 7.0)
                threats.append({
                    "type": "suspicious_filename",
                    "name": "Nom de fichier suspect",
                    "description": f"Le nom du fichier contient des termes suspects: {file_name}",
                    "severity": "medium"
                })
            
            result["threats"] = threats
            result["scan_details"] = {
                "dangerous_functions": dangerous_calls,
                "malicious_patterns": malicious_code,
                "malicious_terms": malicious_terms,
                "vulnerabilities": vulnerabilities,
                "risk_score": risk_score,
                "risk_reasons": reasons
            }
            if result["is_malicious"]:
                result["message"] = f"Détection de code potentiellement malveillant (score: {normalized_score}/10)"
            else:
                result["message"] = "Aucun code malveillant détecté"
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse du fichier Java: {str(e)}")
            result["error"] = str(e)
            result["is_malicious"] = False
            result["score"] = 0
            result["message"] = f"Erreur d'analyse: {str(e)}"
        result["scan_time"] = time.time() - start_time
        return result
    
    def _detect_dangerous_functions(self, content: str) -> Dict[str, List[str]]:
        result = {}
        function_call_pattern = r'(\w+(?:\.\w+)*)\s*\('
        function_calls = re.findall(function_call_pattern, content)
        for category, functions in self.dangerous_functions.items():
            found_functions = []
            for func in functions:
                if func.endswith("("):
                    func = func[:-1].strip()
                for call in function_calls:
                    if func in call:
                        if call not in found_functions:
                            found_functions.append(call)
                if "(" not in func and re.search(r'\b' + re.escape(func) + r'\b', content):
                    found_functions.append(func)
            if found_functions:
                result[category] = found_functions
        return result
    
    def _detect_malicious_patterns(self, content: str) -> Dict[str, List[Dict[str, Any]]]:
        result = {}
        for category, patterns in self.malicious_patterns.items():
            matches = []
            for pattern in patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                    matches.append({
                        "match": match.group(0),
                        "line": content[:match.start()].count('\n') + 1
                    })
            if matches:
                result[category] = matches
        return result
    
    def _search_malicious_terms(self, content: str) -> List[str]:
        found_terms = []
        for term in self.malicious_terms:
            pattern = r'\b' + re.escape(term) + r'[a-zA-Z0-9_]*\b'
            if re.search(pattern, content, re.IGNORECASE):
                found_terms.append(term)
        
        return found_terms
    
    def _detect_vulnerabilities(self, content: str) -> Dict[str, List[str]]:
        result = {}
        for vuln_type, patterns in self.known_vulnerabilities.items():
            instances = []
            for pattern in patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                    instances.append(match.group(0))
            if instances:
                result[vuln_type] = instances
        return result
    
    def _check_malware_characteristics(self, content: str) -> List[Dict[str, str]]:
        characteristics = []
        if re.search(r'Runtime\.getRuntime\(\)\.exec\s*\(\s*\".*java', content, re.IGNORECASE):
            characteristics.append({
                "name": "Auto-exécution de Java",
                "description": "Tentative d'exécuter un autre processus Java",
                "severity": "high"
            })
        if re.search(r'extends\s+HttpServlet', content, re.IGNORECASE) and re.search(r'getParameter\s*\(\s*\"(?:cmd|command|exec|shell)\"', content, re.IGNORECASE):
            characteristics.append({
                "name": "Webshell Java",
                "description": "Servlet qui accepte des commandes à exécuter",
                "severity": "critical"
            })
        if re.search(r'new\s+ServerSocket\s*\(\s*\d+\s*\)', content, re.IGNORECASE) and re.search(r'Runtime\.getRuntime\(\)\.exec', content, re.IGNORECASE):
            characteristics.append({
                "name": "Backdoor réseau",
                "description": "Écoute sur un port réseau et exécute des commandes",
                "severity": "critical"
            })
        if re.search(r'setSecurityManager\s*\(\s*null\s*\)', content, re.IGNORECASE):
            characteristics.append({
                "name": "Contournement du SecurityManager",
                "description": "Désactivation du gestionnaire de sécurité Java",
                "severity": "high"
            })
        if re.search(r'Cipher\s*\.\s*getInstance\s*\(\s*\"', content, re.IGNORECASE) and re.search(r'File\s*\(\s*\".*\"\s*\)', content, re.IGNORECASE) and re.search(r'\.delete\s*\(\s*\)', content, re.IGNORECASE):
            characteristics.append({
                "name": "Comportement de ransomware",
                "description": "Chiffrement de fichiers suivi de suppression",
                "severity": "critical"
            })
        if (re.search(r'getenv\s*\(\s*\"', content, re.IGNORECASE) or re.search(r'System\.getProperty\s*\(\s*\"', content, re.IGNORECASE)) and re.search(r'new\s+URL\s*\(\s*\"', content, re.IGNORECASE):
            characteristics.append({
                "name": "Vol d'information",
                "description": "Récupération de variables d'environnement et communication réseau",
                "severity": "high"
            })
        return characteristics
    
    def _calculate_risk_score(self, dangerous_calls, malicious_code, malicious_terms, 
                              vulnerabilities, malware_characteristics):
        score = 0
        reasons = []
        category_weights = {
            "exec": 10,
            "reflection": 8,
            "network": 6,
            "file": 5,
            "privilege": 9,
            "serialization": 7,
            "jndi": 10,
            "deserialization": 10,
            "classloading": 8,
            "crypto": 5,
            "database": 4,
            "xml": 5
        }
        
        for category, functions in dangerous_calls.items():
            if functions:
                weight = category_weights.get(category, 5)
                points = min(weight, len(functions) * (weight / 2))
                score += points
                reasons.append(f"Fonctions dangereuses '{category}' ({len(functions)}): +{points:.1f}")
        pattern_weights = {
            "shellcode": 15,
            "backdoor": 15,
            "obfuscation": 8,
            "exploitation": 12,
            "webshell": 15,
            "commandInjection": 15,
            "dataExfiltration": 10,
            "bypassingSecurity": 12
        }
        
        for category, patterns in malicious_code.items():
            if patterns:
                weight = pattern_weights.get(category, 10)
                points = min(weight, len(patterns) * (weight / 2))
                score += points
                reasons.append(f"Patterns malveillants '{category}' ({len(patterns)}): +{points:.1f}")
        if malicious_terms:
            points = min(10, len(malicious_terms) * 2)
            score += points
            reasons.append(f"Termes malveillants ({len(malicious_terms)}): +{points:.1f}")
        vuln_weights = {
            "log4shell": 20,
            "spring4shell": 20,
            "deserialization": 18,
            "xxe": 15,
            "ssrf": 12,
            "sqlInjection": 15
        }
        for vuln_type, instances in vulnerabilities.items():
            if instances:
                weight = vuln_weights.get(vuln_type, 15)
                points = min(weight, len(instances) * (weight / 2))
                score += points
                reasons.append(f"Vulnérabilité '{vuln_type}' ({len(instances)}): +{points:.1f}")
        for characteristic in malware_characteristics:
            severity = characteristic.get("severity", "medium")
            if severity == "critical":
                points = 20
            elif severity == "high":
                points = 15
            elif severity == "medium":
                points = 10
            else:
                points = 5
            score += points
            reasons.append(f"{characteristic['name']}: +{points:.1f}")
        score = min(100, score)
        return score, reasons
    
    def get_result_template(self) -> Dict[str, Any]:
        return {
            "scanner": self.name,
            "is_malicious": False,
            "score": 0,
            "threats": [],
            "message": "",
            "scan_details": {},
            "error": None,
            "file_path": ""
        }
