import os
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
logger = logging.getLogger(__name__)

class ScannerException(Exception):
    pass

class BaseScanner(ABC):  
    def __init__(self):
        self.name = self.__class__.__name__
        self.description = "Scanner de base"
        self.version = "1.0"
        self.supported_extensions = []
    
    @abstractmethod
    def can_scan(self, file_path: str) -> bool:
        pass
    
    @abstractmethod
    def scan(self, file_path: str) -> Dict[str, Any]:
        return self.get_result_template()
    
    def get_file_extension(self, file_path: str) -> str:
        _, ext = os.path.splitext(file_path)
        return ext[1:].lower() if ext else ""
    
    def get_result_template(self) -> Dict[str, Any]:
        return {
            "scanner": self.name,
            "is_malicious": False,
            "threats": [],
            "scan_details": {},
            "scan_time": 0,
        }
