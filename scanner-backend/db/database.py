import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class DatabaseError(Exception):
    pass

class Database(ABC):
    @abstractmethod
    def connect(self) -> bool:
        pass
    
    @abstractmethod
    def check_connection(self) -> bool:
        pass
    
    @abstractmethod
    def find(self, collection: str, query: Dict[str, Any], sort: Optional[List[str]] = None, 
             limit: Optional[int] = None, skip: Optional[int] = None) -> List[Dict[str, Any]]:
        pass
    
    @abstractmethod
    def find_one(self, collection: str, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pass
    
    @abstractmethod
    def insert(self, collection: str, document: Dict[str, Any]) -> Dict[str, Any]:
        pass
    
    @abstractmethod
    def update(self, collection: str, id: str, update: Dict[str, Any]) -> Dict[str, Any]:
        pass
    
    @abstractmethod
    def delete(self, collection: str, id: str) -> bool:
        pass
    
    @abstractmethod
    def count(self, collection: str, query: Dict[str, Any]) -> int:
        pass
    
    @abstractmethod
    def list_collections(self) -> List[Dict[str, Any]]:
        pass
    
    def create_collection(self, name: str, schema: Dict[str, Any]) -> bool:
        logger.warning(f"create_collection non implémenté pour {self.__class__.__name__}")
        return False
    
    def close(self):
        pass
