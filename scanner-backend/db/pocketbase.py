import os
import json
import logging
import requests
from typing import Dict, List, Any, Optional

from db.database import Database, DatabaseError

logger = logging.getLogger(__name__)

class PocketBase(Database):
    def __init__(self, url: str, email: str = None, password: str = None):
        self.url = url.rstrip('/')
        self.email = email
        self.password = password
        self.token = None
        self.admin_token = None
        self.connected = False
        if email and password:
            self.connect()
    
    def connect(self) -> bool:
        if not self.email or not self.password:
            try:
                response = requests.get(f"{self.url}/api/collections")
                self.connected = response.status_code == 200
                return self.connected
            except Exception:
                self.connected = False
                return False
        try:
            auth_data = {
                "identity": self.email,
                "password": self.password
            }
            response = requests.post(
                f"{self.url}/api/admins/auth-with-password",
                json=auth_data
            )
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('token')
                self.admin_token = data.get('token')
                self.connected = True
                return True
            else:
                self.connected = False
                return False
        except Exception:
            self.connected = False
            return False
    
    def check_connection(self) -> bool:
        if not self.connected:
            return self.connect()
        return True
    
    def find(self, collection: str, query: Dict[str, Any], sort: Optional[List[str]] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        if not self.check_connection():
            if not self.connect():
                raise DatabaseError("Non connecté à PocketBase")
        try:
            headers = self._get_auth_headers()
            params = {}
            if query:
                if isinstance(query, dict):
                    filter_str = self._build_filter_string(query)
                    if filter_str:
                        params['filter'] = filter_str
            if sort:
                params['sort'] = ','.join(sort)
            if limit:
                params['perPage'] = limit
            response = requests.get(
                f"{self.url}/api/collections/{collection}/records",
                headers=headers,
                params=params
            )
            if response.status_code == 200:
                data = response.json()
                return data.get('items', [])
            else:
                raise DatabaseError(f"Erreur lors de la recherche dans {collection}: {response.status_code} - {response.text}")
        except Exception as e:
            raise DatabaseError(f"Erreur de recherche: {str(e)}")
    
    def find_one(self, collection: str, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            results = self.find(collection, query, limit=1)
            return results[0] if results else None
        except Exception:
            return None
    
    def insert(self, collection: str, data: Dict[str, Any]) -> Dict[str, Any]:
        if not self.check_connection():
            if not self.connect():
                raise DatabaseError("Non connecté à PocketBase")
        try:
            headers = self._get_auth_headers()
            response = requests.post(
                f"{self.url}/api/collections/{collection}/records",
                headers=headers,
                json=data
            )
            if response.status_code in (200, 201):
                return response.json()
            else:
                raise DatabaseError(f"Erreur lors de l'insertion dans {collection}: {response.status_code} - {response.text}")
        except Exception as e:
            raise DatabaseError(str(e))
    
    def update(self, collection: str, id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        if not self.check_connection():
            if not self.connect():
                raise DatabaseError("Non connecté à PocketBase")
        try:
            headers = self._get_auth_headers()
            response = requests.patch(
                f"{self.url}/api/collections/{collection}/records/{id}",
                headers=headers,
                json=data
            )
            if response.status_code == 200:
                return response.json()
            else:
                raise DatabaseError(f"Erreur lors de la mise à jour dans {collection}: {response.status_code} - {response.text}")
        except Exception as e:
            raise DatabaseError(str(e))
    
    def delete(self, collection: str, id: str) -> bool:
        if not self.check_connection():
            if not self.connect():
                raise DatabaseError("Non connecté à PocketBase")
        try:
            headers = self._get_auth_headers()
            response = requests.delete(
                f"{self.url}/api/collections/{collection}/records/{id}",
                headers=headers
            )
            return response.status_code in (200, 204)
        except Exception:
            return False
    
    def list_collections(self) -> List[Dict[str, Any]]:
        if not self.check_connection():
            if not self.connect():
                raise DatabaseError("Non connecté à PocketBase")
        try:
            headers = self._get_auth_headers()
            response = requests.get(
                f"{self.url}/api/collections",
                headers=headers
            )
            if response.status_code == 200:
                data = response.json()
                return data.get('items', [])
            else:
                return []
        except Exception:
            return []
    
    def auth_with_token(self, token: str) -> Dict[str, Any]:
        try:
            response = requests.post(
                f"{self.url}/api/collections/users/auth-refresh",
                headers={"Authorization": f"Bearer {token}"}
            )
            if response.status_code == 200:
                return response.json()
            else:
                return None
        except Exception:
            return None
    
    def count(self, collection: str, query: Dict[str, Any]) -> int:
        try:
            if not self.check_connection():
                return 0
            params = {"filter": self._build_filter_string(query)}
            headers = {}
            if self.admin_token:
                headers["Authorization"] = f"Bearer {self.admin_token}"
            url = f"{self.url}/api/collections/{collection}/records"
            response = requests.get(
                url,
                headers=headers,
                params={**params, "perPage": 1, "count": "true"}
            )
            if response.status_code == 200:
                data = response.json()
                return data.get('totalItems', 0)
            else:
                raise DatabaseError(f"Erreur lors du comptage dans {collection}: {response.status_code} - {response.text}")
        except Exception:
            return 0
    
    def _get_auth_headers(self) -> Dict[str, str]:
        headers = {
            'Content-Type': 'application/json'
        }
        if self.token:
            headers['Authorization'] = f"Bearer {self.token}"
        return headers
    
    def _build_filter_string(self, query: Dict[str, Any]) -> str:
        if not query:
            return ""
        filter_parts = []
        for key, value in query.items():
            if isinstance(key, str) and '~' in key:
                field, op = key.split('~', 1)
                if op == '':
                    filter_parts.append(f"{field.strip()} ~ '{value}'")
                else:
                    filter_parts.append(f"{field.strip()}{op} '{value}'")
            elif isinstance(value, str):
                filter_parts.append(f"{key} = '{value}'")
            elif value is None:
                filter_parts.append(f"{key} = null")
            elif isinstance(value, bool):
                filter_parts.append(f"{key} = {str(value).lower()}")
            else:
                filter_parts.append(f"{key} = {value}")
        return " && ".join(filter_parts)
