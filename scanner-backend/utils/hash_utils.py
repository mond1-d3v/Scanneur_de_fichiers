import re
import os
import hmac
import hashlib
from typing import Dict, List, Optional, Tuple, Union

from .file_utils import calculate_hash

def validate_hash_format(hash_str: str) -> Tuple[bool, Optional[str]]:
    hash_patterns = {
        'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
        'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
        'sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
        'sha512': re.compile(r'^[a-fA-F0-9]{128}$')
    }
    hash_str = hash_str.strip().lower()
    for hash_type, pattern in hash_patterns.items():
        if pattern.match(hash_str):
            return True, hash_type
    return False, None

def normalize_hash(hash_str: str) -> str:
    return hash_str.strip().lower()

def hash_to_filename(hash_str: str) -> str:
    hash_str = normalize_hash(hash_str)
    valid, hash_type = validate_hash_format(hash_str)
    
    if valid:
        return f"{hash_str}.{hash_type}"
    else:
        return f"{hash_str}.unknown"

def hash_id_to_path_segments(hash_id: str) -> List[str]:
    hash_id = normalize_hash(hash_id)
    if len(hash_id) >= 4:
        return [hash_id[:2], hash_id[2:4], hash_id]
    elif len(hash_id) >= 2:
        return [hash_id[:2], "00", hash_id]
    else:
        return ["00", "00", hash_id]

def calculate_file_hashes(filepath: str) -> Dict[str, str]:
    return {
        'md5': calculate_hash(filepath, 'md5'),
        'sha1': calculate_hash(filepath, 'sha1'),
        'sha256': calculate_hash(filepath, 'sha256')
    }

def generate_hmac_signature(data: Union[str, bytes], secret_key: Union[str, bytes], 
    hash_type: str = 'sha256') -> str:
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(secret_key, str):
        secret_key = secret_key.encode('utf-8')
    hmac_obj = hmac.new(secret_key, data, getattr(hashlib, hash_type))
    return hmac_obj.hexdigest()
def verify_hmac_signature(data: Union[str, bytes], signature: str, 
    secret_key: Union[str, bytes], hash_type: str = 'sha256') -> bool:
    expected = generate_hmac_signature(data, secret_key, hash_type)
    return hmac.compare_digest(expected, signature)
