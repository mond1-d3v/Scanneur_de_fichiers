import requests
import sys
from config import active_config as config

def test_pocketbase_connection():
    print("Test de connexion à PocketBase...")

    base_url = config.POCKETBASE_URL
    try:
        root_response = requests.get(f"{base_url}/api/collections")
        if root_response.status_code in [200, 401]: 
            print("✓ Le serveur PocketBase est en ligne")
        else:
            print(f"✗ Erreur: Impossible de contacter le serveur PocketBase. Code: {root_response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"✗ Erreur de connexion: {str(e)}")
        return False
    try:
        auth_data = {
            "identity": config.POCKETBASE_EMAIL,
            "password": config.POCKETBASE_PASSWORD
        }
        auth_response = requests.post(f"{base_url}/api/admins/auth-with-password", json=auth_data)
        if auth_response.status_code == 200:
            auth_result = auth_response.json()
            auth_token = auth_result.get('token', '')
            print(f"✓ Authentification réussie en tant que {auth_result.get('record', {}).get('email', 'admin')}")
        else:
            print(f"✗ Échec de l'authentification. Code: {auth_response.status_code}")
            print(f"  Détails: {auth_response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"✗ Erreur d'authentification: {str(e)}")
        return False
    collections = [
        config.PB_COLLECTION_MALWARE_PATTERNS,
        config.PB_COLLECTION_FILE_HASHES,
        config.PB_COLLECTION_SCAN_HISTORY
    ]
    headers = {
        "Authorization": f"Bearer {auth_token}"
    }
    for collection in collections:
        try:
            coll_response = requests.get(f"{base_url}/api/collections/{collection}/records?perPage=1", headers=headers)
            
            if coll_response.status_code == 200:
                total_items = coll_response.json().get('totalItems', 0)
                print(f"✓ Accès à la collection '{collection}' réussi ({total_items} enregistrements)")
            else:
                print(f"✗ Échec d'accès à la collection '{collection}'. Code: {coll_response.status_code}")
                print(f"  Détails: {coll_response.text}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"✗ Erreur d'accès à la collection '{collection}': {str(e)}")
            return False
    
    print("\n✅ Test de connexion PocketBase réussi! Toutes les collections sont accessibles.")
    return True

if __name__ == "__main__":
    success = test_pocketbase_connection()
    sys.exit(0 if success else 1)
