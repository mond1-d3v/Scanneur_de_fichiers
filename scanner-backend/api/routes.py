import os
import time
import logging
import traceback
from flask import request, jsonify, Blueprint, current_app, abort, send_file
from werkzeug.utils import secure_filename
from scanner.virus_scanner import VirusScanner
from db import get_database, DatabaseError
from utils.file_utils import create_safe_temp_file, get_file_metadata  

logger = logging.getLogger(__name__)

api_bp = Blueprint('api', __name__)

def setup_routes(app):
    """Configure les routes de l'API"""
    
    app.register_blueprint(api_bp, url_prefix='/api')
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

@api_bp.route('/status', methods=['GET'])
def get_status():
    """Vérifier l'état du serveur"""
    return jsonify({
        "status": "ok",
        "version": "1.0.0",
        "service": "Scanner de fichiers malveillants"
    })

@api_bp.route('/scan', methods=['POST'])
def scan_file():
    try:
        logger.info("Nouvelle demande d'analyse de fichier reçue")
        if 'file' not in request.files:
            logger.warning("Aucun fichier n'a été envoyé dans la requête")
            return jsonify({"error": "Aucun fichier n'a été envoyé"}), 400
        
        uploaded_file = request.files['file']
        if uploaded_file.filename == '':
            logger.warning("Aucun nom de fichier sélectionné")
            return jsonify({"error": "Aucun nom de fichier sélectionné"}), 400
        filename = secure_filename(uploaded_file.filename)
        temp_file_path = create_safe_temp_file(filename, uploaded_file.read())
        
        if not temp_file_path:
            logger.error("Impossible de créer le fichier temporaire")
            return jsonify({"error": "Erreur lors du traitement du fichier"}), 500
        
        logger.debug(f"Fichier temporaire créé: {temp_file_path}")
        scanner = VirusScanner()
        result = scanner.scan(temp_file_path)
        try:
            db = get_database()
            
            if db:
                file_info = get_file_metadata(temp_file_path)
                auth_header = request.headers.get('Authorization', '')
                user_id = None
                username = "Anonyme"
                
                if (auth_header.startswith('Bearer ')):
                    token = auth_header.split(' ')[1]
                    try:
                        user_info = db.auth_with_token(token)
                        if user_info and 'record' in user_info:
                            user_id = user_info['record'].get('id')
                            username = user_info['record'].get('username', 'Utilisateur')
                    except Exception as token_error:
                        logger.warning(f"Erreur de vérification du token: {str(token_error)}")
                history_record = {
                    "file_name": filename,
                    "file_size": file_info.get("size_bytes", 0),
                    "file_type": file_info.get("mime_type", "unknown"),
                    "scan_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "is_malicious": result.get("is_malicious", False),
                    "scan_source": "web",
                    "detection_details": {
                        "threats_count": len(result.get("threats", [])),
                        "threat_types": [t.get("type") for t in result.get("threats", [])],
                        "score": result.get("score", 0)
                    },
                    "score": result.get("score", 0),
                    "user_id": user_id,
                    "username": username
                }
                db.insert("scan_history", history_record)
                logger.info(f"Enregistrement ajouté à l'historique des scans pour {filename}")
            
        except Exception as db_error:
            logger.error(f"Erreur lors de l'enregistrement dans la base de données: {str(db_error)}")
        try:
            os.remove(temp_file_path)
            logger.debug(f"Fichier temporaire supprimé: {temp_file_path}")
        except Exception as e:
            logger.warning(f"Impossible de supprimer le fichier temporaire {temp_file_path}: {str(e)}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Erreur générale: {str(e)}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@api_bp.route('/results/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    """
    Endpoint pour récupérer les résultats d'un scan
    """
    if scan_id not in active_scans:
        return jsonify({"error": "Scan non trouvé"}), 404
    
    scan_info = active_scans[scan_id]

    if scan_info["status"] == "in_progress":
        return jsonify({
            "scan_id": scan_id,
            "status": "in_progress",
            "file_name": scan_info["original_name"],
            "message": "L'analyse est en cours, veuillez réessayer plus tard."
        })
    result = scan_info["result"]
    response = {
        "scan_id": scan_id,
        "status": "completed",
        "file_name": scan_info["original_name"],
        "file_path": scan_info["file_path"],
        "is_malicious": result.get("is_malicious", False),
        "score": result.get("score", 0),
        "message": result.get("message", ""),
        "threats": result.get("threats", []),
        "scan_date": result.get("scan_date", ""),
        "file_type": result.get("file_type", "")
    }
    
    if "file_size" in result:
        response["file_size"] = result["file_size"]
    
    return jsonify(response)

@api_bp.route('/scanners', methods=['GET'])
def get_available_scanners():
    try:
        scanner = VirusScanner()
        scanners = scanner.list_available_scanners()
        return jsonify(scanners)
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des scanners: {str(e)}")
        return jsonify({"error": f"Erreur: {str(e)}"}), 500

@api_bp.route('/clean', methods=['POST'])
def clean_scan():
    data = request.json
    scan_id = data.get('scan_id')
    
    if not scan_id or scan_id not in active_scans:
        return jsonify({"error": "Scan non trouvé"}), 404
    
    try:
        file_path = active_scans[scan_id]["file_path"]
        if os.path.exists(file_path):
            os.remove(file_path)
        temp_dir = os.path.dirname(file_path)
        if os.path.exists(temp_dir) and not os.listdir(temp_dir):
            os.rmdir(temp_dir)
        del active_scans[scan_id]
        
        return jsonify({"message": "Scan nettoyé avec succès"})
    except Exception as e:
        logger.error(f"Erreur lors du nettoyage du scan: {str(e)}")
        return jsonify({"error": f"Erreur: {str(e)}"}), 500

@api_bp.route('/history', methods=['GET'])
def get_scan_history():
    try:
        db = get_database()
        if not db:
            logger.error("Base de données non disponible lors de la récupération de l'historique")
            return jsonify({"error": "Base de données non disponible"}), 500
        auth_header = request.headers.get('Authorization', '')
        current_user_id = None
        
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                user_info = db.auth_with_token(token)
                if user_info and 'record' in user_info:
                    current_user_id = user_info['record'].get('id')
            except Exception as token_error:
                logger.warning(f"Erreur de vérification du token: {str(token_error)}")
        try:
            query = {}
            if current_user_id:
                query = {"user_id": current_user_id}
                
            history = db.find('scan_history', query, sort=["-scan_date"], limit=100)
            if not isinstance(history, list):
                logger.warning(f"L'historique récupéré n'est pas une liste mais un {type(history)}")
                history = list(history) if history else []
            for item in history:
                if 'score' not in item or item['score'] is None:
                    item['score'] = 0
                if 'detection_details' in item and 'threats_count' in item['detection_details']:
                    threats_count = item['detection_details']['threats_count']
                    if threats_count <= 1:
                        item['score'] = 1
                    elif threats_count > 10:
                        item['score'] = 10
                    else:
                        item['score'] = threats_count
                if current_user_id:
                    if 'username' in item:
                        del item['username']
                    if 'user_id' in item:
                        del item['user_id']
                else:
                    if 'username' not in item or not item['username']:
                        item['username'] = "Utilisateur anonyme"
            
            logger.info(f"Historique récupéré: {len(history)} résultats")
            return jsonify(history)
        except Exception as db_error:
            logger.error(f"Erreur spécifique à la base de données lors de la récupération: {str(db_error)}")
            import traceback
            logger.error(traceback.format_exc())
            return jsonify({"error": f"Erreur de base de données: {str(db_error)}"}), 500
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'historique: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Erreur: {str(e)}"}), 500

@api_bp.route('/history/<record_id>', methods=['DELETE'])
def delete_scan_history(record_id):
    try:
        db = get_database()
        if not db:
            return jsonify({"error": "Base de données non disponible"}), 500
        record = db.find_one('scan_history', {'id': record_id})
        if not record:
            return jsonify({"error": "Enregistrement non trouvé"}), 404
        db.delete('scan_history', record_id)
        return jsonify({"success": True, "message": "Enregistrement supprimé"})
    except Exception as e:
        logger.error(f"Erreur lors de la suppression de l'historique: {str(e)}")
        return jsonify({"error": f"Erreur: {str(e)}"}), 500

@api_bp.route('/stats', methods=['GET'])
def get_stats():
    try:
        db = get_database()
        if not db:
            return jsonify({"error": "Base de données non disponible"}), 500
        total_scans = len(db.find('scan_history', {}))
        malicious_scans = len(db.find('scan_history', {'is_malicious': True}))
        unique_hashes = len(db.find('file_hashes', {}))
        detection_rate = (malicious_scans / total_scans * 100) if total_scans > 0 else 0
        return jsonify({
            "total_scans": total_scans,
            "malicious_scans": malicious_scans,
            "clean_scans": total_scans - malicious_scans,
            "unique_files": unique_hashes,
            "detection_rate": round(detection_rate, 2)
        })
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des statistiques: {str(e)}")
        return jsonify({"error": f"Erreur: {str(e)}"}), 500

@api_bp.route('/admin/statistics', methods=['GET'])
def get_admin_statistics():
    try:
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authentification requise"}), 401
            
        token = auth_header.split(' ')[1]
        db = get_database()
        
        if not db:
            logger.error("Base de données non disponible")
            return jsonify({"error": "Service indisponible"}), 503
        try:
            user_info = db.auth_with_token(token)
            if not user_info or not user_info.get('record', {}).get('verified', False):
                return jsonify({"error": "Accès non autorisé"}), 403
        except Exception as e:
            logger.error(f"Erreur de vérification du token: {str(e)}")
            return jsonify({"error": "Token invalide"}), 401
        try:
            total_scans = db.count('scan_history', {})
            malicious_scans = db.count('scan_history', {"is_malicious": True})
            clean_scans = total_scans - malicious_scans
            total_users = db.count('users', {})
            from datetime import datetime, timedelta
            
            scans_by_day = []
            for i in range(6, -1, -1):
                date = datetime.now() - timedelta(days=i)
                date_str = date.strftime('%Y-%m-%d')
                try:
                    query = {"created": date_str}
                    count = db.count('scan_history', query)
                    scans_by_day.append({
                        "date": date.strftime('%d/%m'),
                        "count": count
                    })
                except Exception as date_error:
                    logger.error(f"Erreur lors du comptage pour la date {date_str}: {str(date_error)}")
                    scans_by_day.append({
                        "date": date.strftime('%d/%m'),
                        "count": 0
                    })
            statistics = {
                "totalScans": total_scans,
                "maliciousScans": malicious_scans,
                "cleanScans": clean_scans,
                "totalUsers": total_users,
                "scansByDay": scans_by_day
            }
            return jsonify(statistics)
        except Exception as db_error:
            logger.error(f"Erreur lors de la récupération des statistiques: {str(db_error)}")
            return jsonify({"error": f"Erreur de base de données: {str(db_error)}"}), 500
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des statistiques: {str(e)}")
        return jsonify({"error": str(e)}), 500

@api_bp.route('/admin/errors', methods=['GET'])
def get_admin_errors():
    try:
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authentification requise"}), 401
            
        token = auth_header.split(' ')[1]
        db = get_database()
        
        if not db:
            logger.error("Base de données non disponible")
            return jsonify({"error": "Service indisponible"}), 503
        try:
            user_info = db.auth_with_token(token)
            if not user_info or not user_info.get('record', {}).get('verified', False):
                return jsonify({"error": "Accès non autorisé"}), 403
        except Exception as e:
            logger.error(f"Erreur de vérification du token: {str(e)}")
            return jsonify({"error": "Token invalide"}), 401
        try:
            collections = db.list_collections()
            collection_names = [c.get('name') for c in collections]
            
            if 'scan_errors' not in collection_names:
                logger.warning("Collection scan_errors non trouvée, utilisation de scan_history à la place")
                try:
                    history_records = db.find('scan_history', {"error != ''": True}, sort=["-scan_date"], limit=50)
                    
                    if not isinstance(history_records, list):
                        history_records = list(history_records) if history_records else []
                    formatted_errors = []
                    for record in history_records:
                        if record.get("error"):
                            formatted_errors.append({
                                "id": record.get("id"),
                                "errorType": "Erreur de scan",
                                "errorMessage": record.get("error", "Erreur inconnue"),
                                "timestamp": record.get("scan_date"),
                                "fileName": record.get("file_name", "Fichier inconnu"),
                                "fileSize": record.get("file_size", "Taille inconnue"),
                                "userId": record.get("user_id"),
                                "ipAddress": record.get("user_ip", "Adresse IP inconnue"),
                                "userAgent": record.get("user_agent", "User agent inconnu"),
                                "stackTrace": record.get("stack_trace")
                            })
                    
                    return jsonify(formatted_errors)
                except Exception as find_error:
                    logger.error(f"Erreur lors de la recherche d'erreurs dans scan_history: {str(find_error)}")
                    return jsonify([])
            else:
                errors = db.find('scan_errors', {}, sort=["-timestamp"], limit=50)
                
                if not isinstance(errors, list):
                    errors = list(errors) if errors else []
                formatted_errors = []
                for error in errors:
                    formatted_errors.append({
                        "id": error.get("id"),
                        "errorType": error.get("error_type", "Erreur inconnue"),
                        "errorMessage": error.get("error_message", "Pas de message d'erreur"),
                        "timestamp": error.get("timestamp"),
                        "fileName": error.get("file_name", "Fichier inconnu"),
                        "fileSize": error.get("file_size", "Taille inconnue"),
                        "userId": error.get("user_id"),
                        "ipAddress": error.get("ip_address", "Adresse IP inconnue"),
                        "userAgent": error.get("user_agent", "User agent inconnu"),
                        "stackTrace": error.get("stack_trace")
                    })
                return jsonify(formatted_errors)
        except Exception as db_error:
            logger.error(f"Erreur lors de la récupération des erreurs: {str(db_error)}")
            return jsonify([])
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des erreurs: {str(e)}")
        return jsonify([])

@api_bp.route('/admin/logout-user/<user_id>', methods=['POST'])
def admin_logout_user(user_id):
    try:
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authentification requise"}), 401
        token = auth_header.split(' ')[1]
        db = get_database()
        if not db:
            logger.error("Base de données non disponible")
            return jsonify({"error": "Service indisponible"}), 503
        try:
            user_info = db.auth_with_token(token)
            if not user_info or not user_info.get('record', {}).get('verified', False):
                return jsonify({"error": "Accès non autorisé"}), 403
        except Exception as e:
            logger.error(f"Erreur de vérification du token: {str(e)}")
            return jsonify({"error": "Token invalide"}), 401
        try:
            user = db.find_one('users', {"id": user_id})
            
            if not user:
                return jsonify({"error": f"Utilisateur avec ID {user_id} non trouvé"}), 404
            logger.info(f"Administrateur {user_info['record']['id']} a déconnecté l'utilisateur {user_id}")
            
            return jsonify({"success": True, "message": f"Utilisateur {user_id} déconnecté"})
            
        except Exception as db_error:
            logger.error(f"Erreur lors de la déconnexion de l'utilisateur: {str(db_error)}")
            return jsonify({"error": f"Erreur de base de données: {str(db_error)}"}), 500
        
    except Exception as e:
        logger.error(f"Erreur lors de la déconnexion de l'utilisateur: {str(e)}")
        return jsonify({"error": str(e)}), 500
