import os
import logging
from flask import Flask
from flask_cors import CORS
from api.routes import setup_routes

logger = logging.getLogger(__name__)

def create_app(config_object=None):
    app = Flask(__name__)
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    if config_object:
        app.config.from_object(config_object)
    else:
        try:
            from config import active_config
            app.config.from_object(active_config)
            logger.info("Configuration chargée depuis config.py")
        except ImportError:
            logger.warning("Aucun module de configuration trouvé, utilisation des valeurs par défaut")
    if not os.path.exists(app.config.get('UPLOAD_FOLDER', 'uploads')):
        os.makedirs(app.config.get('UPLOAD_FOLDER', 'uploads'))
        
    if not os.path.exists(app.config.get('TEMP_FOLDER', 'temp')):
        os.makedirs(app.config.get('TEMP_FOLDER', 'temp'))
    setup_routes(app)
    @app.route('/')
    def index():
        return {
            "status": "ok",
            "message": "Scanner de Malware API est opérationnel",
            "version": "1.0.0"
        }
    
    return app
