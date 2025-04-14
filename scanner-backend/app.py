import sys
import os
import logging
from utils.logger import setup_logger
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from api.server import create_app
from config import active_config as config_class

logger = setup_logger(
    app_name="malware_analyzer",
    log_dir=getattr(config_class, 'LOG_FOLDER', 'logs'),
    log_level=logging.DEBUG if config_class.DEBUG else logging.INFO
)

if __name__ == "__main__":
    app = create_app()

    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "False").lower() == "true"
    
    logger.info(f"Démarrage du serveur sur le port {port} (debug: {debug})")

    app.run(host="0.0.0.0", port=port, debug=debug)
