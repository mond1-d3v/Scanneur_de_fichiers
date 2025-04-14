import os
import sys
import logging
from waitress import serve
from api.server import create_app
from utils.logger import setup_logger

logger = setup_logger(app_name="malware_analyzer", log_dir="logs")

def main():
    app = create_app()
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Démarrage du serveur Waitress sur le port {port}")
    print(f"Serveur démarré: http://localhost:{port}")
    serve(app, host="0.0.0.0", port=port)

if __name__ == "__main__":
    main()
