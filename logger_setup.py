import logging
import os
from datetime import datetime

# Définir les chemins des dossiers de logs
LOG_DIR = "logs"
FILE_LOG_DIR = os.path.join(LOG_DIR, "files")
APP_LOG_DIR = os.path.join(LOG_DIR, "app")

# Créer les dossiers s'ils n'existent pas
os.makedirs(FILE_LOG_DIR, exist_ok=True)
os.makedirs(APP_LOG_DIR, exist_ok=True)

# Générer un nom de fichier unique basé sur la date et l'heure
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Logger pour les actions sur les fichiers
file_logger = logging.getLogger("file_actions")
file_logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler(os.path.join(FILE_LOG_DIR, f"file_actions_{timestamp}.log"), encoding="utf-8")
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
file_logger.addHandler(file_handler)

# Logger pour le reste (API, erreurs générales...)
app_logger = logging.getLogger("app")
app_logger.setLevel(logging.DEBUG)
app_handler = logging.FileHandler(os.path.join(APP_LOG_DIR, f"app_{timestamp}.log"), encoding="utf-8")
app_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
app_logger.addHandler(app_handler)
