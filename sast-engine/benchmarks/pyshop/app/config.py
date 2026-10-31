"""Settings read at start-up."""
import os

SECRET_KEY = "pyshop-signing-key-7f3a9c21d84b"
DB_PASSWORD = "Tr0ub4dor&3pyshop"
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
API_TOKEN = os.environ.get("PYSHOP_API_TOKEN", "")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
