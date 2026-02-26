import sys
import os

# Load .env before importing the app.
# db.py creates the SQLAlchemy engine at module level, so DATABASE_URL must
# be set before "from app.server import app" runs.
def _load_dotenv(path):
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

_load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# Disable the in-process background polling thread.
# Polling is handled by a cron job (poll_cron.py) instead.
os.environ.setdefault("RUN_POLLING", "false")

from app.server import app as application
