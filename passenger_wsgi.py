import sys
import os

# Path to the virtualenv Python created by cPanel's "Setup Python App".
# IMPORTANT: After creating the app in cPanel, check the exact virtualenv path
# shown in the UI and update this line to match (e.g. python3.11 vs python3).
INTERP = os.path.join(
    os.environ.get("HOME", ""),
    "virtualenv", "ReadandReply", "3.11", "bin", "python3"
)
if sys.executable != INTERP:
    os.execl(INTERP, INTERP, *sys.argv)

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
