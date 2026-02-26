#!/usr/bin/env python3
"""
Cron job script for email polling on cPanel hosting.

Set up in cPanel > Cron Jobs with interval */3 * * * * and command:
  /home/USERNAME/virtualenv/readandreply/3.11/bin/python3 /home/USERNAME/readandreply/poll_cron.py >> /home/USERNAME/readandreply/poll_cron.log 2>&1

Replace USERNAME with your cPanel username and update the virtualenv path
to match the exact path shown in cPanel's "Setup Python App" UI.
"""
import os
import sys

# Use the same virtualenv Python as Passenger.
# Update this path to match the exact virtualenv path shown in cPanel.
VENV_PYTHON = os.path.join(
    os.environ.get("HOME", ""),
    "virtualenv", "ReadandReply", "3.11", "bin", "python3"
)
if sys.executable != VENV_PYTHON:
    os.execl(VENV_PYTHON, VENV_PYTHON, *sys.argv)

# Load .env from the project root.
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

_project_root = os.path.dirname(os.path.abspath(__file__))
_load_dotenv(os.path.join(_project_root, ".env"))

# Add project root to path so "app" package is importable.
sys.path.insert(0, _project_root)

# Disable the in-process background thread (not needed for a cron script).
os.environ["RUN_POLLING"] = "false"

import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

from app.server import poll_once

if __name__ == "__main__":
    poll_once()
