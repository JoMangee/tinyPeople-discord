"""Passenger WSGI entry point for tinyPeople Discord Messages API."""
# Version tracks app.py BOT_VERSION
__version__ = "0.3.0"

import os
import sys

os.environ["PASSENGER_APP"] = "1"

APP_DIR = os.path.dirname(os.path.abspath(__file__))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from app import app as application  # noqa: E402
