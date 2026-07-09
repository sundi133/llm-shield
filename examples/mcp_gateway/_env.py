"""Tiny stdlib .env loader shared by the gateway example scripts.

Handles `export KEY=VAL` and quoted values. Real environment variables win over
.env. Point at a different file with ENV_FILE=... .
"""

import os


def load_env(path=None):
    path = path or os.environ.get("ENV_FILE", ".env")
    env = {}
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export "):]
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


_ENV = load_env()


def cfg(key, default=""):
    return os.environ.get(key) or _ENV.get(key) or default
