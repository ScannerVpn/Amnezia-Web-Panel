#!/bin/sh
# Amnezia Web Panel — Docker entrypoint
# Ensures /app/data has correct ownership before starting uvicorn as paneluser.

set -e

DATA_DIR="${DATA_DIR:-/app/data}"

# Always run as root here (container starts as root)
if [ -d "$DATA_DIR" ]; then
    # Fix ownership of mounted volume
    chown -R 1000:1000 "$DATA_DIR" 2>/dev/null || true
    chmod 700 "$DATA_DIR" 2>/dev/null || true
    # Lock down secret files
    for f in .encryption_key .secret_key known_hosts; do
        [ -f "$DATA_DIR/$f" ] && chmod 600 "$DATA_DIR/$f" 2>/dev/null || true
    done
fi

# Drop privileges and exec the actual command
exec runuser -u paneluser -- "$@"
