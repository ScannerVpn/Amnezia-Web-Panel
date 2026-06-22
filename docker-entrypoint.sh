#!/bin/sh
# Amnezia Web Panel — Docker entrypoint
# Ensures /app/data has correct ownership before starting uvicorn as paneluser.
# Also runs git pull on startup if UPDATE_ON_START=1.

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

# ── Auto-update from GitHub on container start ────────────────────────────────
# Set UPDATE_ON_START=1 in .env to enable.
# After a git pull that needs a rebuild (Dockerfile/requirements changed),
# a flag file is written so the host knows to run: docker compose up -d --build
if [ "${UPDATE_ON_START:-0}" = "1" ]; then
    echo "[entrypoint] Checking for updates from GitHub..."
    if git -C /app remote get-url origin 2>/dev/null | grep -q "ScannerVpn/Amnezia-Web-Panel"; then
        PULL_OUT=$(git -C /app pull 2>&1) || true
        echo "[entrypoint] git pull: $PULL_OUT"
        if echo "$PULL_OUT" | grep -qE "requirements\.txt|Dockerfile"; then
            echo "[entrypoint] WARNING: Dockerfile or requirements.txt changed." \
                 "Run 'docker compose up -d --build' on the host to apply." | tee "$DATA_DIR/.needs_rebuild"
        fi
    else
        echo "[entrypoint] Skipping update — remote URL not recognised."
    fi
fi

# Drop privileges and exec the actual command
exec runuser -u paneluser -- "$@"
