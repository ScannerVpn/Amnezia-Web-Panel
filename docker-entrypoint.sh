#!/bin/sh
# Docker entrypoint — ensures data/ is writable by paneluser (uid 1000)
# so that previous root-owned files don't crash the app.
set -e

DATA_DIR="${DATA_DIR:-/app/data}"
mkdir -p "$DATA_DIR"

# If running as root (e.g. host-mounted volume with root ownership),
# fix ownership of data dir then re-exec as paneluser.
if [ "$(id -u)" = "0" ]; then
    chown -R paneluser:paneluser "$DATA_DIR"
    chmod 700 "$DATA_DIR"
    exec gosu paneluser "$@"
fi

# Running as paneluser: ensure files in data are readable/writable by us.
# Files created by a previous root-run container may be unreadable.
find "$DATA_DIR" -type f -not -readable 2>/dev/null | while read -r f; do
    echo "[entrypoint] Removing unreadable file: $f"
    rm -f "$f" 2>/dev/null || echo "[entrypoint] WARN: cannot remove $f — host chown needed"
done

# Ensure known_hosts is writable
touch "$DATA_DIR/known_hosts" 2>/dev/null || true

exec "$@"
