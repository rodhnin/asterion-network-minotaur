#!/bin/bash
# Database initialization script for Asterion Docker container
# Ensures database tables exist when container starts

set -e

DB_PATH="/data/argos.db"

echo "[DB-Init] Checking database at: $DB_PATH"

# If database doesn't exist or tables are missing, initialize it
if [ ! -f "$DB_PATH" ] || ! sqlite3 "$DB_PATH" "SELECT name FROM sqlite_master WHERE type='table' AND name='scans';" | grep -q "scans"; then
    echo "[DB-Init] Database not found or incomplete. Initializing..."
    python3 /app/scripts/db_migrate.py
    echo "[DB-Init] Database initialized successfully"
else
    echo "[DB-Init] Database already initialized"
fi

# Execute the main command
exec "$@"
