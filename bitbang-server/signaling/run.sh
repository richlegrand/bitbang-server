#!/bin/bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# Load environment variables
if [ -f .env ]; then
    set -a
    source .env
    set +a
else
    echo "Warning: .env file not found - TURN credentials will not be available"
fi

ulimit -n 65536

exec ../venv/bin/python signaling.py
