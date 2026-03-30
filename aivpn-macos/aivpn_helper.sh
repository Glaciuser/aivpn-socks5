#!/bin/bash
# AIVPN Helper - runs aivpn-client with elevated privileges
# Usage: aivpn_helper.sh <binary_path> <key> [--full-tunnel]
# This script is executed by osascript with administrator privileges

BINARY="$1"
KEY="$2"
FULL_TUNNEL="$3"

LOG="/tmp/aivpn_client.log"
PID_FILE="/tmp/aivpn_client.pid"

# Kill old instance if running
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE" 2>/dev/null)
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        kill "$OLD_PID" 2>/dev/null
    fi
    rm -f "$PID_FILE"
fi

# Clear log
> "$LOG"

# Build command
CMD="$BINARY -k $KEY"
if [ "$FULL_TUNNEL" = "--full-tunnel" ]; then
    CMD="$CMD --full-tunnel"
fi

# Start client in background
nohup $CMD > "$LOG" 2>&1 &
echo $! > "$PID_FILE"

exit 0
