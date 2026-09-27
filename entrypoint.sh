#!/bin/bash
set -e

# Signal trap for clean Docker shutdown
trap 'echo "[*] Received termination signal. Stopping scanner..."; kill $(jobs -p) 2>/dev/null; exit 0' SIGTERM SIGINT

CONFIG_FILE="/app/config/config.yaml"
EXTRA_ARGS=""

# Support both TARGET_CIDR and TARGETS environment variables
TARGET_INPUT="${TARGET_CIDR:-$TARGETS}"
if [ -n "$TARGET_INPUT" ]; then
    EXTRA_ARGS="$EXTRA_ARGS -t $TARGET_INPUT"
fi

if [ -n "$SCAN_PROFILE" ]; then
    EXTRA_ARGS="$EXTRA_ARGS -p $SCAN_PROFILE"
else
    EXTRA_ARGS="$EXTRA_ARGS -p wellknown_os"
fi

if [ -n "$MAX_PACKET_RATE" ]; then
    EXTRA_ARGS="$EXTRA_ARGS -r $MAX_PACKET_RATE"
fi

# Export all current environment variables so cron sub-shells have access to AWS credentials and paths
printenv | grep -E '^(AWS_|S3_|PATH=|PYTHON|TARGET|SCAN_|MAX_)' > /etc/environment 2>/dev/null || true

# Check if recurring cron schedule is requested
if [ -n "$CRON_SCHEDULE" ]; then
    echo "================================================================="
    echo "🛡️  CONTROLLED INTERNAL NETWORK SCANNER — PRODUCTION DAEMON"
    echo "Schedule         : $CRON_SCHEDULE"
    echo "Scan Profile     : ${SCAN_PROFILE:-wellknown_os (Curated Windows & Linux)}"
    echo "Packet Rate Cap  : ${MAX_PACKET_RATE:-100} packets/sec"
    echo "Targets          : ${TARGET_INPUT:-Default 10 Subnets in config/config.yaml}"
    echo "S3 Push Enabled  : ${S3_BUCKET_NAME:-Configured in config.yaml}"
    echo "================================================================="

    # Create crontab entry with environment loaded
    CRON_CMD=". /etc/environment; cd /app && /usr/local/bin/python3 /app/scanner/main.py -c $CONFIG_FILE $EXTRA_ARGS >> /app/output/cron_execution.log 2>&1"
    echo "$CRON_SCHEDULE $CRON_CMD" > /etc/cron.d/scanner-cron
    chmod 0644 /etc/cron.d/scanner-cron
    crontab /etc/cron.d/scanner-cron

    # Run initial baseline scan immediately on startup
    echo "[*] Executing initial baseline scan across target subnets..."
    python3 /app/scanner/main.py -c "$CONFIG_FILE" $EXTRA_ARGS --force || true

    echo "[*] Scanner daemon is live. Running cron in foreground (listening for scheduled intervals)..."
    exec cron -f
else
    # One-off execution mode
    if [ "$#" -gt 0 ]; then
        exec python3 /app/scanner/main.py -c "$CONFIG_FILE" "$@"
    else
        exec python3 /app/scanner/main.py -c "$CONFIG_FILE" $EXTRA_ARGS
    fi
fi
