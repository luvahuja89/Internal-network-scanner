#!/bin/bash
# =============================================================================
# Helper script to Build, Run, or Test the Controlled Network Discovery Scanner
# =============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

show_help() {
    echo -e "${CYAN}Controlled Internal Network & Asset Discovery Scanner${NC}"
    echo "Usage: ./run.sh [command]"
    echo ""
    echo "Commands:"
    echo "  build              Build the Docker container image"
    echo "  scan               Run one-off controlled scan via Docker across configured subnets"
    echo "  scan-cidr <CIDR>   Run controlled scan against specific subnet (e.g. ./run.sh scan-cidr 192.168.1.0/24)"
    echo "  scan-auto          Run scan against auto-detected local interface subnet"
    echo "  start-daemon       Start background scheduled scanning service via docker-compose (with cron)"
    echo "  stop-daemon        Stop background scheduled scanning service"
    echo "  restart-daemon     Restart background scheduled scanning service"
    echo "  logs               Follow container execution logs"
    echo "  local-scan         Run locally with Python (without Docker)"
    echo ""
}

case "$1" in
    build)
        echo -e "${YELLOW}[*] Building Docker image 'internal-network-scanner:latest'...${NC}"
        docker build -t internal-network-scanner:latest .
        echo -e "${GREEN}[✓] Docker image built successfully.${NC}"
        ;;

    scan)
        echo -e "${YELLOW}[*] Running controlled asset discovery scan across configured subnets via Docker...${NC}"
        mkdir -p output/state
        docker run --rm --net=host \
            -v "$DIR/config:/app/config:ro" \
            -v "$DIR/output:/app/output:rw" \
            internal-network-scanner:latest -p wellknown_os --force
        ;;

    scan-auto)
        echo -e "${YELLOW}[*] Running controlled asset discovery scan with auto-detected interface via Docker...${NC}"
        mkdir -p output/state
        docker run --rm --net=host \
            -v "$DIR/config:/app/config:ro" \
            -v "$DIR/output:/app/output:rw" \
            internal-network-scanner:latest -p wellknown_os --auto-detect --force
        ;;

    scan-cidr)
        if [ -z "$2" ]; then
            echo "Error: Please specify CIDR (e.g. ./run.sh scan-cidr 192.168.1.0/24)"
            exit 1
        fi
        echo -e "${YELLOW}[*] Running controlled scan on subnet $2 via Docker...${NC}"
        mkdir -p output/state
        docker run --rm --net=host \
            -v "$DIR/config:/app/config:ro" \
            -v "$DIR/output:/app/output:rw" \
            internal-network-scanner:latest -p wellknown_os -t "$2" --force
        ;;

    start-daemon)
        echo -e "${YELLOW}[*] Starting scheduled daemon via docker-compose...${NC}"
        mkdir -p output/state
        docker compose up -d
        echo -e "${GREEN}[✓] Scanner daemon is running in background.${NC}"
        ;;

    stop-daemon)
        echo -e "${YELLOW}[*] Stopping scanner daemon...${NC}"
        docker compose down
        echo -e "${GREEN}[✓] Scanner daemon stopped.${NC}"
        ;;

    restart-daemon)
        echo -e "${YELLOW}[*] Restarting scanner daemon...${NC}"
        docker compose down
        docker compose up -d
        echo -e "${GREEN}[✓] Scanner daemon restarted.${NC}"
        ;;

    logs)
        docker compose logs -f
        ;;

    local-scan)
        PY_BIN="python3"
        if [ -f "$DIR/.venv/bin/python3" ]; then
            PY_BIN="$DIR/.venv/bin/python3"
        fi
        mkdir -p output/state
        if [ -n "$2" ]; then
            echo -e "${YELLOW}[*] Running locally with Python on subnet $2...${NC}"
            "$PY_BIN" scanner/main.py -t "$2" -p wellknown_os --force
        else
            echo -e "${YELLOW}[*] Running locally with Python on configured subnets (config/config.yaml)...${NC}"
            "$PY_BIN" scanner/main.py -p wellknown_os --force
        fi
        ;;

    *)
        show_help
        ;;
esac
